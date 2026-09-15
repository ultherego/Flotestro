package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ultherego/flotestro/internal/outbox"
)

// Message is what a channel carries: a subject, a one-line title, the
// lines under it, a link into the panel, and the event of the trail it
// reports for a receiver that wants the facts rather than the words.
type Message struct {
	Subject string `json:"event"`
	Title   string `json:"title"`
	Text    string `json:"text"`
	Link    string `json:"link,omitempty"`
	// Severity is the alert's; empty for the other subjects.
	Severity string `json:"severity,omitempty"`
	// EventID and the fields after it are the row of the trail; zero and
	// empty for a test message.
	EventID     int64           `json:"event_id"`
	EventType   string          `json:"event_type"`
	Aggregate   string          `json:"aggregate_type,omitempty"`
	AggregateID string          `json:"aggregate_id,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	OccurredAt  time.Time       `json:"occurred_at"`
}

// SendError is a failure with a code the log keeps. The code is the kind
// of failure - the address refused, the name unknown, the receiver
// answering with a status - so an operator reading the log knows what to
// fix without the sentence.
type SendError struct {
	Code string
	Err  error
}

func (e SendError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e SendError) Unwrap() error { return e.Err }

// The codes of a failed delivery.
const (
	CodeConnectionRefused = "connection_refused"
	CodeDNSFailure        = "dns_failure"
	CodeTimeout           = "timeout"
	CodeTLSFailure        = "tls_failure"
	CodeUnreachable       = "unreachable"
	CodeReceiverStatus    = "receiver_status"
	CodeSMTPAuthFailed    = "smtp_auth_failed"
	CodeSMTPRejected      = "smtp_rejected"
	CodeSecretUnavailable = "secret_unavailable"
	CodeInvalidConfig     = "invalid_config"
)

// classify names a transport error. The order matters: a timeout is a
// timeout whatever wrapped it, a DNS failure says the name was wrong
// before any connection, and a refusal says the name was right and the
// port closed.
func classify(err error) SendError {
	var sendErr SendError
	if errors.As(err, &sendErr) {
		return sendErr
	}
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return SendError{Code: CodeTimeout, Err: err}
	case errors.As(err, &netErr) && netErr.Timeout():
		return SendError{Code: CodeTimeout, Err: err}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return SendError{Code: CodeDNSFailure, Err: err}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return SendError{Code: CodeConnectionRefused, Err: err}
	}
	var recordErr tls.RecordHeaderError
	var certErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &recordErr) || errors.As(err, &certErr) || errors.As(err, &hostErr) ||
		errors.As(err, &certInvalid) || strings.Contains(err.Error(), "tls:") {
		return SendError{Code: CodeTLSFailure, Err: err}
	}
	return SendError{Code: CodeUnreachable, Err: err}
}

// sendTimeout bounds one attempt at one receiver.
const sendTimeout = 15 * time.Second

// Sender delivers a message to one kind of channel.
type Sender interface {
	Send(ctx context.Context, channel Channel, message Message) error
}

// WebhookSender posts the message as JSON, signed the way the legacy
// webhook signs its deliveries: the receiver verifies with outbox.Verify.
type WebhookSender struct {
	Client *http.Client
}

func (w WebhookSender) Send(ctx context.Context, channel Channel, message Message) error {
	var config WebhookConfig
	if err := json.Unmarshal(channel.Config, &config); err != nil {
		return SendError{Code: CodeInvalidConfig, Err: err}
	}
	body, err := json.Marshal(message)
	if err != nil {
		return err
	}
	headers := http.Header{}
	headers.Set(outbox.DeliveryHeader, "notification-"+strconv.FormatInt(message.EventID, 10))
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	headers.Set(outbox.TimestampHeader, timestamp)
	headers.Set(outbox.SignatureHeader, outbox.Sign(config.Secret, body, timestamp))
	return post(ctx, w.Client, config.URL, body, headers)
}

// SlackSender posts the message in the shape of an incoming webhook: a
// text for the notification and one block with the same words, which
// every service that reads Slack's shape shows.
type SlackSender struct {
	Client *http.Client
}

func (s SlackSender) Send(ctx context.Context, channel Channel, message Message) error {
	var config SlackConfig
	if err := json.Unmarshal(channel.Config, &config); err != nil {
		return SendError{Code: CodeInvalidConfig, Err: err}
	}
	text := "*" + message.Title + "*"
	if message.Text != "" {
		text += "\n" + message.Text
	}
	if message.Link != "" {
		text += "\n<" + message.Link + "|" + "Open in Flotestro" + ">"
	}
	body, err := json.Marshal(map[string]any{
		"text": message.Title,
		"blocks": []map[string]any{{
			"type": "section",
			"text": map[string]string{"type": "mrkdwn", "text": text},
		}},
	})
	if err != nil {
		return err
	}
	return post(ctx, s.Client, config.URL, body, nil)
}

// post sends one body and reads the status. The answer is read and
// dropped so the connection can be reused; a status outside 2xx is a
// refusal of the receiver, with the status in the code's sentence.
func post(ctx context.Context, client *http.Client, address string, body []byte, headers http.Header) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		return SendError{Code: CodeInvalidConfig, Err: err}
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "flotestro-notifications")
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return classify(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return SendError{Code: CodeReceiverStatus, Err: fmt.Errorf("the receiver answered %d", response.StatusCode)}
	}
	return nil
}

// SecretReader hands the sender the value of a secret of the store. The
// panel reads it for its own client, so no lease is issued: the value
// goes to the mail relay and nowhere else.
type SecretReader interface {
	ReadCurrent(ctx context.Context, name string) ([]byte, error)
}

// EmailSender delivers over SMTP with the standard library alone: a
// plain connection, STARTTLS when the channel asks for it, PLAIN
// authentication over the encrypted connection. A password is read from
// the secret store at the moment of sending and is not kept.
type EmailSender struct {
	Secrets SecretReader
	// Dialer is replaced in tests; nil means a dialer with sendTimeout.
	Dialer *net.Dialer
}

func (e EmailSender) Send(ctx context.Context, channel Channel, message Message) error {
	var config EmailConfig
	if err := json.Unmarshal(channel.Config, &config); err != nil {
		return SendError{Code: CodeInvalidConfig, Err: err}
	}
	password := ""
	if config.Username != "" {
		if e.Secrets == nil {
			return SendError{Code: CodeSecretUnavailable, Err: errors.New("this installation has no secret store")}
		}
		value, err := e.Secrets.ReadCurrent(ctx, config.PasswordSecret)
		if err != nil {
			return SendError{Code: CodeSecretUnavailable, Err: fmt.Errorf("the secret %q: %w", config.PasswordSecret, err)}
		}
		password = string(value)
	}

	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	dialer := e.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: sendTimeout}
	}
	address := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return classify(err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, config.Host)
	if err != nil {
		return classify(err)
	}
	defer client.Close()
	if err := client.Hello("flotestro"); err != nil {
		return SendError{Code: CodeSMTPRejected, Err: err}
	}
	if config.StartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return SendError{Code: CodeTLSFailure, Err: errors.New("the relay offers no STARTTLS")}
		}
		if err := client.StartTLS(&tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return SendError{Code: CodeTLSFailure, Err: err}
		}
	}
	if config.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", config.Username, password, config.Host)); err != nil {
			return SendError{Code: CodeSMTPAuthFailed, Err: err}
		}
	}
	if err := client.Mail(config.From); err != nil {
		return SendError{Code: CodeSMTPRejected, Err: err}
	}
	for _, to := range config.To {
		if err := client.Rcpt(to); err != nil {
			return SendError{Code: CodeSMTPRejected, Err: fmt.Errorf("recipient %s: %w", to, err)}
		}
	}
	writer, err := client.Data()
	if err != nil {
		return SendError{Code: CodeSMTPRejected, Err: err}
	}
	if _, err := writer.Write(mailBody(config, message)); err != nil {
		return classify(err)
	}
	if err := writer.Close(); err != nil {
		return SendError{Code: CodeSMTPRejected, Err: err}
	}
	if err := client.Quit(); err != nil {
		// The message was taken at the end of DATA; a failed goodbye
		// changes nothing about that.
		return nil
	}
	return nil
}

// mailBody renders the message as a plain-text mail. The subject carries
// the title; the body the lines and the link. Line endings are CRLF as
// the protocol wants; the writer of net/smtp dot-stuffs the lines and
// ends the message, so nothing of that is done here.
func mailBody(config EmailConfig, message Message) []byte {
	var out bytes.Buffer
	fmt.Fprintf(&out, "From: %s\r\n", config.From)
	fmt.Fprintf(&out, "To: %s\r\n", strings.Join(config.To, ", "))
	fmt.Fprintf(&out, "Subject: %s\r\n", mailHeaderText("[Flotestro] "+message.Title))
	fmt.Fprintf(&out, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&out, "Message-ID: <%d.%d@flotestro>\r\n", message.EventID, time.Now().UnixNano())
	out.WriteString("MIME-Version: 1.0\r\n")
	out.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	out.WriteString("X-Flotestro-Event: " + mailHeaderText(message.Subject) + "\r\n")
	out.WriteString("\r\n")
	lines := []string{message.Title, ""}
	if message.Text != "" {
		lines = append(lines, strings.Split(message.Text, "\n")...)
	}
	if message.Link != "" {
		lines = append(lines, "", message.Link)
	}
	for _, line := range lines {
		out.WriteString(line + "\r\n")
	}
	return out.Bytes()
}

// mailHeaderText keeps a header on one line: a title with a line break
// in it would otherwise start a header of its own.
func mailHeaderText(text string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(text)
}

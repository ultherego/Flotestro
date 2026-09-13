package certificates

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The host trust store: the anchor directory and the tool that assembles
// the bundle from them.
//
// The panel writes neither to the bundle itself nor to the distribution
// directory: the bundle is a result, not a source, and rewritten by hand it
// returns to its previous form at the next package update. The source is
// the local anchor directory - the only place where the host administrator
// adds their own authorities.
const (
	AdapterDebian = "update-ca-certificates"
	AdapterRHEL   = "update-ca-trust"

	AnchorDirDebian = "/usr/local/share/ca-certificates"
	AnchorDirRHEL   = "/etc/pki/ca-trust/source/anchors"
	AnchorDirArch   = "/etc/ca-certificates/trust-source/anchors"

	UpdateCACertificatesPath = "/usr/sbin/update-ca-certificates"
	UpdateCATrustPath        = "/usr/bin/update-ca-trust"

	// AnchorPrefix tells the panel anchors from those the host
	// administrator placed there themselves. The panel does not remove
	// foreign authorities.
	AnchorPrefix = "flotestro-"
)

var anchorName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Anchor is an authority trusted on the host.
//
// There is no private key here and there cannot be: an anchor is public
// material - it is the authority certificate, not the host identity.
type Anchor struct {
	// ID is the name the panel gave the anchor. The file on the host is
	// named after it, so that is how the panel recognises its anchor after
	// a reboot.
	ID   string `json:"id"`
	Path string `json:"path"`
	// Managed tells a panel anchor from an authority placed there by hand.
	Managed           bool       `json:"managed"`
	Subject           string     `json:"subject,omitempty"`
	Issuer            string     `json:"issuer,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	IsCA              bool       `json:"is_ca"`
	// UnavailableReason describes a file that could not be read.
	UnavailableReason string `json:"unavailable_reason,omitempty"`
}

// TrustStore describes what the host has and what it recomputes it with.
type TrustStore struct {
	Adapter   string   `json:"adapter,omitempty"`
	Directory string   `json:"directory,omitempty"`
	Tool      string   `json:"tool,omitempty"`
	Anchors   []Anchor `json:"anchors,omitempty"`
	// UnavailableReason says why the store was not read. A host without
	// the tool and a host with an empty directory are two different
	// answers.
	UnavailableReason string    `json:"unavailable_reason,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
}

// Exists says whether the path is on the host. A directory and a file mean
// the same here: the trust store consists of both.
func Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// DetectStore recognises the host trust store.
//
// The tool decides, not the distribution name: the same package is found
// in different systems, and the panel is meant to work also where it does
// not know the system by name.
func DetectStore(exists func(string) bool) TrustStore {
	switch {
	case exists(UpdateCACertificatesPath) && exists(AnchorDirDebian):
		return TrustStore{Adapter: AdapterDebian,
			Directory: AnchorDirDebian, Tool: UpdateCACertificatesPath}
	case exists(UpdateCATrustPath) && exists(AnchorDirRHEL):
		return TrustStore{Adapter: AdapterRHEL,
			Directory: AnchorDirRHEL, Tool: UpdateCATrustPath}
	case exists(UpdateCATrustPath) && exists(AnchorDirArch):
		return TrustStore{Adapter: AdapterRHEL,
			Directory: AnchorDirArch, Tool: UpdateCATrustPath}
	}
	return TrustStore{
		UnavailableReason: "this host has neither an anchor directory nor a tool recomputing the trust store",
	}
}

// AnchorPath assembles the file path of a panel anchor.
//
// The extension is part of the agreement with the tool:
// update-ca-certificates considers only ".crt" files, and update-ca-trust
// only ".pem". An anchor with the wrong extension lies in the directory and
// does nothing.
func AnchorPath(store TrustStore, id string) string {
	if store.Directory == "" || id == "" {
		return ""
	}
	extension := ".crt"
	if store.Adapter == AdapterRHEL {
		extension = ".pem"
	}
	return path.Join(store.Directory, AnchorPrefix+id+extension)
}

// ValidateAnchor checks an anchor name.
func ValidateAnchor(id string) error {
	if !anchorName.MatchString(id) {
		return fmt.Errorf("invalid anchor name %q", id)
	}
	return nil
}

// ReadAnchors reads the anchor directory and describes what lies in it.
func ReadAnchors(store TrustStore) TrustStore {
	if store.Directory == "" {
		return store
	}
	entries, err := os.ReadDir(store.Directory)
	if err != nil {
		store.UnavailableReason = err.Error()
		return store
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		anchorFile := path.Join(store.Directory, entry.Name())
		anchor := Anchor{
			Path:    anchorFile,
			ID:      anchorIdentifier(entry.Name()),
			Managed: strings.HasPrefix(entry.Name(), AnchorPrefix),
		}
		data, err := ReadFile(anchorFile)
		if err != nil {
			anchor.UnavailableReason = err.Error()
			store.Anchors = append(store.Anchors, anchor)
			continue
		}
		certs, err := ParsePEM(data)
		if err != nil {
			anchor.UnavailableReason = err.Error()
			store.Anchors = append(store.Anchors, anchor)
			continue
		}
		description := Describe(anchorFile, certs)
		anchor.Subject = description.Subject
		anchor.Issuer = description.Issuer
		anchor.FingerprintSHA256 = description.FingerprintSHA256
		anchor.NotAfter = description.NotAfter
		anchor.IsCA = description.IsCA
		store.Anchors = append(store.Anchors, anchor)
	}
	sort.Slice(store.Anchors, func(i, j int) bool {
		return store.Anchors[i].Path < store.Anchors[j].Path
	})
	store.ObservedAt = time.Now().UTC()
	return store
}

// Anchor returns the panel anchor with the given name.
func (s TrustStore) Anchor(id string) *Anchor {
	for i := range s.Anchors {
		if s.Anchors[i].Managed && s.Anchors[i].ID == id {
			return &s.Anchors[i]
		}
	}
	return nil
}

func anchorIdentifier(name string) string {
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".crt"), ".pem")
	return strings.TrimPrefix(name, AnchorPrefix)
}

// TrustPlan describes the difference between the anchors the host has and
// the requested ones.
//
// An authority rotation is a sequence of states, not one change: first
// every host trusts the old and the new authority at once, then it gets a
// new leaf certificate, and only at the end does the old authority vanish.
// The plan describes one step of that sequence and says what the host is
// not ready to do yet.
type TrustPlan struct {
	Kind     string `json:"kind"`
	AnchorID string `json:"anchor_id"`
	Path     string `json:"path,omitempty"`
	Adapter  string `json:"adapter,omitempty"`
	// Action names what would happen: create, update, no_change, remove or
	// remove_absent.
	Action string `json:"action"`

	// The state found.
	Exists             bool       `json:"exists"`
	CurrentFingerprint string     `json:"current_fingerprint,omitempty"`
	CurrentNotAfter    *time.Time `json:"current_not_after,omitempty"`

	// The desired state. An anchor is public material, so the plan
	// describes it directly - unlike the leaf private key.
	DesiredSubject     string     `json:"desired_subject,omitempty"`
	DesiredFingerprint string     `json:"desired_fingerprint,omitempty"`
	DesiredNotAfter    *time.Time `json:"desired_not_after,omitempty"`

	// InUseBy lists the host certificates issued by this anchor. Removing
	// an authority that still signs something breaks trust in a running
	// service.
	InUseBy []string `json:"in_use_by,omitempty"`

	Changes []string `json:"changes,omitempty"`
	Refusal string   `json:"refusal,omitempty"`

	PlanHash string `json:"plan_hash"`
}

// ComputeAnchor computes the difference for creating or replacing an
// anchor.
func ComputeAnchor(store TrustStore, id, material string, now time.Time) TrustPlan {
	plan := TrustPlan{Kind: KindTrust, AnchorID: id, Adapter: store.Adapter,
		Path: AnchorPath(store, id)}
	if err := ValidateAnchor(id); err != nil {
		return plan.withRefusal(err.Error())
	}
	if store.UnavailableReason != "" {
		return plan.withRefusal(store.UnavailableReason)
	}
	certs, err := ParsePEM([]byte(material))
	if err != nil {
		return plan.withRefusal(err.Error())
	}
	// An anchor that is not an authority will not start signing anything -
	// and looks in the store just like an authority.
	if !certs[0].IsCA {
		return plan.withRefusal("the material is not an authority certificate (no basicConstraints CA)")
	}
	if err := CheckDates(certs[0], now); err != nil {
		return plan.withRefusal(err.Error())
	}
	end := certs[0].NotAfter.UTC()
	plan.DesiredSubject = certs[0].Subject.String()
	plan.DesiredFingerprint = Fingerprint(certs[0])
	plan.DesiredNotAfter = &end

	current := store.Anchor(id)
	switch {
	case current == nil:
		plan.Action = PlanCreate
		plan.Changes = []string{"the host will start trusting the authority " + plan.DesiredSubject +
			" (valid until " + end.Format(time.RFC3339) + ")"}
	case current.FingerprintSHA256 == plan.DesiredFingerprint:
		plan.describeCurrent(current)
		plan.Action = PlanNoChange
	default:
		plan.describeCurrent(current)
		plan.Action = PlanUpdate
		plan.Changes = []string{"anchor " + id + " from " + shortened(current.FingerprintSHA256) +
			" to " + shortened(plan.DesiredFingerprint)}
	}
	if plan.Action != PlanNoChange {
		plan.Changes = append(plan.Changes, "the trust store will be recomputed ("+store.Tool+")")
	}
	plan.PlanHash = trustPlanFingerprint(plan)
	return plan
}

// ComputeAnchorRemoval computes the difference for withdrawing trust.
//
// Host certificates issued by this anchor are a refusal here, not a note:
// removing an authority while a service still shows its certificate breaks
// trust for clients that changed nothing.
func ComputeAnchorRemoval(store TrustStore, id string,
	certificates []Certificate) TrustPlan {
	plan := TrustPlan{Kind: KindTrust, AnchorID: id, Adapter: store.Adapter,
		Path: AnchorPath(store, id)}
	if err := ValidateAnchor(id); err != nil {
		return plan.withRefusal(err.Error())
	}
	if store.UnavailableReason != "" {
		return plan.withRefusal(store.UnavailableReason)
	}
	current := store.Anchor(id)
	if current == nil {
		plan.Action = PlanRemoveAbsent
		plan.PlanHash = trustPlanFingerprint(plan)
		return plan
	}
	plan.describeCurrent(current)
	for _, certificate := range certificates {
		if certificate.Issuer != "" && certificate.Issuer == current.Subject {
			plan.InUseBy = append(plan.InUseBy, certificate.Path)
		}
	}
	sort.Strings(plan.InUseBy)
	if len(plan.InUseBy) > 0 {
		return plan.withRefusal("the authority still signs certificates of this host: " +
			strings.Join(plan.InUseBy, ", "))
	}
	plan.Action = PlanRemove
	plan.Changes = []string{"the host will stop trusting the authority " + current.Subject,
		"the trust store will be recomputed (" + store.Tool + ")"}
	plan.PlanHash = trustPlanFingerprint(plan)
	return plan
}

// Refuse records a refusal reason learned after the differences were
// computed.
func (p *TrustPlan) Refuse(reason string) {
	p.Refusal = reason
	p.PlanHash = trustPlanFingerprint(*p)
}

func (p TrustPlan) withRefusal(reason string) TrustPlan {
	p.Refusal = reason
	p.PlanHash = trustPlanFingerprint(p)
	return p
}

func (p *TrustPlan) describeCurrent(anchor *Anchor) {
	p.Exists = true
	p.Path = anchor.Path
	p.CurrentFingerprint = anchor.FingerprintSHA256
	p.CurrentNotAfter = anchor.NotAfter
}

// trustPlanFingerprint computes the plan fingerprint excluding the
// fingerprint itself.
func trustPlanFingerprint(plan TrustPlan) string {
	stripped := plan
	stripped.PlanHash = ""
	encoded, err := json.Marshal(stripped)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// ComposeAnchor checks the anchor material before writing it to the host.
func ComposeAnchor(material string, now time.Time) ([]byte, *x509.Certificate, error) {
	certs, err := ParsePEM([]byte(material))
	if err != nil {
		return nil, nil, err
	}
	if !certs[0].IsCA {
		return nil, nil, fmt.Errorf("the material is not an authority certificate (no basicConstraints CA)")
	}
	if err := CheckDates(certs[0], now); err != nil {
		return nil, nil, err
	}
	return []byte(material), certs[0], nil
}

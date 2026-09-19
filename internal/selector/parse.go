package selector

import (
	"fmt"
	"strings"
	"unicode"
)

// ErrSyntax means a text expression that does not parse; the message says
// where.
var ErrSyntax = fmt.Errorf("%w: the expression does not parse", ErrInvalid)

// Key describes one fact a text expression may name, for the parser and
// for the panel that suggests keys while the operator types.
type Key struct {
	// Name is the field of the selector the key sets.
	Name string
	// Aliases are the shorter spellings the parser also accepts.
	Aliases []string
	// Values lists the values of a key that takes a fixed set; nil for a
	// key that takes free text.
	Values []string
	// Ordered says the key compares with <, <=, > and >= as well as =.
	Ordered bool
}

// Keys lists what a text expression may name, in the order the panel offers
// them.
var Keys = []Key{
	{Name: "site"},
	{Name: "environment", Aliases: []string{"env"}},
	{Name: "os_family", Aliases: []string{"os"}},
	{Name: "os_version"},
	{Name: "tag"},
	{Name: "group"},
	{Name: "owner"},
	{Name: "capability"},
	{Name: "connection_state", Aliases: []string{"connection"}, Values: connectionStates},
	{Name: "lifecycle_state", Aliases: []string{"lifecycle"}, Values: lifecycleStates},
	{Name: "channel", Aliases: []string{"release_channel"}, Values: releaseChannels},
	{Name: "security_updates", Values: booleans},
	{Name: "reboot_required", Values: booleans},
	{Name: "failed_units", Values: booleans},
	{Name: "agent_version", Ordered: true},
	{Name: "relay"},
	{Name: "failure_domain"},
}

// keyByName resolves a key or one of its aliases; nil for a name no key
// carries.
func keyByName(name string) *Key {
	for i := range Keys {
		if Keys[i].Name == name || contains(Keys[i].Aliases, name) {
			return &Keys[i]
		}
	}
	return nil
}

// Parse reads the one-line text form of a selector: site = warsaw and (tag =
// role=db or not environment = prod) agent_version < 0.
func Parse(text string) (*Expression, error) {
	tokens, err := tokenize(text)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens}
	if p.peek().kind == tokenEnd {
		return nil, fmt.Errorf("%w: the expression is empty", ErrSyntax)
	}
	expression, err := p.or()
	if err != nil {
		return nil, err
	}
	if next := p.peek(); next.kind != tokenEnd {
		return nil, fmt.Errorf("%w: unexpected %q at %d", ErrSyntax, next.text, next.at)
	}
	if err := expression.Validate(); err != nil {
		return nil, err
	}
	return expression, nil
}

// The kinds of token the text form is made of.
type tokenKind int

const (
	tokenEnd tokenKind = iota
	tokenWord
	tokenOperator
	tokenOpen
	tokenClose
	tokenQuoted
)

type token struct {
	kind tokenKind
	text string
	// at is the offset of the token in the text, for the error message.
	at int
}

// operatorRunes are the characters an operator is made of.
const operatorRunes = "=!<>"

// tokenize cuts the text into words, operators, parentheses and quoted
// strings.
func tokenize(text string) ([]token, error) {
	var tokens []token
	// afterKey is true right after a word naming a key: the operator characters
	// that follow are an operator.
	afterKey, valueNext := false, false
	runes := []rune(text)
	for i := 0; i < len(runes); {
		r := runes[i]
		switch {
		case unicode.IsSpace(r):
			i++
		case r == '(' || r == ')':
			kind := tokenOpen
			if r == ')' {
				kind = tokenClose
			}
			tokens = append(tokens, token{kind, string(r), i})
			afterKey, valueNext = false, false
			i++
		case r == '"':
			end := i + 1
			var value strings.Builder
			for end < len(runes) && runes[end] != '"' {
				if runes[end] == '\\' && end+1 < len(runes) {
					end++
				}
				value.WriteRune(runes[end])
				end++
			}
			if end >= len(runes) {
				return nil, fmt.Errorf("%w: the quote opened at %d is never closed", ErrSyntax, i)
			}
			tokens = append(tokens, token{tokenQuoted, value.String(), i})
			afterKey, valueNext = false, false
			i = end + 1
		case afterKey && strings.ContainsRune(operatorRunes, r):
			end := i
			for end < len(runes) && strings.ContainsRune(operatorRunes, runes[end]) {
				end++
			}
			tokens = append(tokens, token{tokenOperator, string(runes[i:end]), i})
			afterKey, valueNext = false, true
			i = end
		default:
			end := i
			for end < len(runes) && !unicode.IsSpace(runes[end]) && runes[end] != '(' && runes[end] != ')' && runes[end] != '"' {
				if !valueNext && !isKeyRune(runes[end]) {
					break
				}
				end++
			}
			if end == i {
				// An operator where no key stands before it: cut it as one anyway, so the
				// parser can say what is missing in front of it rather than the tokenizer
				// saying "unexpected".
				for end < len(runes) && strings.ContainsRune(operatorRunes, runes[end]) {
					end++
				}
				if end == i {
					return nil, fmt.Errorf("%w: unexpected %q at %d", ErrSyntax, string(r), i)
				}
				tokens = append(tokens, token{tokenOperator, string(runes[i:end]), i})
				afterKey, valueNext = false, true
				i = end
				continue
			}
			word := string(runes[i:end])
			tokens = append(tokens, token{tokenWord, word, i})
			afterKey = !valueNext && isKeyWord(word)
			valueNext = false
			i = end
		}
	}
	return append(tokens, token{tokenEnd, "", len(runes)}), nil
}

// isKeyRune says whether the character can be part of a key name.
func isKeyRune(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// isKeyWord says whether the word names a key of the grammar, in any of its
// spellings.
func isKeyWord(word string) bool {
	return keyByName(strings.ToLower(word)) != nil
}

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() token {
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	t := p.tokens[p.pos]
	if t.kind != tokenEnd {
		p.pos++
	}
	return t
}

// keyword says whether the next token is the given keyword, in any case.
func (p *parser) keyword(word string) bool {
	t := p.peek()
	return t.kind == tokenWord && strings.EqualFold(t.text, word)
}

func (p *parser) or() (*Expression, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	if !p.keyword("or") {
		return left, nil
	}
	alternatives := []Expression{*left}
	for p.keyword("or") {
		p.next()
		right, err := p.and()
		if err != nil {
			return nil, err
		}
		alternatives = append(alternatives, *right)
	}
	return &Expression{Any: alternatives}, nil
}

func (p *parser) and() (*Expression, error) {
	left, err := p.not()
	if err != nil {
		return nil, err
	}
	if !p.keyword("and") {
		return left, nil
	}
	all := []Expression{*left}
	for p.keyword("and") {
		p.next()
		right, err := p.not()
		if err != nil {
			return nil, err
		}
		all = append(all, *right)
	}
	return &Expression{All: all}, nil
}

func (p *parser) not() (*Expression, error) {
	if p.keyword("not") {
		p.next()
		inner, err := p.not()
		if err != nil {
			return nil, err
		}
		return &Expression{Not: inner}, nil
	}
	return p.primary()
}

func (p *parser) primary() (*Expression, error) {
	t := p.next()
	switch t.kind {
	case tokenOpen:
		inner, err := p.or()
		if err != nil {
			return nil, err
		}
		if closing := p.next(); closing.kind != tokenClose {
			return nil, fmt.Errorf("%w: the parenthesis opened at %d is never closed", ErrSyntax, t.at)
		}
		return inner, nil
	case tokenWord:
		return p.condition(t)
	case tokenEnd:
		return nil, fmt.Errorf("%w: a condition is missing at the end", ErrSyntax)
	default:
		return nil, fmt.Errorf("%w: unexpected %q at %d", ErrSyntax, t.text, t.at)
	}
}

// condition reads "key operator value" from the key on.
func (p *parser) condition(name token) (*Expression, error) {
	key := keyByName(strings.ToLower(name.text))
	if key == nil {
		return nil, fmt.Errorf("%w: %q at %d is not a key; use one of %s",
			ErrSyntax, name.text, name.at, strings.Join(KeyNames(), ", "))
	}
	operator := p.next()
	if operator.kind != tokenOperator {
		return nil, fmt.Errorf("%w: an operator such as = is expected after %q at %d", ErrSyntax, name.text, name.at)
	}
	value := p.next()
	if value.kind != tokenWord && value.kind != tokenQuoted {
		return nil, fmt.Errorf("%w: a value is expected after %q at %d", ErrSyntax, operator.text, operator.at)
	}
	leaf := &Expression{}
	switch operator.text {
	case "=", "==":
		leaf.set(key.Name, value.text)
	case "!=":
		leaf.set(key.Name, value.text)
		leaf = &Expression{Not: leaf}
	case "<", "<=", ">", ">=":
		if !key.Ordered {
			return nil, fmt.Errorf("%w: %s compares only with = and !=; %s at %d applies to agent_version",
				ErrSyntax, key.Name, operator.text, operator.at)
		}
		leaf.set(key.Name, operator.text+" "+value.text)
	default:
		return nil, fmt.Errorf("%w: %q at %d is not an operator; use =, !=, <, <=, > or >=",
			ErrSyntax, operator.text, operator.at)
	}
	return leaf, nil
}

// set fills the named leaf field. The names are the JSON fields, the
// same list leaves reads.
func (e *Expression) set(name, value string) {
	switch name {
	case "site":
		e.Site = value
	case "environment":
		e.Environment = value
	case "os_family":
		e.OSFamily = value
	case "os_version":
		e.OSVersion = value
	case "tag":
		e.Tag = value
	case "group":
		e.Group = value
	case "owner":
		e.Owner = value
	case "capability":
		e.Capability = value
	case "connection_state":
		e.ConnectionState = value
	case "lifecycle_state":
		e.LifecycleState = value
	case "channel":
		e.Channel = value
	case "security_updates":
		e.SecurityUpdates = value
	case "reboot_required":
		e.RebootRequired = value
	case "failed_units":
		e.FailedUnits = value
	case "agent_version":
		e.AgentVersion = value
	case "relay":
		e.Relay = value
	case "failure_domain":
		e.FailureDomain = value
	}
}

// KeyNames lists the canonical key names, for an error message and for
// the catalogue the panel reads.
func KeyNames() []string {
	names := make([]string, 0, len(Keys))
	for _, key := range Keys {
		names = append(names, key.Name)
	}
	return names
}

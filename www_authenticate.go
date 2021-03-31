package digest_auth_client

import (
	"bytes"
	"errors"
	"strings"
)

type wwwAuthenticate struct {
	Algorithm string // unquoted
	Domain    string // quoted
	Nonce     string // quoted
	Opaque    string // quoted
	Qop       string // quoted
	Realm     string // quoted
	Stale     bool   // unquoted
	Charset   string // quoted
	Userhash  bool   // quoted
	Type      string
}

func newWwwAuthenticate(wwwAuthHeader string) (*wwwAuthenticate, error) {
	parts := strings.SplitN(wwwAuthHeader, " ", 2)
	if len(parts) != 2 {
		return nil, errors.New("bad WWW-Authenticate header")
	}

	vals := ParsePairs(parts[1])

	return &wwwAuthenticate{
		Algorithm: vals["algorithm"],
		Domain:    vals["domain"],
		Nonce:     vals["nonce"],
		Opaque:    vals["opaque"],
		Qop:       vals["qop"],
		Realm:     vals["realm"],
		Stale:     strings.ToLower(vals["stale"]) == "true",
		Charset:   vals["charset"],
		Userhash:  strings.ToLower(vals["userhash"]) == "true",
		Type:      parts[0],
	}, nil
}

// ParseList parses a comma-separated list of values as described by
// RFC 2068 and returns list elements.
//
// Lifted from https://code.google.com/p/gorilla/source/browse/http/parser/parser.go
// which was ported from urllib2.parse_http_list, from the Python
// standard library.
func ParseList(value string) []string {
	var list []string
	var escape, quote bool
	b := new(bytes.Buffer)
	for _, r := range value {
		switch {
		case escape:
			b.WriteRune(r)
			escape = false
		case quote:
			if r == '\\' {
				escape = true
			} else {
				if r == '"' {
					quote = false
				}
				b.WriteRune(r)
			}
		case r == ',':
			list = append(list, strings.TrimSpace(b.String()))
			b.Reset()
		case r == '"':
			quote = true
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	// Append last part.
	if s := b.String(); s != "" {
		list = append(list, strings.TrimSpace(s))
	}
	return list
}

// ParsePairs extracts key/value pairs from a comma-separated list of
// values as described by RFC 2068 and returns a map[key]value. The
// resulting values are unquoted. If a list element doesn't contain a
// "=", the key is the element itself and the value is an empty
// string.
//
// Lifted from https://code.google.com/p/gorilla/source/browse/http/parser/parser.go
func ParsePairs(value string) map[string]string {
	m := make(map[string]string)
	for _, pair := range ParseList(strings.TrimSpace(value)) {
		switch i := strings.Index(pair, "="); {
		case i < 0:
			// No '=' in pair, treat whole string as a 'key'.
			m[pair] = ""
		case i == len(pair)-1:
			// Malformed pair ('key=' with no value), keep key with empty value.
			m[pair[:i]] = ""
		default:
			v := pair[i+1:]
			if v[0] == '"' && v[len(v)-1] == '"' {
				// Unquote it.
				v = v[1 : len(v)-1]
			}
			m[pair[:i]] = v
		}
	}
	return m
}

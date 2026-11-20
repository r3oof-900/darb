package iampolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Input limits (docs/THREAT_MODEL.md, denial of service). The largest AWS
// resource policies (e.g. KMS key policies, 32 KiB) fit comfortably.
const (
	MaxBytes = 256 << 10
	MaxDepth = 32
)

// ErrMalformed is returned for input that is not a valid policy document.
var ErrMalformed = errors.New("iampolicy: malformed policy")

// field is one member of a JSON object, in document order.
type field struct {
	key string
	val any
}

// object is a JSON object that preserves member order. Duplicate keys are
// rejected while decoding: encoding/json would silently keep the last one,
// and AWS's handling of duplicates is not something we want to guess.
type object struct {
	fields []field
}

func (o *object) get(key string) (any, bool) {
	for _, f := range o.fields {
		if f.key == key {
			return f.val, true
		}
	}
	return nil, false
}

// decode parses data into string, json.Number, bool, nil, []any or *object.
func decode(data []byte) (any, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%w: %d bytes exceeds the %d-byte limit", ErrMalformed, len(data), MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after the policy document", ErrMalformed)
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	if depth >= MaxDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d", ErrMalformed, MaxDepth)
	}
	if delim == '[' {
		return decodeArray(dec, depth+1)
	}
	return decodeObject(dec, depth+1)
}

func decodeArray(dec *json.Decoder, depth int) (any, error) {
	out := []any{}
	for dec.More() {
		v, err := decodeValue(dec, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	_, err := dec.Token() // ']'
	return out, err
}

func decodeObject(dec *json.Decoder, depth int) (any, error) {
	o := &object{}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		key, _ := tok.(string) // json.Decoder guarantees object keys are strings
		if seen[key] {
			return nil, fmt.Errorf("%w: duplicate key %q", ErrMalformed, key)
		}
		seen[key] = true
		v, err := decodeValue(dec, depth)
		if err != nil {
			return nil, err
		}
		o.fields = append(o.fields, field{key: key, val: v})
	}
	_, err := dec.Token() // '}'
	return o, err
}

package model

// Tri is a three-valued truth value (Kleene logic). Unknown means the
// analyzer could not decide; it is never treated as true or false.
type Tri uint8

// Truth values.
const (
	False Tri = iota
	True
	Unknown
)

// TriOf converts a bool.
func TriOf(b bool) Tri {
	if b {
		return True
	}
	return False
}

// And is Kleene conjunction: False dominates, then Unknown.
func (t Tri) And(u Tri) Tri {
	switch {
	case t == False || u == False:
		return False
	case t == Unknown || u == Unknown:
		return Unknown
	default:
		return True
	}
}

// Or is Kleene disjunction: True dominates, then Unknown.
func (t Tri) Or(u Tri) Tri {
	switch {
	case t == True || u == True:
		return True
	case t == Unknown || u == Unknown:
		return Unknown
	default:
		return False
	}
}

// Not is Kleene negation; Unknown stays Unknown.
func (t Tri) Not() Tri {
	switch t {
	case True:
		return False
	case False:
		return True
	case Unknown:
		return Unknown
	}
	return Unknown
}

// String returns "false", "true" or "unknown".
func (t Tri) String() string {
	switch t {
	case False:
		return "false"
	case True:
		return "true"
	case Unknown:
		return "unknown"
	}
	return "unknown"
}

// MarshalText renders the value as "true", "false" or "unknown" in JSON.
func (t Tri) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// Package archtest holds the layer dependency table (layers.go) and the checks
// that enforce it: an import checker over every .go file in the module, a file
// length limit, and renderers that generate the depguard configuration and the
// table in docs/DESIGN.md from the same data. See docs/DESIGN.md section 3.2.
//
// It is repository tooling and is never linked into the clapa binary.
package archtest

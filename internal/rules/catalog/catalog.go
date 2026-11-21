// Package catalog builds the rule registry. Its version changes whenever a
// rule's ID set or version changes (TestCatalogVersion).
package catalog

import (
	"github.com/r3oof-900/clapa/internal/rules"
	"github.com/r3oof-900/clapa/internal/rules/pathrules"
	"github.com/r3oof-900/clapa/internal/rules/posture"
)

// Version is the rule catalog's semver.
const Version = "1.2.1"

// New returns the registry of every rule.
func New() (*rules.Registry, error) {
	return rules.NewRegistry(append(pathrules.Rules(), posture.Rules()...)...)
}

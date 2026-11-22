package awsraw

import "github.com/r3oof-900/darb/internal/coverage"

// Call outcomes (Call.Status).
const (
	StatusOK           = "ok"
	StatusAccessDenied = "AccessDenied"
	StatusThrottling   = "Throttling"
	StatusTimeout      = "Timeout"
	StatusError        = "Error"
)

// Gap is the coverage gap of a failed call (nil for a call that succeeded).
// The live collector and the snapshot reader both use it, so a call that
// failed live and the same call recorded in a snapshot give the same gap.
func (c *Call) Gap(source, account string) *coverage.Gap {
	if c.Status == StatusOK {
		return nil
	}
	kind, ok := map[string]coverage.Kind{
		StatusAccessDenied: coverage.KindAccessDenied, StatusThrottling: coverage.KindThrottled, StatusTimeout: coverage.KindTimeout,
	}[c.Status]
	if !ok {
		kind = coverage.KindAPIError
	}
	return &coverage.Gap{
		Kind: kind, Source: source, Account: account, Service: c.Service, Region: c.Region,
		API: c.API, Address: c.Target, Detail: c.Error,
	}
}

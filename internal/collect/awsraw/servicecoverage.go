package awsraw

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// Coverage of one service in one region (S3 and IAM: global), derived from
// the recorded calls: Units are the items its list call returned (each one
// is the target of that service's other calls), Complete those whose every
// call succeeded. When the list call failed or was not made, the number of
// items is not known: Known is false and the coverage is unknown, never
// 100% (docs/DESIGN.md 4.4).
type Coverage struct {
	Service  string
	Region   string
	Known    bool
	Units    int
	Complete int
	ListCall string // the call that lists the units, e.g. "kms:ListKeys"
	Status   string // the list call's status when it failed
}

// listCalls: per service, the call whose result is the set of units, and
// the units' name.
func listCalls() map[string][2]string {
	return map[string][2]string{
		"iam":            {"GetAccountAuthorizationDetails", "authorization details"},
		"s3":             {"ListBuckets", "buckets"},
		"kms":            {"ListKeys", "keys"},
		"eks":            {"ListClusters", "clusters"},
		"secretsmanager": {"ListSecrets", "secrets"},
		"ssm":            {"DescribeParameters", "parameters"},
	}
}

// Full reports whether every unit was collected in full.
func (c *Coverage) Full() bool { return c.Known && c.Units == c.Complete }

func (c *Coverage) String() string {
	what := listCalls()[c.Service][1]
	if !c.Known {
		return fmt.Sprintf("coverage unknown: %s %s, so the number of %s is not known", c.ListCall, statusText(c.Status), what)
	}
	return fmt.Sprintf("%d of %d %s collected in full; the others have failed calls (see the gaps)", c.Complete, c.Units, what)
}

func statusText(s string) string {
	if s == "" {
		return "was not made"
	}
	return "failed (" + s + ")"
}

// unitOf maps a call's target to its unit: a Pod Identity association
// ("cluster/id") belongs to its cluster.
func unitOf(c *Call) string {
	if c.Service == "eks" && c.API == "DescribePodIdentityAssociation" {
		cluster, _, _ := strings.Cut(c.Target, "/")
		return cluster
	}
	return c.Target
}

// ServiceCoverage computes the coverage of every service and region the
// calls touch, sorted.
func ServiceCoverage(calls []Call) []Coverage {
	t := &tally{lists: listCalls(), out: map[scope]*Coverage{}, failed: map[scope]map[string]bool{}}
	for i := range calls {
		t.add(&calls[i])
	}
	res := make([]Coverage, 0, len(t.out))
	for k, cv := range t.out {
		if k.service != "iam" {
			cv.Units = len(t.failed[k])
			for _, f := range t.failed[k] {
				if !f {
					cv.Complete++
				}
			}
		}
		res = append(res, *cv)
	}
	slices.SortFunc(res, func(a, b Coverage) int {
		return cmp.Or(strings.Compare(a.Service, b.Service), strings.Compare(a.Region, b.Region))
	})
	return res
}

type scope struct{ service, region string }

// tally counts, per service and region, the units and whether each one
// had a failed call.
type tally struct {
	lists  map[string][2]string
	out    map[scope]*Coverage
	failed map[scope]map[string]bool
}

func (t *tally) add(c *Call) {
	list, ok := t.lists[c.Service]
	if !ok {
		return // sts: identification, not a unit
	}
	k := scope{c.Service, c.Region}
	if c.Service == "s3" || c.Service == "iam" {
		k.region = "" // a global listing; per-bucket calls go to the bucket's region
	}
	if t.out[k] == nil {
		t.out[k] = &Coverage{Service: c.Service, Region: k.region, ListCall: c.Service + ":" + list[0]}
		t.failed[k] = map[string]bool{}
	}
	cv := t.out[k]
	switch c.API {
	case list[0]:
		cv.Known = c.Status == StatusOK
		if !cv.Known {
			cv.Status = c.Status
		}
		if c.Service == "iam" { // one unit: the account's authorization details
			cv.Units = 1
			if cv.Known {
				cv.Complete = 1
			}
		}
	case "ListAliases":
		// aliases are not units; a failed ListAliases is a gap of its own
	default:
		u := unitOf(c)
		t.failed[k][u] = t.failed[k][u] || c.Status != StatusOK
	}
}

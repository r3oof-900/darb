package app

import (
	"fmt"
	"strings"

	"github.com/r3oof-900/darb/internal/config"
	"github.com/r3oof-900/darb/internal/model"
)

// splitK8sIdentity splits "k8s:{cluster}/{rest}" into the cluster part and
// the rest; the cluster part of an ARN key includes "cluster/<name>".
func splitK8sIdentity(id string) (cluster, rest string, ok bool) {
	s, found := strings.CutPrefix(id, "k8s:")
	if !found {
		return "", "", false
	}
	skip := 0
	if strings.HasPrefix(s, "arn:") {
		skip = strings.Index(s, ":cluster/") + len(":cluster/")
		if skip < len(":cluster/") {
			return "", "", false
		}
	}
	i := strings.IndexByte(s[skip:], '/')
	if i < 0 {
		return "", "", false
	}
	return s[:skip+i], s[skip+i+1:], true
}

// resolveIdentities writes the Kubernetes identities of darb.yaml
// (intended_access principals) with their cluster key: a user may name the
// cluster ("k8s:prod/payments/Deployment/api"); the name must match one
// cluster of the scan (two clusters of one name need the ARN).
func resolveIdentities(inv *model.Inventory, cfg *config.Config) ([]config.IntendedAccess, error) {
	out := make([]config.IntendedAccess, len(cfg.IntendedAccess))
	copy(out, cfg.IntendedAccess)
	for i := range out {
		cluster, rest, ok := splitK8sIdentity(out[i].Principal)
		if !ok || model.IsClusterARN(cluster) {
			continue
		}
		var keys []string
		for _, c := range inv.Clusters {
			if c.Name == cluster {
				keys = append(keys, c.Key())
			}
		}
		switch len(keys) {
		case 0: // a cluster no input describes: its name is its key
		case 1:
			out[i].Principal = "k8s:" + keys[0] + "/" + rest
		default:
			return nil, fmt.Errorf("%w: %w: intended_access[%d] principal %q: cluster name %q matches %d clusters (%s); write the cluster's ARN",
				config.ErrInvalid, ErrAmbiguousCluster, i, out[i].Principal, cluster, len(keys), strings.Join(keys, ", "))
		}
	}
	return out, nil
}

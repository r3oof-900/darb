package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/r3oof-900/darb/internal/app"
)

// k8sFlags are the live Kubernetes flags of scan.
type k8sFlags struct {
	contexts   list // --live-k8s CONTEXT[=CLUSTER]
	eks        list // --k8s-eks NAME
	kubeconfig string
	insecure   bool
}

func (k *k8sFlags) on(fs *flag.FlagSet) {
	fs.Var(&k.contexts, "live-k8s", "read a live cluster through a kubeconfig context, CONTEXT[=CLUSTER] (repeatable; CLUSTER: its name or ARN, default the context name)")
	fs.Var(&k.eks, "k8s-eks", "read a live EKS cluster by name with an in-memory token from --aws-profile, in the first --aws-region (repeatable)")
	fs.StringVar(&k.kubeconfig, "kubeconfig", "", "kubeconfig file for --live-k8s (default: $KUBECONFIG, then ~/.kube/config)")
	fs.BoolVar(&k.insecure, "insecure", false, "turn TLS verification off for --live-k8s clusters (loudly warned, and recorded in the report)")
}

func (k *k8sFlags) any() bool { return len(k.contexts) > 0 || len(k.eks) > 0 }

// clusters connects to every live cluster. A context's cluster is the
// part after "=", else the context's own name (EKS kubeconfigs name their
// contexts by cluster ARN); app.Load resolves a name to the cluster's key.
func (k *k8sFlags) clusters(ctx context.Context, env *Env, aws *awsFlags, stderr io.Writer) ([]app.K8sLive, error) {
	if k.insecure {
		_, _ = fmt.Fprintln(stderr, "WARNING: --insecure: TLS verification is OFF for every --live-k8s cluster. "+
			"The API servers' identities are not checked, so their answers may not be the clusters'. The report records it.")
	}
	var out []app.K8sLive
	for _, c := range k.contexts {
		name, cluster, _ := strings.Cut(c, "=")
		if cluster == "" {
			cluster = name
		}
		clients, err := env.K8s.Kubeconfig(k.kubeconfig, name, k.insecure)
		if err != nil {
			return nil, err
		}
		out = append(out, app.K8sLive{Cluster: cluster, Clients: clients})
	}
	region := ""
	if len(aws.regions) > 0 {
		region = aws.regions[0]
	}
	for _, name := range k.eks {
		clients, arn, err := env.K8s.EKS(ctx, aws.profile, region, name)
		if err != nil {
			return nil, err
		}
		out = append(out, app.K8sLive{Cluster: arn, Clients: clients})
	}
	return out, nil
}

package app

import (
	"context"

	"github.com/r3oof-900/darb/internal/access"
	"github.com/r3oof-900/darb/internal/collect/awslive"
	"github.com/r3oof-900/darb/internal/collect/k8s/live"
	"github.com/r3oof-900/darb/pkg/schema"
)

// K8sClients reads one live cluster (typed and metadata-only clients).
type K8sClients = live.Clients

// K8sLive is one live cluster to scan.
type K8sLive struct {
	Cluster string // the name findings use (darb.yaml clusters[].name)
	Clients *K8sClients
}

// K8sConnector makes the clients of a live cluster; the CLI uses
// ConnectKubeconfig and ConnectEKS, tests pass fakes.
type K8sConnector struct {
	Kubeconfig func(path, kubeContext string, insecure bool) (*K8sClients, error)
	EKS        func(ctx context.Context, profile, region, cluster string) (clients *K8sClients, arn string, err error)
}

// ConnectKubeconfig connects to a kubeconfig context (no exec plugins).
func ConnectKubeconfig(path, kubeContext string, insecure bool) (*K8sClients, error) {
	cfg, err := live.KubeconfigREST(path, kubeContext, insecure)
	if err != nil {
		return nil, err
	}
	return live.NewClients(cfg)
}

// ConnectEKS connects to an EKS cluster with an in-memory token signed by
// the AWS profile's credentials (the SDK reads them) and returns the
// cluster's ARN.
func ConnectEKS(ctx context.Context, profile, region, cluster string) (clients *K8sClients, arn string, err error) {
	cfg, err := awslive.LoadConfig(ctx, profile, region)
	if err != nil {
		return nil, "", err
	}
	return live.ConnectEKS(ctx, &cfg, cluster)
}

// insecureNote records that a cluster was read without TLS verification.
func insecureNote(cluster string) access.Note {
	return access.Note{
		Kind: schema.NoteInsecureTLS, Subject: cluster,
		Detail: "TLS verification was off for cluster " + cluster + " (--insecure): the API server's identity was not checked, so its answers may not be the cluster's",
	}
}

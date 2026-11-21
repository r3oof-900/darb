package live

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ErrExecPlugin is returned for a kubeconfig user that runs an exec
// credential plugin: CLAPA runs no external commands (docs/THREAT_MODEL.md).
var ErrExecPlugin = errors.New(Name + ": the kubeconfig user runs an exec credential plugin; " +
	"CLAPA runs no external commands: for EKS use --k8s-eks CLUSTER (an in-memory token), otherwise a token or client certificate")

// KubeconfigREST loads a context of a kubeconfig (path "" for the default
// loading rules: $KUBECONFIG, then ~/.kube/config). It never prompts. TLS
// verification stays on unless insecure, which the report records.
func KubeconfigREST(path, kubeContext string, insecure bool) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		rules.ExplicitPath = path
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: kubeContext})
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("%s: kubeconfig: %w", Name, err)
	}
	if cfg.ExecProvider != nil || cfg.AuthProvider != nil {
		return nil, ErrExecPlugin
	}
	if insecure {
		cfg.Insecure, cfg.CAData, cfg.CAFile = true, nil, ""
	}
	return cfg, nil
}

// PresignAPI presigns sts:GetCallerIdentity (sts.PresignClient).
type PresignAPI interface {
	PresignGetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, opts ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

const tokenPrefix = "k8s-aws-v1." //nolint:gosec // G101: the EKS token format prefix, not a credential.

// EKSToken makes the bearer token EKS accepts: a SigV4-presigned
// sts:GetCallerIdentity URL that signs the x-k8s-aws-id header (the
// cluster name), base64url-encoded behind "k8s-aws-v1." (EKS user guide,
// "Grant IAM users access to Kubernetes"; what `aws eks get-token`
// prints). Presigning is local: nothing is sent. The token is never
// logged or written.
func EKSToken(ctx context.Context, p PresignAPI, cluster string) (string, error) {
	req, err := p.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(o *sts.PresignOptions) {
		o.ClientOptions = append(o.ClientOptions, func(so *sts.Options) {
			so.APIOptions = append(so.APIOptions,
				smithyhttp.SetHeaderValue("x-k8s-aws-id", cluster),
				smithyhttp.SetHeaderValue("X-Amz-Expires", "60"))
		})
	})
	if err != nil {
		return "", fmt.Errorf("%s: presigning the EKS token: %w", Name, err)
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(req.URL)), nil
}

// EKSREST is the configuration of an EKS cluster's API server reached with
// in-memory tokens, renewed before they expire (EKS accepts a token for 15
// minutes). TLS is verified against the cluster's CA.
func EKSREST(endpoint string, caData []byte, cluster string, p PresignAPI) *rest.Config {
	src := &tokenSource{presign: p, cluster: cluster, lifetime: 10 * time.Minute}
	return &rest.Config{
		Host:            endpoint,
		TLSClientConfig: rest.TLSClientConfig{CAData: caData},
		WrapTransport: func(rt http.RoundTripper) http.RoundTripper {
			return &bearer{next: rt, src: src}
		},
	}
}

type tokenSource struct {
	presign  PresignAPI
	cluster  string
	lifetime time.Duration
	mu       sync.Mutex
	token    string
	made     time.Time
}

func (s *tokenSource) get(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Since(s.made) < s.lifetime {
		return s.token, nil
	}
	t, err := EKSToken(ctx, s.presign, s.cluster)
	if err != nil {
		return "", err
	}
	s.token, s.made = t, time.Now()
	return t, nil
}

type bearer struct {
	next http.RoundTripper
	src  *tokenSource
}

func (b *bearer) RoundTrip(req *http.Request) (*http.Response, error) {
	t, err := b.src.get(req.Context())
	if err != nil {
		return nil, err
	}
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+t)
	return b.next.RoundTrip(r)
}

// DescribeClusterAPI reads an EKS cluster's endpoint and CA.
type DescribeClusterAPI interface {
	DescribeCluster(ctx context.Context, in *eks.DescribeClusterInput, opts ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
}

// EKSConfig reads the cluster's endpoint and certificate authority
// (eks:DescribeCluster) and returns its configuration with in-memory
// tokens.
func EKSConfig(ctx context.Context, api DescribeClusterAPI, p PresignAPI, cluster string) (*rest.Config, error) {
	out, err := api.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &cluster})
	if err != nil {
		return nil, fmt.Errorf("%s: eks:DescribeCluster %s: %w", Name, cluster, err)
	}
	c := out.Cluster
	if c == nil || c.Endpoint == nil || c.CertificateAuthority == nil || c.CertificateAuthority.Data == nil {
		return nil, fmt.Errorf("%s: cluster %s has no endpoint or certificate authority (is it active?)", Name, cluster)
	}
	ca, err := base64.StdEncoding.DecodeString(*c.CertificateAuthority.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: cluster %s certificate authority: %w", Name, cluster, err)
	}
	return EKSREST(*c.Endpoint, ca, cluster, p), nil
}

// ConnectEKS makes the clients of an EKS cluster from an AWS
// configuration (awslive.LoadConfig): the SDK reads the credentials.
func ConnectEKS(ctx context.Context, cfg *aws.Config, cluster string) (*Clients, error) {
	rc, err := EKSConfig(ctx, eks.NewFromConfig(*cfg), sts.NewPresignClient(sts.NewFromConfig(*cfg)), cluster)
	if err != nil {
		return nil, err
	}
	return NewClients(rc)
}

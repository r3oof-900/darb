package live

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func kubeconfig(t *testing.T, user string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config")
	cfg := `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString([]byte("not a real CA")) + `
contexts:
- name: ctx
  context: {cluster: c, user: u}
current-context: ctx
users:
- name: u
  user:
` + user
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKubeconfigREST(t *testing.T) {
	cfg, err := KubeconfigREST(kubeconfig(t, "    token: abc\n"), "ctx", false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Insecure || len(cfg.CAData) == 0 || cfg.Host != "https://127.0.0.1:6443" {
		t.Fatalf("config %+v", cfg)
	}
	cfg, err = KubeconfigREST(kubeconfig(t, "    token: abc\n"), "ctx", true)
	if err != nil || !cfg.Insecure || cfg.CAData != nil {
		t.Fatalf("insecure: %v %+v", err, cfg)
	}
	exec := "    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n      args: [eks, get-token, --cluster-name, prod]\n"
	if _, err := KubeconfigREST(kubeconfig(t, exec), "ctx", false); !errors.Is(err, ErrExecPlugin) {
		t.Fatalf("exec plugin: %v", err)
	}
	if _, err := KubeconfigREST(kubeconfig(t, "    token: abc\n"), "no-such-context", false); err == nil {
		t.Fatal("unknown context accepted")
	}
}

func presigner() *sts.PresignClient {
	return sts.NewPresignClient(sts.NewFromConfig(aws.Config{
		Region:      "eu-west-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "example-secret", ""),
	}))
}

// The token is built locally (presigning sends nothing): the presigned
// GetCallerIdentity URL signs the cluster name header.
func TestEKSToken(t *testing.T) {
	tok, err := EKSToken(context.Background(), presigner(), "prod")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, tokenPrefix) {
		t.Fatalf("token %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(tok, tokenPrefix))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Host != "sts.eu-west-1.amazonaws.com" || q.Get("Action") != "GetCallerIdentity" || q.Get("X-Amz-Expires") != "60" ||
		!strings.Contains(q.Get("X-Amz-SignedHeaders"), "x-k8s-aws-id") || q.Get("X-Amz-Signature") == "" {
		t.Fatalf("presigned URL %s", u)
	}
}

type countingPresigner struct {
	n   int
	err error
}

func (c *countingPresigner) PresignGetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	c.n++
	return &v4.PresignedHTTPRequest{URL: "https://sts.example/?n=1"}, c.err
}

type recordRT struct{ auth []string }

func (r *recordRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.auth = append(r.auth, req.Header.Get("Authorization"))
	return &http.Response{StatusCode: 200, Body: http.NoBody, Request: req}, nil
}

func TestEKSRESTReusesTheToken(t *testing.T) {
	p := &countingPresigner{}
	cfg := EKSREST("https://eks.example", []byte("ca"), "prod", p)
	rec := &recordRT{}
	rt := cfg.WrapTransport(rec)
	for range 3 {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://eks.example/api", http.NoBody)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if p.n != 1 || len(rec.auth) != 3 || !strings.HasPrefix(rec.auth[0], "Bearer "+tokenPrefix) || cfg.Insecure {
		t.Fatalf("presigned %d times, headers %v", p.n, rec.auth)
	}
	p.err = errors.New("no credentials")
	cfg = EKSREST("https://eks.example", nil, "prod", p)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://eks.example/api", http.NoBody)
	resp, err := cfg.WrapTransport(rec).RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a token error must fail the request")
	}
}

type fakeEKS struct{ out *eks.DescribeClusterOutput }

func (f fakeEKS) DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	if f.out == nil {
		return nil, errors.New("AccessDeniedException: not authorized")
	}
	return f.out, nil
}

func TestEKSConfig(t *testing.T) {
	ca := base64.StdEncoding.EncodeToString([]byte("ca-bytes"))
	ok := fakeEKS{&eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{
		Endpoint: aws.String("https://ABC.gr7.eu-west-1.eks.amazonaws.com"), CertificateAuthority: &ekstypes.Certificate{Data: aws.String(ca)},
	}}}
	cfg, err := EKSConfig(context.Background(), ok, &countingPresigner{}, "prod")
	if err != nil || cfg.Host != "https://ABC.gr7.eu-west-1.eks.amazonaws.com" || string(cfg.CAData) != "ca-bytes" || cfg.Insecure {
		t.Fatalf("%v %+v", err, cfg)
	}
	for name, f := range map[string]fakeEKS{
		"denied":   {},
		"inactive": {&eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{}}},
		"bad CA":   {&eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{Endpoint: aws.String("https://x"), CertificateAuthority: &ekstypes.Certificate{Data: aws.String("%%%")}}}},
	} {
		if _, err := EKSConfig(context.Background(), f, &countingPresigner{}, "prod"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/app"
	"github.com/r3oof-900/clapa/internal/collect/k8s/live/k8sfake"
)

// fakeK8s records how each cluster was asked for and serves one workload.
type fakeK8s struct {
	calls []string
	err   error
}

func (f *fakeK8s) env() *Env {
	return &Env{
		K8s: app.K8sConnector{
			Kubeconfig: func(path, kubeContext string, insecure bool) (*app.K8sClients, error) {
				f.calls = append(f.calls, "kubeconfig "+path+" "+kubeContext+" insecure="+map[bool]string{true: "yes", false: "no"}[insecure])
				if f.err != nil {
					return nil, f.err
				}
				c := k8sfake.Clients(k8sfake.Workload("payments", "api", "arn:aws:iam::111122223333:role/payments-api")...)
				c.Insecure = insecure
				return c, nil
			},
			EKS: func(_ context.Context, profile, region, cluster string) (*app.K8sClients, string, error) {
				f.calls = append(f.calls, "eks "+profile+" "+region+" "+cluster)
				return k8sfake.Clients(k8sfake.Workload("payments", "api", "")...), "arn:aws:eks:" + region + ":111122223333:cluster/" + cluster, nil
			},
		},
	}
}

func runK8s(t *testing.T, f *fakeK8s, args ...string) (code ExitCode, stdout, stderr string) {
	t.Helper()
	var out, errOut strings.Builder
	code = RunWith(context.Background(), args, &out, &errOut, f.env())
	return code, out.String(), errOut.String()
}

const prodConfig = "version: 1\nclusters:\n  - {name: prod, account: \"111122223333\", region: us-east-1}\n"

func rootWithConfig(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "clapa.yaml"), []byte(prodConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestScanLiveK8s(t *testing.T) {
	f := &fakeK8s{}
	code, out, errOut := runK8s(t, f, "scan", "--root", rootWithConfig(t), "--live-k8s", "kind-prod=prod", "--kubeconfig", "kc.yaml", "--format", "json")
	if code == ExitUsage || code == ExitInternal || !strings.Contains(out, `"collected": 3`) {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	// prod resolves through clapa.yaml to its ARN, the cluster's key.
	if !strings.Contains(out, "k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/payments/Namespace") &&
		!strings.Contains(out, "k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod//Namespace/payments") {
		t.Fatalf("the cluster key is not the ARN:\n%s", out)
	}
	if len(f.calls) != 1 || f.calls[0] != "kubeconfig kc.yaml kind-prod insecure=no" || strings.Contains(errOut, "WARNING") {
		t.Fatalf("calls %v, stderr %q", f.calls, errOut)
	}
}

func TestScanLiveK8sInsecure(t *testing.T) {
	f := &fakeK8s{}
	_, out, errOut := runK8s(t, f, "scan", "--root", rootWithConfig(t), "--live-k8s", "kind-prod=prod", "--insecure")
	if !strings.Contains(errOut, "WARNING: --insecure: TLS verification is OFF") || f.calls[0] != "kubeconfig  kind-prod insecure=yes" {
		t.Fatalf("stderr %q calls %v", errOut, f.calls)
	}
	if !strings.Contains(out, "WARNING: TLS verification was off for cluster arn:aws:eks:us-east-1:111122223333:cluster/prod (--insecure)") {
		t.Fatalf("the report does not record it:\n%s", out)
	}
}

func TestScanK8sEKS(t *testing.T) {
	f := &fakeK8s{}
	code, out, errOut := runK8s(t, f, "scan", "--root", t.TempDir(), "--k8s-eks", "prod", "--aws-profile", "audit", "--aws-region", "eu-west-1", "--format", "json")
	if code == ExitUsage || code == ExitInternal || f.calls[0] != "eks audit eu-west-1 prod" {
		t.Fatalf("exit %d calls %v\n%s", code, f.calls, errOut)
	}
	if !strings.Contains(out, "k8s:arn:aws:eks:eu-west-1:111122223333:cluster/prod/") {
		t.Fatalf("the EKS cluster's ARN is its key:\n%s", out)
	}
}

func TestLiveK8sErrors(t *testing.T) {
	f := &fakeK8s{err: errors.New("the kubeconfig context \"kind-prod\" authenticates with a credential plugin")}
	if code, _, errOut := runK8s(t, f, "scan", "--root", t.TempDir(), "--live-k8s", "kind-prod"); code != ExitUsage || !strings.Contains(errOut, "credential plugin") {
		t.Fatalf("exit %d %q", code, errOut)
	}
	if code, _, errOut := runK8s(t, &fakeK8s{}, "remediate", "--root", t.TempDir(), "--live-k8s", "kind-prod",
		"0000000000000000000000000000000000000000000000000000000000000000"); code != ExitUsage || !strings.Contains(errOut, "collect-snapshot") {
		t.Fatalf("remediate live: exit %d %q", code, errOut)
	}
}

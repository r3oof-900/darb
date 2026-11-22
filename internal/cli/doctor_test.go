package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/app"
	"github.com/r3oof-900/darb/internal/collect/awslive"
	"github.com/r3oof-900/darb/internal/collect/awslive/awsfake"
	"github.com/r3oof-900/darb/internal/collect/k8s/live/k8sfake"
)

func doctorEnv(files map[string]bool, vars map[string]string) *Env {
	e := (&fakeEnv{fake: &awsfake.Factory{}}).env()
	e.Exists = func(p string) bool { return files[filepath.ToSlash(p)] }
	e.Getenv = func(k string) string { return vars[k] }
	e.K8s = app.K8sConnector{Kubeconfig: func(_, kubeContext string, _ bool) (*app.K8sClients, error) {
		if kubeContext != "kind-darb" {
			return nil, errors.New("no context " + kubeContext)
		}
		return k8sfake.Clients(), nil
	}}
	return e
}

func runDoctor(t *testing.T, e *Env, args ...string) (code ExitCode, output string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = RunWith(context.Background(), append([]string{"doctor"}, args...), &out, &errOut, e)
	return code, out.String() + errOut.String()
}

// Without a probe flag, doctor calls nothing and reads no file: it says
// which files exist, names settings, and never shows a key's value.
func TestDoctorOffline(t *testing.T) {
	const secret = "AKIA" + "QQQQQQQQQQQQQQQQ"
	e := doctorEnv(map[string]bool{"/cfg/aws": true}, map[string]string{ //nolint:gosec // G101: test values; the test checks they are never printed.
		"AWS_CONFIG_FILE": "/cfg/aws", "AWS_SHARED_CREDENTIALS_FILE": "/cfg/creds", "AWS_PROFILE": "audit",
		"AWS_ACCESS_KEY_ID": secret, app.LLMKeyVariable: "sk-ant-" + "x", "KUBECONFIG": "/k/a" + string(filepath.ListSeparator) + "/k/b",
	})
	calls := 0
	e.AWS = func(context.Context, string, []string) (awslive.Factory, []string, error) {
		calls++
		return nil, nil, errors.New("must not be called")
	}
	code, out := runDoctor(t, e)
	for _, want := range []string{
		"[ok     ] darb: ", "[ok     ] go runtime: go", "[warn   ] managed-policy snapshot: 3 AWS managed policies",
		"config file present; credentials file absent; AWS_PROFILE=audit; AWS_ACCESS_KEY_ID set (value not shown) (contents not read)",
		"[absent ] kubeconfig: /k/a absent; /k/b absent", "[ok     ] LLM key: ANTHROPIC_API_KEY set (value not shown)",
		"[skipped] AWS probe", "[skipped] Kubernetes probe",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if code != ExitOK || calls != 0 || strings.Contains(out, secret) || strings.Contains(out, "sk-ant-") {
		t.Fatalf("%d calls %d:\n%s", code, calls, out)
	}
}

// The probes: sts:GetCallerIdentity on the fake account and a cluster's
// version; a failed probe is exit 3.
func TestDoctorProbes(t *testing.T) {
	e := doctorEnv(nil, nil)
	code, out := runDoctor(t, e, "--probe-aws", "--aws-region", "eu-west-1", "--probe-k8s", "kind-darb")
	if code != ExitOK || !strings.Contains(out, "[ok     ] AWS probe (sts:GetCallerIdentity): account 111122223333") ||
		!strings.Contains(out, "[ok     ] Kubernetes probe (server version): context kind-darb: Kubernetes ") {
		t.Fatalf("%d:\n%s", code, out)
	}
	code, out = runDoctor(t, e, "--probe-k8s", "other")
	if code != ExitIncomplete || !strings.Contains(out, "[fail   ] Kubernetes probe (server version): no context other") {
		t.Fatalf("%d:\n%s", code, out)
	}
	if code, _ := runDoctor(t, e, "extra"); code != ExitUsage {
		t.Errorf("an argument: %d", code)
	}
}

// darb graph writes every node and edge of the inputs, in a stable order:
// the JSON counts are the report's, two runs are identical, DOT is the
// default.
func TestGraphCommand(t *testing.T) {
	args := append([]string{"graph"}, scan01...)
	code, dot, _ := run(t, args...)
	if code != ExitOK || !strings.HasPrefix(dot, "digraph darb {") ||
		!strings.Contains(dot, `"k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/payments/Deployment/api" -> "k8s:arn:aws:eks:us-east-1:111122223333:cluster/prod/payments/ServiceAccount/api" [label="RUNS_AS", style=solid];`) {
		t.Fatalf("dot %d:\n%s", code, dot)
	}
	_, js, _ := run(t, append(args, "--format", "json")...)
	_, again, _ := run(t, append(args, "--format", "json")...)
	var doc struct {
		Schema string `json:"schema"`
		Nodes  []any  `json:"nodes"`
		Edges  []struct {
			Kind    string `json:"kind"`
			Derived bool   `json:"derived"`
		} `json:"edges"`
	}
	if err := json.Unmarshal([]byte(js), &doc); err != nil || js != again {
		t.Fatalf("json %v (stable: %t)", err, js == again)
	}
	_, rep, _ := run(t, append(append([]string{"scan"}, scan01...), "--format", "json")...)
	var r struct {
		Graph struct{ Nodes, Edges int } `json:"graph"`
	}
	if err := json.Unmarshal([]byte(rep), &r); err != nil || doc.Schema != app.GraphVersion || len(doc.Nodes) != r.Graph.Nodes || len(doc.Edges) != r.Graph.Edges {
		t.Fatalf("graph %d nodes %d edges, report %+v", len(doc.Nodes), len(doc.Edges), r.Graph)
	}
	if code, _, _ := run(t, append(args, "--format", "sarif")...); code != ExitUsage {
		t.Errorf("sarif graph: %d", code)
	}
}

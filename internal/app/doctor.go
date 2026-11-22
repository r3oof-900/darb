package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/r3oof-900/darb/internal/collect/awslive"
	"github.com/r3oof-900/darb/internal/managedpolicies"
	"github.com/r3oof-900/darb/internal/rules/catalog"
	"github.com/r3oof-900/darb/internal/version"
)

// Doctor statuses.
const (
	DoctorOK      = "ok"
	DoctorWarn    = "warn"
	DoctorAbsent  = "absent"
	DoctorFail    = "fail"
	DoctorSkipped = "skipped"
)

// DoctorCheck is one line of darb doctor.
type DoctorCheck struct {
	Name, Status, Detail string
}

// DoctorOptions say what darb doctor looks at. It reads no file: it says
// whether the AWS and Kubernetes configuration files exist, never what is in
// them (DESIGN.md §11). It calls a cloud API only when asked to probe.
type DoctorOptions struct {
	Getenv func(string) string
	Exists func(path string) bool
	Home   string

	ProbeAWS   bool
	AWSProfile string
	AWSRegions []string
	AWS        AWSConnector

	ProbeK8s   string // a kubeconfig context; "" for none
	Kubeconfig string
	K8s        func(path, kubeContext string, insecure bool) (*K8sClients, error)
}

// managedPolicyMinimum: below it the vendored snapshot is far from AWS's
// full set of managed policies (over a thousand), and the report says so.
const managedPolicyMinimum = 1000

// Doctor runs the checks in a fixed order.
func Doctor(ctx context.Context, o *DoctorOptions) []DoctorCheck {
	v := version.Get()
	out := []DoctorCheck{
		{"darb", DoctorOK, fmt.Sprintf("%s (commit %s, rule catalog %s)", v.Version, v.Commit, catalog.Version)},
		{"go runtime", DoctorOK, fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)},
		managedPolicyCheck(),
	}
	out = append(out, o.awsConfig(), o.kubeconfig(), o.llmKey(), o.probeAWS(ctx), o.probeK8s())
	return out
}

func managedPolicyCheck() DoctorCheck {
	mp, err := managedpolicies.Load()
	if err != nil {
		return DoctorCheck{"managed-policy snapshot", DoctorFail, err.Error()}
	}
	d := fmt.Sprintf("%d AWS managed policies, snapshot of %s", len(mp.Policies), mp.SnapshotDate)
	if len(mp.Policies) < managedPolicyMinimum {
		return DoctorCheck{"managed-policy snapshot", DoctorWarn, d + ": incomplete; every other attached managed policy is UNKNOWN (go run ./tools/refresh-managed-policies)"}
	}
	return DoctorCheck{"managed-policy snapshot", DoctorOK, d}
}

// file: a path from an environment variable, else under the home directory.
func (o *DoctorOptions) file(env string, rel ...string) string {
	if p := o.Getenv(env); p != "" {
		return p
	}
	if o.Home == "" {
		return ""
	}
	return filepath.Join(append([]string{o.Home}, rel...)...)
}

func (o *DoctorOptions) present(p string) string {
	if p != "" && o.Exists(p) {
		return "present"
	}
	return "absent"
}

// awsConfig: whether the shared files exist and which settings the
// environment names. Key values are never shown, only whether one is set.
func (o *DoctorOptions) awsConfig() DoctorCheck {
	cfg, creds := o.file("AWS_CONFIG_FILE", ".aws", "config"), o.file("AWS_SHARED_CREDENTIALS_FILE", ".aws", "credentials")
	parts := []string{"config file " + o.present(cfg), "credentials file " + o.present(creds)}
	for _, k := range []string{"AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		if v := o.Getenv(k); v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if o.Getenv("AWS_ACCESS_KEY_ID") != "" {
		parts = append(parts, "AWS_ACCESS_KEY_ID set (value not shown)")
	}
	status := DoctorOK
	if o.present(cfg) == "absent" && o.present(creds) == "absent" && o.Getenv("AWS_ACCESS_KEY_ID") == "" {
		status = DoctorAbsent
	}
	return DoctorCheck{"AWS configuration", status, strings.Join(parts, "; ") + " (contents not read)"}
}

func (o *DoctorOptions) kubeconfig() DoctorCheck {
	paths := []string{o.file("", ".kube", "config")}
	if o.Kubeconfig != "" {
		paths = []string{o.Kubeconfig}
	} else if env := o.Getenv("KUBECONFIG"); env != "" {
		paths = filepath.SplitList(env)
	}
	var parts []string
	found := false
	for _, p := range paths {
		s := o.present(p)
		found = found || s == "present"
		parts = append(parts, p+" "+s)
	}
	status := DoctorOK
	if !found {
		status = DoctorAbsent
	}
	return DoctorCheck{"kubeconfig", status, strings.Join(parts, "; ") + " (contents not read)"}
}

func (o *DoctorOptions) llmKey() DoctorCheck {
	if o.Getenv(LLMKeyVariable) != "" {
		return DoctorCheck{"LLM key", DoctorOK, LLMKeyVariable + " set (value not shown); used only with --llm"}
	}
	return DoctorCheck{"LLM key", DoctorAbsent, LLMKeyVariable + " not set; --llm is off by default"}
}

// probeAWS: sts:GetCallerIdentity with the configured credentials (the
// only call; the policy of docs/PERMISSIONS.md allows it).
func (o *DoctorOptions) probeAWS(ctx context.Context) DoctorCheck {
	const name = "AWS probe (sts:GetCallerIdentity)"
	if !o.ProbeAWS {
		return DoctorCheck{name, DoctorSkipped, "pass --probe-aws to call AWS"}
	}
	if o.AWS == nil {
		return DoctorCheck{name, DoctorFail, "no AWS connector"}
	}
	factory, regions, err := o.AWS(ctx, o.AWSProfile, o.AWSRegions)
	if err == nil && len(regions) == 0 {
		err = ErrNoRegion
	}
	if err != nil {
		return DoctorCheck{name, DoctorFail, err.Error()}
	}
	account, arn, err := awslive.CallerIdentity(ctx, factory.Clients(awslive.Target{}, regions[0]))
	if err != nil {
		return DoctorCheck{name, DoctorFail, err.Error()}
	}
	return DoctorCheck{name, DoctorOK, fmt.Sprintf("account %s as %s (region %s)", account, arn, regions[0])}
}

// probeK8s: the API server's version through a kubeconfig context.
func (o *DoctorOptions) probeK8s() DoctorCheck {
	const name = "Kubernetes probe (server version)"
	if o.ProbeK8s == "" {
		return DoctorCheck{name, DoctorSkipped, "pass --probe-k8s CONTEXT to call a cluster"}
	}
	if o.K8s == nil {
		return DoctorCheck{name, DoctorFail, "no Kubernetes connector"}
	}
	c, err := o.K8s(o.Kubeconfig, o.ProbeK8s, false)
	if err != nil {
		return DoctorCheck{name, DoctorFail, err.Error()}
	}
	v, err := c.Typed.Discovery().ServerVersion()
	if err != nil {
		return DoctorCheck{name, DoctorFail, err.Error()}
	}
	return DoctorCheck{name, DoctorOK, "context " + o.ProbeK8s + ": Kubernetes " + v.GitVersion}
}

// DefaultExists reports whether a path exists (darb doctor).
func DefaultExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

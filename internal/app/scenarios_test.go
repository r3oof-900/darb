package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r3oof-900/clapa/internal/rules"
)

// analyzeVariant copies a fixture variant, lets edit change the copy, and
// analyzes it (the fixture itself is never modified).
func analyzeVariant(t *testing.T, fixture string, edit func(dir string)) *Analysis {
	t.Helper()
	dir := copyTree(t, filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(fixture)))
	if edit != nil {
		edit(dir)
	}
	in := scansFor(t, dir)["normalized.golden.json"]
	l, err := Load(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Analyze(l, in.Config, DefaultFailOn)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func replaceIn(t *testing.T, file, old, repl string) {
	t.Helper()
	data, err := os.ReadFile(file) //nolint:gosec // G304: inside the test's temp copy.
	if err != nil || !strings.Contains(string(data), old) {
		t.Fatalf("%s: %q not found (%v)", file, old, err)
	}
	if err := os.WriteFile(file, []byte(strings.Replace(string(data), old, repl, 1)), 0o600); err != nil { //nolint:gosec // G703: temp copy.
		t.Fatal(err)
	}
}

func findingFor(a *Analysis, rule, jewel string) *rules.Finding {
	for i := range a.Findings {
		if a.Findings[i].Rule == rule && a.Findings[i].Jewel == jewel {
			return &a.Findings[i]
		}
	}
	return nil
}

// Scenario 7 (DESIGN.md §13.2): iam:PassRole + lambda:CreateFunction without
// an execution primitive is still an escalation, with lower confidence.
func TestPassRoleWithoutInvokeIsLowerConfidence(t *testing.T) {
	a := analyzeVariant(t, "07_passrole_lambda/vulnerable", func(dir string) {
		replaceIn(t, filepath.Join(dir, "terraform", "role.tf"), `["lambda:CreateFunction", "lambda:InvokeFunction"]`, `["lambda:CreateFunction"]`)
	})
	f := findingFor(a, "CLAPA-PATH-002", "arn:aws:s3:::acme-customer-pii")
	if f == nil || f.Confidence != "medium" || f.Factors.Confidence != 700 {
		t.Fatalf("PassRole + CreateFunction alone: %+v", f)
	}
}

// Scenario 10 (DESIGN.md §13.2): with the organization ID configured, a
// matching one gives the path, a non-matching one gives none.
func TestOrganizationIDDecidesScenario10(t *testing.T) {
	withOrg := func(org string) *Analysis {
		return analyzeVariant(t, "10_kms_principal_org_id/vulnerable", func(dir string) {
			f, err := os.OpenFile(filepath.Join(dir, "clapa.yaml"), os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // G304: temp copy.
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if _, err := f.WriteString("assume:\n  aws:PrincipalOrgID: [\"" + org + "\"]\n"); err != nil {
				t.Fatal(err)
			}
		})
	}
	if f := findingFor(withOrg("o-a1b2c3d4e5"), "CLAPA-PATH-001", "arn:aws:s3:::acme-customer-pii"); f == nil || !f.Confirmed {
		t.Errorf("matching organization: %+v", f)
	}
	if f := findingFor(withOrg("o-other"), "CLAPA-PATH-001", "arn:aws:s3:::acme-customer-pii"); f != nil {
		t.Errorf("non-matching organization: %+v", f)
	}
}

// Every rule names failing and passing cases: fixture variants (which must
// exist) or rule-level tests ("test:<name>").
func TestRuleCatalogMetadata(t *testing.T) {
	a := analyzeVariant(t, "01_classic/vulnerable", nil)
	for _, r := range a.Registry.Rules() {
		m := r.Meta()
		if m.Title == "" || m.Rationale == "" || len(m.References) == 0 || m.Major() != "1" {
			t.Errorf("%s: incomplete metadata", m.ID)
		}
		for _, ref := range m.References {
			if !strings.HasPrefix(ref.URL, "https://") {
				t.Errorf("%s: reference %s", m.ID, ref.URL)
			}
		}
		if len(m.Failing) == 0 || len(m.Passing) == 0 {
			t.Errorf("%s: needs at least one failing and one passing case", m.ID)
		}
		for _, f := range append(m.Failing, m.Passing...) {
			if strings.HasPrefix(f, "test:") {
				continue
			}
			if _, err := os.Stat(filepath.Join(repoRoot(t), "tests", "fixtures", filepath.FromSlash(f))); err != nil {
				t.Errorf("%s: fixture %s: %v", m.ID, f, err)
			}
		}
	}
}

// A pod that projects a service account token itself gets an ASSUMES edge
// with no annotation (Phase 4 review, C): an sts.amazonaws.com audience is
// accepted by the documented OIDC setup; any other audience, with the
// provider not in the input, is UNKNOWN.
func TestProjectedTokenWithoutAnnotation(t *testing.T) {
	project := func(audience string) func(dir string) {
		return func(dir string) {
			file := filepath.Join(dir, "k8s", "tools.yaml")
			replaceIn(t, file, "    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/tools-ci\n", "    team: tools\n")
			replaceIn(t, file, "  annotations:\n    team: tools\n", "  labels:\n    team: tools\n")
			replaceIn(t, file, "      containers:\n        - name: shell\n", "      volumes:\n        - name: aws\n          projected:\n            sources:\n              - serviceAccountToken:\n                  audience: "+audience+"\n                  path: token\n      containers:\n        - name: shell\n")
		}
	}
	pathFrom := func(a *Analysis) *rules.Finding {
		for i := range a.Findings {
			if a.Findings[i].Entry == "k8s:prod/tools/Deployment/debug" {
				return &a.Findings[i]
			}
		}
		return nil
	}
	if f := pathFrom(analyzeVariant(t, "04_wildcard_sub/vulnerable", project("sts.amazonaws.com"))); f == nil || !f.Confirmed ||
		!strings.Contains(strings.Join(f.Path, " "), "ASSUMES arn:aws:iam::111122223333:role/payments-api") {
		t.Errorf("projected sts.amazonaws.com token: %+v", f)
	}
	// The trust itself requires aud = sts.amazonaws.com: a definite no.
	if f := pathFrom(analyzeVariant(t, "04_wildcard_sub/vulnerable", project("vault"))); f != nil {
		t.Errorf("the trust's aud condition refuses the token: %+v", f)
	}
	// The trust accepts vault too; whether the provider does is not in the input.
	acceptVault := func(dir string) {
		project("vault")(dir)
		replaceIn(t, filepath.Join(dir, "terraform", "trust.tf"), `values   = ["sts.amazonaws.com"]`, `values   = ["sts.amazonaws.com", "vault"]`)
	}
	if f := pathFrom(analyzeVariant(t, "04_wildcard_sub/vulnerable", acceptVault)); f == nil || f.Confirmed {
		t.Errorf("an audience the absent provider may not accept is UNKNOWN: %+v", f)
	}
}

// create on serviceaccounts/token is as good as create on pods: it mints a
// token with any audience for any service account of the namespace.
func TestTokenRequestIsLikePodCreation(t *testing.T) {
	a := analyzeVariant(t, "04b_create_pods_wildcard/vulnerable", func(dir string) {
		replaceIn(t, filepath.Join(dir, "k8s", "tools.yaml"), `resources: ["pods"]`, `resources: ["serviceaccounts/token"]`)
	})
	if f := findingFor(a, "CLAPA-PATH-002", "arn:aws:s3:::acme-customer-pii"); f == nil || f.Entry != "k8s:prod/tools/Deployment/builder" {
		t.Errorf("token request: %+v", f)
	}
	a = analyzeVariant(t, "04b_create_pods_wildcard/vulnerable", func(dir string) {
		replaceIn(t, filepath.Join(dir, "k8s", "tools.yaml"), `verbs: ["create", "get", "list"]`, `verbs: ["get", "list"]`)
	})
	if f := findingFor(a, "CLAPA-PATH-002", "arn:aws:s3:::acme-customer-pii"); f != nil {
		t.Errorf("read-only RBAC mints nothing: %+v", f)
	}
}

// deployerSetup adds, to a copy of scenario 8 fixed (ci can only read), a
// workload whose IRSA role "deployer" is given Kubernetes access by mapAccess.
func deployerSetup(t *testing.T, mapAccess string, tf string) func(dir string) {
	t.Helper()
	return func(dir string) {
		k8s := `apiVersion: v1
kind: ServiceAccount
metadata:
  name: deploy
  namespace: payments
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/deployer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy
  namespace: payments
spec:
  selector:
    matchLabels:
      app: deploy
  template:
    metadata:
      labels:
        app: deploy
    spec:
      serviceAccountName: deploy
      containers:
        - name: deploy
          image: registry.example.com/deploy:1
` + mapAccess
		role := `resource "aws_iam_role" "deployer" {
  name = "deployer"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow",
    Principal = { Federated = local.oidc_provider }, Action = "sts:AssumeRoleWithWebIdentity",
    Condition = { StringEquals = { "${local.oidc_host}:sub" = "system:serviceaccount:payments:deploy", "${local.oidc_host}:aud" = "sts.amazonaws.com" } } }] })
}
` + tf
		for name, content := range map[string]string{filepath.Join(dir, "k8s", "deploy.yaml"): k8s, filepath.Join(dir, "terraform", "deployer.tf"): role} {
			if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// aws-auth and EKS access entries reach Kubernetes RBAC (MAPS_TO, then the
// subject's escalation edges), and from there the namespace's IRSA roles.
func TestIAMToKubernetesMappings(t *testing.T) {
	awsAuth := `---
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: arn:aws:iam::111122223333:role/deployer
      username: deployer
      groups: [deployers]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-creator
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deployers
  namespace: payments
subjects:
  - kind: Group
    name: deployers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-creator
`
	accessEntry := `resource "aws_eks_access_entry" "deployer" {
  cluster_name  = "prod"
  principal_arn = aws_iam_role.deployer.arn
}
resource "aws_eks_access_policy_association" "deployer" {
  cluster_name  = "prod"
  principal_arn = aws_iam_role.deployer.arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"
  access_scope {
    type       = "namespace"
    namespaces = ["payments"]
  }
}
`
	for name, c := range map[string]struct{ k8s, tf, step string }{
		"aws-auth":     {awsAuth, "", "MAPS_TO k8s:prod//Group/deployers"},
		"access entry": {"", accessEntry, "CAN_ESCALATE k8s:prod/payments/ServiceAccount/api"},
	} {
		a := analyzeVariant(t, "08_rbac_create_pods/fixed", deployerSetup(t, c.k8s, c.tf))
		var f *rules.Finding
		for i := range a.Findings {
			if a.Findings[i].Entry == "k8s:prod/payments/Deployment/deploy" && a.Findings[i].Rule == "CLAPA-PATH-002" {
				f = &a.Findings[i]
			}
		}
		if f == nil || !strings.Contains(strings.Join(f.Path, " | "), c.step) || !f.Confirmed {
			t.Errorf("%s: %+v", name, f)
		}
	}
	// A view-only access policy gives no escalation.
	view := strings.Replace(accessEntry, "AmazonEKSEditPolicy", "AmazonEKSViewPolicy", 1)
	a := analyzeVariant(t, "08_rbac_create_pods/fixed", deployerSetup(t, "", view))
	for i := range a.Findings {
		if a.Findings[i].Entry == "k8s:prod/payments/Deployment/deploy" && a.Findings[i].Rule == "CLAPA-PATH-002" {
			t.Errorf("view only: %+v", a.Findings[i])
		}
	}
}

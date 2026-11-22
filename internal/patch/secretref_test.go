package patch

import (
	"strings"
	"testing"

	"github.com/r3oof-900/darb/internal/model"
	"github.com/r3oof-900/darb/internal/remediate"
)

const pod = `apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: ns
spec:
  initContainers:
    - name: init
      image: i
      envFrom:
        - secretRef:
            name: db
        - configMapRef:
            name: settings
  containers:
    - name: app
      image: a
      env:
        - name: MODE
          value: live
        - name: PASSWORD
          valueFrom:
            secretKeyRef:
              name: db
              key: password
        - name: TOKEN
          valueFrom:
            secretKeyRef:
              name: other
              key: token
      volumeMounts:
        - name: creds
          mountPath: /etc/creds
        - name: cache
          mountPath: /cache
  volumes:
    - name: creds
      secret:
        secretName: db
    - name: cache
      emptyDir: {}
`

func renderSecretRef(t *testing.T, src, secret string) *Result {
	t.Helper()
	loc := model.FileLocation("k8s/pod.yaml", 1, 1, "Pod/ns/app")
	w := model.NewWorkload(&model.WorkloadInput{Cluster: "prod", Namespace: "ns", Kind: "Pod", Name: "app", SecretRefs: []string{secret}, Source: loc})
	res, err := Render(&model.Inventory{Workloads: []*model.Workload{w}},
		[]remediate.Edit{{Op: remediate.OpRemoveSecretRef, Workload: w, Secret: secret}},
		memSource{"k8s/pod.yaml": []byte(src)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Only what names the Secret goes: its env entry, its envFrom entry, its
// volume and that volume's mount; the other entries of each list stay.
func TestRemoveSecretRefKeepsTheRest(t *testing.T) {
	res := renderSecretRef(t, pod, "db")
	if !res.Complete() || len(res.Files) != 1 {
		t.Fatalf("%+v", res)
	}
	after := string(res.Files[0].After)
	for _, gone := range []string{"name: db", "secretName: db", "PASSWORD", "creds"} {
		if strings.Contains(after, gone) {
			t.Errorf("%q is still there:\n%s", gone, after)
		}
	}
	for _, kept := range []string{"configMapRef:", "name: MODE", "name: other", "name: cache", "emptyDir: {}", "mountPath: /cache"} {
		if !strings.Contains(after, kept) {
			t.Errorf("%q was removed:\n%s", kept, after)
		}
	}
}

// A list left empty loses its key; a flow-style list or a projected
// volume with other sources is a TODO.
func TestRemoveSecretRefForms(t *testing.T) {
	only := strings.Replace(pod, `        - name: MODE
          value: live
`, "", 1)
	only = strings.Replace(only, `        - name: TOKEN
          valueFrom:
            secretKeyRef:
              name: other
              key: token
`, "", 1)
	if after := string(renderSecretRef(t, only, "db").Files[0].After); strings.Contains(after, "      env:") {
		t.Errorf("an empty env list keeps its key:\n%s", after)
	}
	flow := strings.Replace(pod, `      envFrom:
        - secretRef:
            name: db
        - configMapRef:
            name: settings`, `      envFrom: [{secretRef: {name: db}}]`, 1)
	if res := renderSecretRef(t, flow, "db"); res.Complete() || !strings.Contains(res.TODO[0], "flow-style") {
		t.Errorf("flow list: %+v", res)
	}
	projected := strings.Replace(pod, `      secret:
        secretName: db`, `      projected:
        sources:
          - secret:
              name: db
          - configMap:
              name: settings`, 1)
	if res := renderSecretRef(t, projected, "db"); res.Complete() || !strings.Contains(res.TODO[0], "projected volume creds") {
		t.Errorf("projected: %+v", res)
	}
}

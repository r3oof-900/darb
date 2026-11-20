package k8s

import (
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/r3oof-900/clapa/internal/collect/k8sraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
	"github.com/r3oof-900/clapa/internal/normalize"
)

// Name identifies this normalizer in coverage gaps.
const Name = "normalize-k8s"

// IRSA annotations (EKS User Guide › "Configure Kubernetes service accounts
// to assume an IAM role").
const (
	annotationRoleARN  = "eks.amazonaws.com/role-arn"
	annotationAudience = "eks.amazonaws.com/audience"
	defaultAudience    = "sts.amazonaws.com"
)

// workload is a pod template with its owner, used for selector matching.
type workload struct {
	node   *model.Workload
	labels map[string]string
	spec   *corev1.PodSpec
}

type norm struct {
	cluster   string
	b         *normalize.Builder
	rec       *coverage.Recorder
	workloads []*workload
	accounts  map[string]*corev1.ServiceAccount // "ns/name"
	saSource  map[string]model.SourceLocation
}

// Normalize converts decoded manifests of one cluster into canonical nodes.
func Normalize(objs *k8sraw.Objects, b *normalize.Builder, rec *coverage.Recorder) {
	n := &norm{cluster: objs.Cluster, b: b, rec: rec, accounts: map[string]*corev1.ServiceAccount{}, saSource: map[string]model.SourceLocation{}}
	for _, o := range objs.Items {
		if sa, ok := o.Obj.(*corev1.ServiceAccount); ok {
			n.accounts[o.Namespace+"/"+o.Name] = sa
			n.saSource[o.Namespace+"/"+o.Name] = loc(o)
		}
	}
	for _, o := range objs.Items {
		if spec, labels, ok := podTemplate(o); ok {
			n.addWorkload(o, spec, labels)
		}
	}
	n.addServiceAccounts()
	n.exposures(objs.Items)
	n.rbac(objs.Items)
	n.awsAuth(objs.Items)
	n.secrets(objs.Items)
}

func loc(o *k8sraw.Object) model.SourceLocation {
	return model.FileLocation(o.Pos.File, o.Pos.Line, o.Pos.Line, o.Kind+"/"+o.Namespace+"/"+o.Name)
}

func (n *norm) gap(kind coverage.Kind, o *k8sraw.Object, detail string) {
	n.rec.Add(&coverage.Gap{Kind: kind, Source: Name, File: o.Pos.File, Line: o.Pos.Line, Address: o.Kind + "/" + o.Namespace + "/" + o.Name, Detail: detail})
}

// podTemplate extracts the pod spec of every workload kind.
func podTemplate(o *k8sraw.Object) (*corev1.PodSpec, map[string]string, bool) {
	switch w := o.Obj.(type) {
	case *appsv1.Deployment:
		return &w.Spec.Template.Spec, w.Spec.Template.Labels, true
	case *appsv1.StatefulSet:
		return &w.Spec.Template.Spec, w.Spec.Template.Labels, true
	case *appsv1.DaemonSet:
		return &w.Spec.Template.Spec, w.Spec.Template.Labels, true
	case *appsv1.ReplicaSet:
		return &w.Spec.Template.Spec, w.Spec.Template.Labels, true
	case *batchv1.Job:
		return &w.Spec.Template.Spec, w.Spec.Template.Labels, true
	case *batchv1.CronJob:
		return &w.Spec.JobTemplate.Spec.Template.Spec, w.Spec.JobTemplate.Spec.Template.Labels, true
	case *corev1.Pod:
		return &w.Spec, w.Labels, true
	}
	return nil, nil, false
}

// addWorkload: pods without serviceAccountName run as "default"; the token
// is mounted unless the pod or its service account says otherwise
// (Kubernetes › "Configure Service Accounts for Pods").
func (n *norm) addWorkload(o *k8sraw.Object, spec *corev1.PodSpec, labels map[string]string) {
	sa := spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	acct, declared := n.accounts[o.Namespace+"/"+sa]
	if !declared && sa != "default" {
		n.gap(coverage.KindUnresolved, o, "service account "+o.Namespace+"/"+sa+" is not in the input")
	}
	automount, defaulted := automountOf(spec, acct, declared || sa == "default")
	w := model.NewWorkload(&model.WorkloadInput{
		Cluster: n.cluster, Namespace: o.Namespace, Kind: o.Kind, Name: o.Name, ServiceAccount: sa,
		HostNetwork: spec.HostNetwork, Privileged: privileged(spec), AutomountToken: automount, Defaulted: defaulted, Source: loc(o),
	})
	n.b.AddWorkload(w)
	n.workloads = append(n.workloads, &workload{node: w, labels: labels, spec: spec})
}

// automountOf: the Pod's automountServiceAccountToken wins over its service
// account's; when neither states it the token is mounted (documented
// default). A service account that is not in the input (other than the
// namespace's "default", which Kubernetes creates without the field) may
// set it, so the value is then unknown.
func automountOf(spec *corev1.PodSpec, acct *corev1.ServiceAccount, accountKnown bool) (mount model.Tri, defaulted []string) {
	switch {
	case spec.AutomountServiceAccountToken != nil:
		return model.TriOf(*spec.AutomountServiceAccountToken), nil
	case acct != nil && acct.AutomountServiceAccountToken != nil:
		return model.TriOf(*acct.AutomountServiceAccountToken), nil
	case accountKnown:
		return model.True, []string{model.DefaultAutomountToken}
	}
	return model.Unknown, nil
}

// privileged: any container or init container with securityContext.privileged
// true (unset is false, the documented default).
func privileged(spec *corev1.PodSpec) bool {
	for _, cs := range [][]corev1.Container{spec.InitContainers, spec.Containers} {
		for i := range cs {
			if sc := cs[i].SecurityContext; sc != nil && sc.Privileged != nil && *sc.Privileged {
				return true
			}
		}
	}
	return false
}

// addServiceAccounts adds every declared service account, plus the
// "default" account of each namespace a workload uses implicitly (it is
// created by Kubernetes, so it exists without a manifest).
func (n *norm) addServiceAccounts() {
	for key, sa := range n.accounts {
		s := n.saSource[key]
		n.addSA(sa.Namespace, sa.Name, sa.Annotations, sa.AutomountServiceAccountToken, &s)
	}
	for _, w := range n.workloads {
		key := w.node.Namespace() + "/default"
		if _, declared := n.accounts[key]; w.node.ServiceAccount() == "default" && !declared {
			id := model.NewID(model.KindK8sServiceAcct, model.K8sIdentity(n.cluster, w.node.Namespace(), "ServiceAccount", "default"))
			if !n.b.Has(id) {
				n.addSA(w.node.Namespace(), "default", nil, nil, w.node.Source())
			}
		}
	}
}

func (n *norm) addSA(ns, name string, ann map[string]string, automount *bool, s *model.SourceLocation) {
	var defaulted []string
	audience := ann[annotationAudience]
	if audience == "" {
		audience, defaulted = defaultAudience, append(defaulted, model.DefaultIRSAAudience)
	}
	mount := model.True
	if automount != nil {
		mount = model.TriOf(*automount)
	} else {
		defaulted = append(defaulted, model.DefaultAutomountToken)
	}
	n.b.AddServiceAccount(&model.ServiceAccount{
		ID:      model.NewID(model.KindK8sServiceAcct, model.K8sIdentity(n.cluster, ns, "ServiceAccount", name)),
		Cluster: n.cluster, Namespace: ns, Name: name, RoleARN: ann[annotationRoleARN], Audience: audience,
		AutomountToken: mount, Defaulted: defaulted, Source: *s,
	})
}

func (n *norm) secrets(items []*k8sraw.Object) {
	for _, o := range items {
		if s, ok := o.Obj.(*corev1.Secret); ok {
			n.b.AddResource(model.NewResource(&model.ResourceInput{
				Kind: model.KindK8sSecret, ARN: model.K8sIdentity(n.cluster, o.Namespace, "Secret", o.Name),
				Tags: s.Labels, Source: loc(o),
			}))
		}
	}
}

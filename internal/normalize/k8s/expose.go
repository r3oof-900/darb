package k8s

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/r3oof-900/clapa/internal/collect/k8sraw"
	"github.com/r3oof-900/clapa/internal/coverage"
	"github.com/r3oof-900/clapa/internal/model"
)

// exposures: Services of type LoadBalancer/NodePort, and Ingresses through
// the Services they route to, expose the workloads their selectors match.
func (n *norm) exposures(items []*k8sraw.Object) {
	services := map[string]*corev1.Service{}
	for _, o := range items {
		svc, ok := o.Obj.(*corev1.Service)
		if !ok {
			continue
		}
		services[o.Namespace+"/"+o.Name] = svc
		switch svc.Spec.Type {
		case corev1.ServiceTypeLoadBalancer:
			n.expose(o, svc, "Service/LoadBalancer", lbPublic(svc.Annotations))
		case corev1.ServiceTypeNodePort:
			// Reachability depends on node security groups, which manifests do not show.
			n.expose(o, svc, "Service/NodePort", model.Unknown)
		case corev1.ServiceTypeClusterIP, corev1.ServiceTypeExternalName:
		}
	}
	for _, o := range items {
		if ing, ok := o.Obj.(*networkingv1.Ingress); ok {
			n.ingress(o, ing, services)
		}
	}
}

func (n *norm) expose(o *k8sraw.Object, svc *corev1.Service, via string, public model.Tri) {
	if len(svc.Spec.Selector) == 0 {
		n.gap(coverage.KindUnresolved, o, "service has no selector; its endpoints are not visible in manifests")
		return
	}
	s := loc(o)
	for _, w := range n.workloads {
		if w.node.Namespace() == o.Namespace && selects(svc.Spec.Selector, w.labels) {
			n.b.AddExposure(model.NewNetworkExposure(w.node.ID(), via, public, &s))
		}
	}
}

func selects(selector, labels map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// lbPublic: an explicit scheme annotation decides; the AWS Load Balancer
// Controller ("external"/"nlb-ip" type) defaults to internal; the in-tree
// cloud provider defaults to internet-facing
// (AWS Load Balancer Controller › Service annotations).
func lbPublic(ann map[string]string) model.Tri {
	switch ann["service.beta.kubernetes.io/aws-load-balancer-scheme"] {
	case "internet-facing":
		return model.True
	case "internal":
		return model.False
	}
	if ann["service.beta.kubernetes.io/aws-load-balancer-internal"] == "true" {
		return model.False
	}
	switch ann["service.beta.kubernetes.io/aws-load-balancer-type"] {
	case "external", "nlb-ip":
		return model.False
	}
	return model.True
}

// ingress: the ALB scheme annotation decides; without it the result is
// unknown (the controller and its defaults are not visible in manifests).
func (n *norm) ingress(o *k8sraw.Object, ing *networkingv1.Ingress, services map[string]*corev1.Service) {
	public := model.Unknown
	switch ing.Annotations["alb.ingress.kubernetes.io/scheme"] {
	case "internet-facing":
		public = model.True
	case "internal":
		public = model.False
	}
	for _, name := range backends(ing) {
		svc, ok := services[o.Namespace+"/"+name]
		if !ok {
			n.gap(coverage.KindUnresolved, o, "ingress backend service "+name+" is not in the input")
			continue
		}
		n.expose(o, svc, "Ingress", public)
	}
}

func backends(ing *networkingv1.Ingress) []string {
	var out []string
	if b := ing.Spec.DefaultBackend; b != nil && b.Service != nil {
		out = append(out, b.Service.Name)
	}
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			if p.Backend.Service != nil {
				out = append(out, p.Backend.Service.Name)
			}
		}
	}
	return out
}

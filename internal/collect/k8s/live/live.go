package live

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	"github.com/r3oof-900/darb/internal/collect/k8sraw"
	"github.com/r3oof-900/darb/internal/coverage"
)

// Name identifies this collector in coverage gaps.
const Name = "k8s-live"

// Clients reads one cluster: typed lists, and metadata-only lists for
// Secrets (the API server never sends their data).
type Clients struct {
	Typed    kubernetes.Interface
	Metadata metadata.Interface
	// Insecure: TLS verification is off for this cluster (reported).
	Insecure bool
}

// NewClients makes the clients of cfg.
func NewClients(cfg *rest.Config) (*Clients, error) {
	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	meta, err := metadata.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	return &Clients{Typed: typed, Metadata: meta, Insecure: cfg.Insecure}, nil
}

// Options configure the collection of one cluster.
type Options struct {
	Cluster string
	Clients *Clients
	// PageSize is each list call's Limit; default 500.
	PageSize int64
	// CallTimeout bounds each page; default 30s.
	CallTimeout time.Duration
}

// ErrNothingCollected is returned when not one list succeeded (the cluster is unreachable
// or nothing is allowed); exit code 3, never a clean result.
var ErrNothingCollected = errors.New(Name + ": nothing could be listed")

// Collect lists the cluster's objects, page by page (Limit/Continue). A
// list that fails is a coverage gap and that kind is unknown; only the
// caller cancelling ctx stops the collection. Objects a controller owns
// (the Pods of a ReplicaSet, the ReplicaSets of a Deployment, the Jobs of
// a CronJob) are skipped: their owner's template is analysed, as in a
// manifest scan.
func Collect(ctx context.Context, o *Options, rec *coverage.Recorder) (*k8sraw.Objects, error) {
	c := &collector{o: o, rec: rec, out: &k8sraw.Objects{Cluster: o.Cluster}}
	c.pageSize = cmp.Or(o.PageSize, 500)
	c.timeout = cmp.Or(o.CallTimeout, 30*time.Second)
	for _, k := range kinds() {
		if err := c.listKind(ctx, &k); err != nil {
			return nil, err
		}
	}
	if err := c.secrets(ctx); err != nil {
		return nil, err
	}
	if err := c.awsAuth(ctx); err != nil {
		return nil, err
	}
	if c.listed == 0 {
		return nil, ErrNothingCollected
	}
	c.out.Sort()
	return c.out, nil
}

type collector struct {
	o        *Options
	rec      *coverage.Recorder
	out      *k8sraw.Objects
	pageSize int64
	timeout  time.Duration
	listed   int // successful list operations
}

// page runs one call with the timeout; it returns an error only when the
// caller's ctx is done, and records any other failure as a gap.
func (c *collector) page(ctx context.Context, api string, fn func(context.Context) error) (ok bool, err error) {
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	err = fn(cctx)
	cancel()
	if ctx.Err() != nil {
		return false, fmt.Errorf("%s: %w", Name, ctx.Err())
	}
	if err != nil {
		c.rec.Add(&coverage.Gap{Kind: kindOf(err), Source: Name, Service: "kubernetes", Address: c.o.Cluster, API: api, Detail: err.Error()})
		return false, nil
	}
	return true, nil
}

func kindOf(err error) coverage.Kind {
	switch {
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		return coverage.KindAccessDenied
	case apierrors.IsTooManyRequests(err):
		return coverage.KindThrottled
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err), errors.Is(err, context.DeadlineExceeded):
		return coverage.KindTimeout
	}
	return coverage.KindAPIError
}

// listKind lists every page of one kind. A failure part-way keeps nothing
// of that kind: a partial list would read as "these are all".
func (c *collector) listKind(ctx context.Context, k *kind) error {
	var objs []runtime.Object
	opts := metav1.ListOptions{Limit: c.pageSize}
	for {
		var cont string
		ok, err := c.page(ctx, "list "+k.resource, func(ctx context.Context) error {
			items, next, lerr := k.list(ctx, c.o.Clients, opts)
			objs, cont = append(objs, items...), next
			return lerr
		})
		if err != nil || !ok {
			return err
		}
		if cont == "" {
			break
		}
		opts.Continue = cont
	}
	c.listed++
	for _, obj := range objs {
		c.add(k.gvk, obj)
	}
	return nil
}

// ownerKinds: controllers whose template darb analyses.
func ownerKinds() []string {
	return []string{"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob"}
}

func (c *collector) add(gvk schema.GroupVersionKind, obj runtime.Object) {
	m, ok := obj.(metav1.Object)
	if !ok {
		return
	}
	if owner := metav1.GetControllerOf(m); owner != nil && contains(ownerKinds(), owner.Kind) {
		return
	}
	m.SetManagedFields(nil)
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	c.out.Items = append(c.out.Items, &k8sraw.Object{
		APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind, Namespace: m.GetNamespace(), Name: m.GetName(), Obj: obj,
	})
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// secrets lists Secrets as metadata only (PartialObjectMetadataList): the
// API server returns names, namespaces, labels and annotations, never data.
func (c *collector) secrets(ctx context.Context) error {
	var items []metav1.PartialObjectMetadata
	opts := metav1.ListOptions{Limit: c.pageSize}
	res := c.o.Clients.Metadata.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"})
	for {
		var cont string
		ok, err := c.page(ctx, "list secrets (metadata)", func(ctx context.Context) error {
			l, lerr := res.List(ctx, opts)
			if lerr == nil {
				items, cont = append(items, l.Items...), l.Continue
			}
			return lerr
		})
		if err != nil || !ok {
			return err
		}
		if cont == "" {
			break
		}
		opts.Continue = cont
	}
	c.listed++
	for i := range items {
		meta := items[i].ObjectMeta
		meta.ManagedFields = nil
		c.add(gvk("", "v1", "Secret"), &corev1.Secret{ObjectMeta: meta})
	}
	return nil
}

// awsAuth reads the kube-system/aws-auth ConfigMap (EKS IAM mappings), the
// one ConfigMap darb analyses; a cluster without it is not an error.
func (c *collector) awsAuth(ctx context.Context) error {
	var cm *corev1.ConfigMap
	notFound := false
	ok, err := c.page(ctx, "get configmaps kube-system/aws-auth", func(ctx context.Context) error {
		got, gerr := c.o.Clients.Typed.CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", metav1.GetOptions{})
		if apierrors.IsNotFound(gerr) {
			notFound = true
			return nil
		}
		cm = got
		return gerr
	})
	if err != nil || !ok || notFound {
		return err
	}
	c.listed++
	c.add(gvk("", "v1", "ConfigMap"), cm)
	return nil
}

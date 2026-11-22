package graph

// Ways a Kubernetes Secret is read without an RBAC read of it
// (CAN_READ_PLAINTEXT[...], DESIGN.md 7.2): a pod is given the Secrets its
// spec names (mount), and whoever may create pods in a namespace can create
// one that names any of its Secrets (pod-create).
const (
	SubMount     = "mount"
	SubPodCreate = "pod-create"
)

// Package live lists objects from a live cluster with client-go (docs/DESIGN.md
// 4.5): paginated lists, Secrets as metadata only, TLS verified, no exec
// plugins, an in-memory EKS token. A failed list is a coverage gap.
package live

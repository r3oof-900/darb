package redact

import (
	"context"
	"log/slog"
	"strings"
)

// Handler redacts what a slog.Handler writes: the message and every string
// attribute pass Redact, and an attribute whose key names a secret
// (password, secret, token, API key, authorization, credential) is replaced
// whole, whatever its value.
type Handler struct{ next slog.Handler }

// NewHandler wraps next.
func NewHandler(next slog.Handler) *Handler { return &Handler{next: next} }

// Enabled reports whether next handles the level.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

// Handle redacts the record, then passes it on.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error { //nolint:gocritic // hugeParam: slog.Handler's signature
	out := slog.NewRecord(r.Time, r.Level, Redact(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(attr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

// WithAttrs redacts the attributes first.
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(as))
	for i, a := range as {
		red[i] = attr(a)
	}
	return &Handler{next: h.next.WithAttrs(red)}
}

// WithGroup keeps redacting inside the group.
func (h *Handler) WithGroup(name string) slog.Handler { return &Handler{next: h.next.WithGroup(name)} }

var secretKeys = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "api-key", "authorization", "credential", "private_key", "privatekey"}

func attr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	key := strings.ToLower(a.Key)
	for _, k := range secretKeys {
		if strings.Contains(key, k) {
			return slog.String(a.Key, "[REDACTED:"+k+"]")
		}
	}
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, Redact(v.String()))
	case slog.KindGroup:
		group := v.Group()
		red := make([]any, len(group))
		for i, g := range group {
			red[i] = attr(g)
		}
		return slog.Group(a.Key, red...)
	case slog.KindAny:
		return slog.String(a.Key, Redact(v.String()))
	case slog.KindBool, slog.KindDuration, slog.KindFloat64, slog.KindInt64, slog.KindTime, slog.KindUint64, slog.KindLogValuer:
	}
	return slog.Attr{Key: a.Key, Value: v}
}

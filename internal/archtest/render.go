package archtest

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Region names shared by the generator (tools/archgen) and the drift tests.
const (
	RegionDepguard  = "depguard"
	RegionCorePaths = "core-paths"
	RegionLayerDoc  = "layer-table"
)

// ErrRegion is returned when a generated region's markers are missing or malformed.
var ErrRegion = errors.New("archtest: generated region")

// ReplaceRegion replaces the lines between the "BEGIN GENERATED: name" and
// "END GENERATED: name" marker lines of text with body. Markers are kept.
func ReplaceRegion(text, name, body string) (string, error) {
	lines := strings.SplitAfter(text, "\n")
	begin, end, err := regionBounds(lines, name)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, l := range lines[:begin+1] {
		b.WriteString(l)
	}
	b.WriteString(body)
	for _, l := range lines[end:] {
		b.WriteString(l)
	}
	return b.String(), nil
}

// ExtractRegion returns the lines between the markers of region name.
func ExtractRegion(text, name string) (string, error) {
	lines := strings.SplitAfter(text, "\n")
	begin, end, err := regionBounds(lines, name)
	if err != nil {
		return "", err
	}
	return strings.Join(lines[begin+1:end], ""), nil
}

func regionBounds(lines []string, name string) (begin, end int, err error) {
	begin, end = -1, -1
	for i, l := range lines {
		switch {
		case strings.Contains(l, "BEGIN GENERATED: "+name+" "):
			begin = i
		case strings.Contains(l, "END GENERATED: "+name) && begin >= 0:
			end = i
		}
		if end >= 0 {
			break
		}
	}
	if begin < 0 || end < 0 {
		return 0, 0, fmt.Errorf("%w %q: markers not found", ErrRegion, name)
	}
	return begin, end, nil
}

// RenderDepguard renders depguard rules (golangci-lint v2 syntax), indented
// for linters.settings.depguard.rules. Only non-test files are covered:
// archtest is authoritative for test files.
func RenderDepguard(rules []*Rule) string {
	var b strings.Builder
	for _, r := range sortedRules(rules) {
		fmt.Fprintf(&b, "        %s:\n", strings.ReplaceAll(r.Package, "/", "-"))
		b.WriteString("          list-mode: strict\n")
		b.WriteString("          files:\n")
		fmt.Fprintf(&b, "            - \"**/%s/*.go\"\n", r.Package)
		b.WriteString("            - \"!$test\"\n")
		b.WriteString("          allow:\n")
		b.WriteString("            - \"$gostd\"\n")
		for _, a := range depguardAllow(r) {
			fmt.Fprintf(&b, "            - %q\n", a)
		}
		deny := depguardDeny(r)
		if len(deny) > 0 {
			b.WriteString("          deny:\n")
		}
		for _, d := range deny {
			fmt.Fprintf(&b, "            - pkg: %q\n", d)
			fmt.Fprintf(&b, "              desc: \"forbidden in the %s layer (docs/DESIGN.md section 3)\"\n", r.Layer)
		}
	}
	return b.String()
}

func depguardAllow(r *Rule) []string {
	var out []string
	for _, in := range r.Internal {
		if base, ok := strings.CutSuffix(in, "/..."); ok {
			out = append(out, ModulePath+"/"+base+"$", ModulePath+"/"+base+"/")
		} else {
			out = append(out, ModulePath+"/"+in+"$")
		}
	}
	for _, ext := range r.External {
		out = append(out, ext+"$", ext+"/")
	}
	for _, s := range r.ExtraStd {
		out = append(out, s+"$")
	}
	return out
}

// depguardDeny lists the denied std prefixes. depguard lets a deny prefix win
// over a more specific allow, so when an ExtraStd package lies below a
// denied prefix (net/netip below net), the prefix is replaced by its exact
// form and its other known subpackages; archtest applies the same rule
// natively (ExtraStd is checked before the denials).
func depguardDeny(r *Rule) []string {
	var out []string
	for _, d := range DeniedStd(r.Layer) {
		if d == "C" || slices.Contains(r.ExtraStd, d) {
			continue // cgo is not an import depguard sees; ExtraStd overrides.
		}
		if !shadowsExtra(d, r.ExtraStd) {
			out = append(out, d)
			continue
		}
		out = append(out, d+"$")
		for _, sub := range stdSubpackages(d) {
			if !slices.Contains(r.ExtraStd, sub) {
				out = append(out, sub)
			}
		}
	}
	return out
}

func shadowsExtra(prefix string, extra []string) bool {
	for _, e := range extra {
		if strings.HasPrefix(e, prefix+"/") {
			return true
		}
	}
	return false
}

// stdSubpackages lists the direct std subpackages of the prefixes that an
// ExtraStd entry can sit below. TestStdSubpackagesComplete keeps it honest.
func stdSubpackages(prefix string) []string {
	if prefix == "net" {
		return []string{"net/http", "net/mail", "net/netip", "net/rpc", "net/smtp", "net/textproto", "net/url"}
	}
	return nil
}

// RenderCorePaths renders golangci-lint exclusion rules that scope
// gochecknoglobals and the time.Now ban to core packages, indented for
// linters.exclusions.rules.
func RenderCorePaths(rules []*Rule) string {
	var core []string
	for _, r := range sortedRules(rules) {
		if r.Layer == LayerCore {
			core = append(core, r.Package)
		}
	}
	re := "^(" + strings.Join(core, "|") + ")/[^/]+\\.go$"
	var b strings.Builder
	fmt.Fprintf(&b, "      - path-except: '%s'\n", re)
	b.WriteString("        linters:\n          - gochecknoglobals\n")
	fmt.Fprintf(&b, "      - path-except: '%s'\n", re)
	b.WriteString("        linters:\n          - forbidigo\n")
	b.WriteString("        text: 'time\\.Now'\n")
	return b.String()
}

// RenderLayerDoc renders the Markdown dependency table for docs/DESIGN.md.
func RenderLayerDoc(rules []*Rule) string {
	var b strings.Builder
	b.WriteString("| Package | Layer | May import (module) | May import (external) | Extra std / test-only |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, r := range sortedRules(rules) {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
			r.Package, r.Layer, codeList(r.Internal, "— (leaf)"), codeList(r.External, "—"), extras(r))
	}
	b.WriteString("\nStandard-library packages denied in non-test files, by layer (an entry also denies its subpackages):\n\n")
	b.WriteString("| Layer | Denied std packages |\n|---|---|\n")
	for _, l := range []Layer{LayerCore, LayerPure, LayerIO, LayerEntry, LayerTooling} {
		fmt.Fprintf(&b, "| %s | %s |\n", l, codeList(DeniedStd(l), "—"))
	}
	return b.String()
}

func extras(r *Rule) string {
	var parts []string
	if len(r.ExtraStd) > 0 {
		parts = append(parts, "std: "+codeList(r.ExtraStd, ""))
	}
	if len(r.TestInternal) > 0 {
		parts = append(parts, "tests: "+codeList(r.TestInternal, ""))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "; ")
}

func codeList(items []string, empty string) string {
	if len(items) == 0 {
		return empty
	}
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = "`" + it + "`"
	}
	return strings.Join(quoted, ", ")
}

func sortedRules(rules []*Rule) []*Rule {
	out := slices.Clone(rules)
	slices.SortFunc(out, func(a, b *Rule) int { return strings.Compare(a.Package, b.Package) })
	return out
}

package version

// Set by the linker. Defaults identify an unreleased development build.
var (
	version = "dev"
	commit  = "unknown"
)

// Info describes the running build.
type Info struct {
	Version string
	Commit  string
}

// Get returns the build information.
func Get() Info {
	return Info{Version: version, Commit: commit}
}

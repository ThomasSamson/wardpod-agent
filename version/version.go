// Package version porte la version du binaire, injectée au build :
//
//	go build -ldflags "-X github.com/ThomasSamson/wardpod-agent/version.Version=1.2.3 -X github.com/ThomasSamson/wardpod-agent/version.Commit=abc123"
package version

var (
	Version = "dev"
	Commit  = ""
)

// String renvoie la version et, si elle est connue, la révision.
func String() string {
	if Commit == "" {
		return Version
	}
	return Version + " (" + Commit + ")"
}

// UserAgent identifie wardpod auprès des API et des sources.
func UserAgent() string { return "wardpod/" + Version }

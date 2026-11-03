// Package version holds the build version, stamped at link time:
//
//	go build -ldflags "-X github.com/tm1000/birdscale/internal/version.Version=1.2.3"
package version

// Version is the birdscale version; "dev" for an unstamped build.
var Version = "dev"

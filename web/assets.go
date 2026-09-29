// Package web bundles the locally built viewer. No Node runtime is required.
package web

import "embed"

//go:embed dist
var Assets embed.FS

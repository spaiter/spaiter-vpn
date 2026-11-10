//go:build tools

// Package tools keeps the core's main package, and so everything its command
// line imports (cobra, the build helpers' dependencies), in this module's
// dependency graph. The core is built from here, through the replace directive,
// so go.sum has to cover it; the version pins that matter (security fixes) are
// then decided in one place, this go.mod.
package tools

import _ "github.com/sagernet/sing-box/cmd/sing-box"

// Package config serialises a generated sing-box configuration and writes it
// to disk.
package config

import (
	"bytes"
	"context"
	stdjson "encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sagernet/sing/common/json"
	"github.com/spaiter/spaiter-vpn/core/include"
	"github.com/spaiter/spaiter-vpn/core/option"
)

// Marshal renders the options as indented JSON.
//
// The context is required rather than incidental: most of the fork's option
// types marshal through MarshalJSONContext, and several — the inbound,
// endpoint and service wrappers — flatten their protocol-specific options into
// the same JSON object through it. Marshalling with encoding/json directly
// would silently emit only the type and tag.
func Marshal(ctx context.Context, options option.Options) ([]byte, error) {
	raw, err := json.MarshalContext(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	var pretty bytes.Buffer
	if err := stdjson.Indent(&pretty, raw, "", "  "); err != nil {
		return nil, fmt.Errorf("indent config: %w", err)
	}
	pretty.WriteByte('\n')
	return pretty.Bytes(), nil
}

// Write writes data to path atomically, with the given permissions.
//
// Atomicity matters for the config specifically: sing-box rewrites this file
// itself through config_output_path whenever a peer or user changes, so a
// half-written file is a file the running service may read.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	// Sync before the rename: a crash between the two would otherwise leave a
	// correctly named file with no contents.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// Unmarshal parses a sing-box configuration.
//
// The inverse of Marshal, and it needs the context for the same reason: the
// inbound, endpoint and service wrappers decode their protocol-specific
// options through UnmarshalJSONContext, so plain encoding/json yields objects
// with a type and a tag and nothing else — which looks like a successful parse
// right up to the moment something reads a field.
//
// It exists so a live deployment's own config can be read back as the typed
// options it was rendered from. That is what lets a migration recover the
// credentials of every user the server actually has, rather than only the ones
// the installer happened to create.
func Unmarshal(ctx context.Context, data []byte) (option.Options, error) {
	ctx = include.Context(ctx)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		return option.Options{}, fmt.Errorf("parse config: %w", err)
	}
	return options, nil
}

package clashapi

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type ConfigManager struct {
	mu       sync.Mutex
	ctx      context.Context
	filePath string

	// applied is the config as it was last pushed into the running instance.
	// ModifyConfig only rewrites the file, so without this snapshot there is
	// no way to tell which tags a later apply actually has to touch. It is
	// captured at construction — i.e. while the file still matches what the
	// instance was built from — because by the time anything calls apply the
	// file has already been edited. //H
	appliedMu  sync.Mutex
	applied    option.Options
	hasApplied bool
}

func NewConfigManager(ctx context.Context, filePath string) *ConfigManager {
	m := &ConfigManager{
		ctx:      ctx,
		filePath: filePath,
	}
	if options, err := m.ReadConfig(); err == nil {
		m.applied = options
		m.hasApplied = true
	}
	return m
}

// Applied returns the config last pushed into the running instance. //H
func (m *ConfigManager) Applied() (option.Options, error) {
	m.appliedMu.Lock()
	defer m.appliedMu.Unlock()
	if !m.hasApplied {
		// Construction-time read failed (unreadable or invalid file); the file
		// as it stands now is the best available baseline.
		options, err := m.ReadConfig()
		if err != nil {
			return option.Options{}, err
		}
		m.applied = options
		m.hasApplied = true
	}
	return m.applied, nil
}

// SetApplied records the config now live in the instance. //H
func (m *ConfigManager) SetApplied(options option.Options) {
	m.appliedMu.Lock()
	defer m.appliedMu.Unlock()
	m.applied = options
	m.hasApplied = true
}

func (m *ConfigManager) ReadConfig() (option.Options, error) {
	content, err := os.ReadFile(m.filePath)
	if err != nil {
		return option.Options{}, E.Cause(err, "read config file")
	}
	options, err := json.UnmarshalExtendedContext[option.Options](m.ctx, content)
	if err != nil {
		return option.Options{}, E.Cause(err, "decode config")
	}
	return options, nil
}

func (m *ConfigManager) WriteConfig(options option.Options) error {
	cleaned, err := badjson.Omitempty(m.ctx, options)
	if err != nil {
		return E.Cause(err, "clean config")
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoderContext(m.ctx, &buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(cleaned)
	if err != nil {
		return E.Cause(err, "encode config")
	}
	dir := filepath.Dir(m.filePath)
	tmpFile, err := os.CreateTemp(dir, ".sing-box-config-*.tmp")
	if err != nil {
		return E.Cause(err, "create temp file")
	}
	tmpPath := tmpFile.Name()
	_, err = tmpFile.Write(buffer.Bytes())
	if closeErr := tmpFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmpPath)
		return E.Cause(err, "write temp file")
	}
	err = os.Rename(tmpPath, m.filePath)
	if err != nil {
		os.Remove(tmpPath)
		return E.Cause(err, "rename config file")
	}
	return nil
}

func (m *ConfigManager) ModifyConfig(modifier func(option.Options) (option.Options, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	options, err := m.ReadConfig()
	if err != nil {
		return err
	}
	options, err = modifier(options)
	if err != nil {
		return err
	}
	return m.WriteConfig(options)
}

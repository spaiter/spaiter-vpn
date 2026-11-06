package manage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Credentials are exactly what a management client needs: where the API is
// and its bearer secret. Bootstrap writes them to a file of their own so the
// bot can reach the core without being able to read the core's configuration,
// which holds every private key of the deployment.
type Credentials struct {
	Controller string `json:"controller"`
	Secret     string `json:"secret"`
}

// CredentialsFromCoreConfig extracts the credentials from a core config.
func CredentialsFromCoreConfig(data []byte) (Credentials, error) {
	var parsed clashAPI
	if err := json.Unmarshal(data, &parsed); err != nil {
		return Credentials{}, fmt.Errorf("parse core config: %w", err)
	}
	controller := parsed.Experimental.ClashAPI.ExternalController
	if controller == "" || parsed.Experimental.ClashAPI.Secret == "" {
		return Credentials{}, fmt.Errorf("the core config has no clash API controller or secret")
	}
	if strings.HasPrefix(controller, ":") {
		controller = "127.0.0.1" + controller
	}
	return Credentials{Controller: controller, Secret: parsed.Experimental.ClashAPI.Secret}, nil
}

// NewFromCredentialsFile builds a client from a credentials file.
func NewFromCredentialsFile(path string) (*Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read management credentials %s: %w", path, err)
	}
	var credentials Credentials
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return nil, fmt.Errorf("parse management credentials %s: %w", path, err)
	}
	if credentials.Controller == "" || credentials.Secret == "" {
		return nil, fmt.Errorf("%s names no controller or secret", path)
	}
	return New(credentials.Controller, credentials.Secret)
}

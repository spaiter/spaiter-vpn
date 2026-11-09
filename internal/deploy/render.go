package deploy

import "os"

const (
	ComposeFileName = "docker-compose.yml"
	EnvFileName     = ".env"
)

// Artifact is one host file rendered for a deployment. Name is deliberately a
// basename rather than an arbitrary path: the caller chooses a validated
// deployment directory and its own safe write policy.
type Artifact struct {
	Name string
	Data []byte
	Mode os.FileMode
}

// Artifacts is the complete set of non-secret deployment files. Config and
// credentials come from profile.Render; these files are deterministic around
// that generated core.
type Artifacts struct {
	Compose     Artifact
	Environment Artifact
	Logrotate   Artifact
	ReloadAgent *Artifact
	BotConfig   *Artifact
}

// Render produces every deployment artifact without touching the host.
func Render(params Params) (Artifacts, error) {
	result := Artifacts{
		Compose: Artifact{
			Name: ComposeFileName,
			Data: []byte(params.Compose()),
			Mode: 0o644,
		},
		Environment: Artifact{
			Name: EnvFileName,
			Data: []byte(params.Env()),
			Mode: 0o644,
		},
		Logrotate: Artifact{
			Name: LogrotateFileName,
			Data: []byte(params.Logrotate()),
			Mode: 0o644,
		},
	}
	if params.Reload.Enabled {
		result.ReloadAgent = &Artifact{
			Name: ReloadAgentScriptName,
			Data: []byte(params.Reload.Script()),
			Mode: 0o755,
		}
	}
	if params.Bot.Enabled {
		data, err := params.Bot.ConfigJSON(params)
		if err != nil {
			return Artifacts{}, err
		}
		result.BotConfig = &Artifact{
			Name: BotConfigFileName,
			Data: data,
			Mode: 0o644,
		}
	}
	return result, nil
}

// Files returns the present artifacts in stable write order.
func (a Artifacts) Files() []Artifact {
	files := []Artifact{a.Compose, a.Environment, a.Logrotate}
	if a.ReloadAgent != nil {
		files = append(files, *a.ReloadAgent)
	}
	if a.BotConfig != nil {
		files = append(files, *a.BotConfig)
	}
	return files
}

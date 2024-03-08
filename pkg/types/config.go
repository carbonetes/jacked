package types

const ConfigVersion string = "1.0"

type Configuration struct {
	Version     string          `yaml:"version"`
	MaxFileSize int64           `yaml:"maxFileSize"`
	Registry    Registry        `yaml:"registry"`
	CI          CIConfiguration `yaml:"ci"`
}

type Registry struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type CIConfiguration struct {
	FailCriteria FailCriteria `yaml:"failCriteria"`
}

// TODO: Add more logic to handle multiple fail criteria
type FailCriteria struct {
	// TODO: Add logic to handle multiple vulnerability id as fail criteria
	Vulnerabilities []string `yaml:"vulnerability"`

	Severity string `yaml:"severity"`
}

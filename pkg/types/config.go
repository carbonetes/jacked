package types

const ConfigVersion string = "1.1"

type Configuration struct {
	Version     string          `yaml:"version"`
	Ignore      Ignore          `yaml:"ignore"`
	MaxFileSize int64           `yaml:"maxFileSize"`
	Registry    Registry        `yaml:"registry"`
	CI          CIConfiguration `yaml:"ci"`
}

type Ignore struct {
	Package Package `yaml:"package"`
}

type Registry struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Package struct {
	Name    []string `yaml:"name"`
	Type    []string `yaml:"type"`
	Version []string `yaml:"version"`
}

type CIConfiguration struct {
	FailCriteria FailCriteria `yaml:"failCriteria"`
}

type FailCriteria struct {
	Vulnerability string   `yaml:"vulnerability"`
	Package       string   `yaml:"package"`
	Severity      []string `yaml:"severity"`
}

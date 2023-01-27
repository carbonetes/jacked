package model

type Secret struct {
	ContentRegexName string `json:"contentRegexName"`
	FileName         string `json:"fileName"`
	FilePath         string `json:"filePath"`
	LineNumber       string `json:"lineNumber"`
}

type SecretConfig struct {
	Disabled    bool      `yaml:"disabled" json:"disabled"`
	SecretRegex string    `yaml:"secret-regex" json:"secretRegex"`
	Excludes    *[]string `yaml:"excludes" json:"excludes"`
	MaxFileSize int64     `yaml:"max-file-size" json:"maxFileSize"`
}

type SecretResults struct {
	Configuration SecretConfig `json:"applied-configuration"`
	Secrets       []Secret     `json:"secrets"`
}
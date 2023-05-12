package model

func NewArguments() *Arguments {
	return &Arguments{
		Image:               new(string),
		SbomFile:            new(string),
		Output:              new(string),
		Quiet:               new(bool),
		OutputFile:          new(string),
		EnabledParsers:      &[]string{},
		DisableFileListing:  new(bool),
		SecretContentRegex:  new(string),
		DisableSecretSearch: new(bool),
		RegistryURI:         new(string),
		RegistryUsername:    new(string),
		RegistryPassword:    new(string),
		RegistryToken:       new(string),
		Dir:                 new(string),
		Tar:                 new(string),
		ExcludedFilenames:   &[]string{},
		FailCriteria:        new(string),
		SkipDbUpdate:        new(bool),
	}
}

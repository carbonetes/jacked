package model

type Arguments struct {
	Image               *string
	SbomFile            *string
	Output              *string
	Quiet               *bool
	OutputFile          *string
	EnabledParsers      *[]string
	DisableFileListing  *bool
	SecretContentRegex  *string
	DisableSecretSearch *bool
	SecretMaxFileSize   int64
	RegistryURI         *string
	RegistryUsername    *string
	RegistryPassword    *string
	RegistryToken       *string
	Dir                 *string
	Tar                 *string
	ExcludedFilenames   *[]string
}

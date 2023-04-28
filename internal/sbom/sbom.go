package sbom

import (
	"strings"

	dm "github.com/carbonetes/diggity/pkg/model"
	diggity "github.com/carbonetes/diggity/pkg/scanner"
	"github.com/carbonetes/jacked/pkg/core/model"
)

func Scan(arguments *model.Arguments) *dm.Result {
	return diggity.Scan(parseArgs(arguments))
}

func parseArgs(arguments *model.Arguments) *dm.Arguments {
	args := dm.NewArguments()
	args.Dir = arguments.Dir
	args.DisableFileListing = arguments.DisableFileListing
	args.DisableSecretSearch = arguments.DisableSecretSearch
	args.EnabledParsers = split(arguments.EnabledParsers)
	args.ExcludedFilenames = arguments.ExcludedFilenames
	args.Image = arguments.Image
	args.RegistryURI = arguments.RegistryURI
	args.RegistryPassword = arguments.RegistryPassword
	args.RegistryToken = arguments.RegistryToken
	args.RegistryUsername = arguments.RegistryUsername
	args.Tar = arguments.Tar
	args.SecretMaxFileSize = int64(arguments.SecretMaxFileSize)
	args.SecretContentRegex = arguments.SecretContentRegex
	args.Provenance = new(string)
	args.DisablePullTimeout = new(bool)
	return args
}

func split(args *[]string) *[]string {
	result := new([]string)
	for _, arg := range *args {
		if !strings.Contains(arg, ",") {
			*result = append(*result, arg)
			continue
		}
		*result = append(*result, strings.Split(arg, ",")...)
	}
	return result
}

package sbom

import (
	dm "github.com/carbonetes/diggity/pkg/model"
	diggity "github.com/carbonetes/diggity/pkg/scanner"
	"github.com/carbonetes/jacked/internal/logger"
	"github.com/carbonetes/jacked/internal/ui/spinner"
	"github.com/carbonetes/jacked/pkg/core/model"
)

var log = logger.GetLogger()

func Scan(arguments *model.Arguments) *dm.SBOM {
	if len(*arguments.Image) > 0 {
		spinner.OnSBOMScan(*arguments.Image)
	} else if len(*arguments.Dir) > 0 {
		spinner.OnSBOMScan(*arguments.Dir)
	} else if len(*arguments.Tar) > 0 {
		spinner.OnSBOMScan(*arguments.Tar)
	}

	sbom, _ := diggity.Scan(parseArgs(arguments))
	spinner.OnStop(nil)
	return sbom
}

func parseArgs(arguments *model.Arguments) *dm.Arguments {
	args := dm.NewArguments()
	args.Image = arguments.Image
	args.Dir = arguments.Dir
	args.Tar = arguments.Tar

	args.DisableFileListing = arguments.DisableFileListing
	args.ExcludedFilenames = arguments.ExcludedFilenames
	args.EnabledParsers = arguments.EnabledParsers

	args.DisableSecretSearch = arguments.DisableSecretSearch
	args.SecretContentRegex = arguments.SecretContentRegex
	args.SecretMaxFileSize = arguments.SecretMaxFileSize

	args.RegistryUsername = arguments.RegistryUsername
	args.RegistryPassword = arguments.RegistryPassword
	args.RegistryToken = arguments.RegistryToken
	args.RegistryURI = arguments.RegistryURI

	return args
}

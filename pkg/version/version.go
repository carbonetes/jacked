package version

import "errors"

// Errors for version and constraint parsing
var (
	// ErrInvalidVersionFormat indicates that the version is malformed.
	ErrInvalidVersionFormat = errors.New("invalid version format")
	// ErrInvalidConstraintFormat indicates that the version in constraint is malformed.
	ErrInvalidConstraintFormat = errors.New("invalid constraint format")
	// ErrInvalidConstraintOperator indicates that the operator in constraint is not supported.
	ErrInvalidConstraintOperator = errors.New("invalid constraint operator, only '==', '!=', '<', '<=', '>', '>=' are supported")
	// NoConstraintError indicates that no constraint was provided.
	NoConstraintError = errors.New("no constraint provided, at least one constraint is required")
	// NoVersionError indicates that no version was provided.
	NoVersionError = errors.New("no version provided, at least one version is required")
	// InvalidConstraintError indicates that the constraint is invalid.
	InvalidConstraintError = errors.New("invalid constraint, must be in the format 'operator version' where operator is one of '==', '!=', '<', '<=', '>', '>=' and version is a valid version string")
	errCheckFormat         = "error checking version %v against constraint %v: %v"
)

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
	// ErrNoConstraint indicates that no constraint was provided.
	ErrNoConstraint = errors.New("no constraint provided, at least one constraint is required")
	// ErrNoVersion indicates that no version was provided.
	ErrNoVersion = errors.New("no version provided, at least one version is required")
	// ErrInvalidConstraint indicates that the constraint is invalid.
	ErrInvalidConstraint = errors.New("invalid constraint, must be in the format 'operator version' where operator is one of '==', '!=', '<', '<=', '>', '>=' and version is a valid version string")
	errCheckFormat       = "error checking version %v against constraint %v: %v"
)

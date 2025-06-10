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
)

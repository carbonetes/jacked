package base

import (
	"github.com/carbonetes/jacked/pkg/version"
	hashicorp "github.com/hashicorp/go-version"
)

// SemanticVersionWrapper wraps hashicorp Version to implement VersionChecker
type SemanticVersionWrapper struct {
	version *hashicorp.Version
}

// NewSemanticVersionWrapper creates a wrapper for semantic versions
func NewSemanticVersionWrapper(versionStr string) (*SemanticVersionWrapper, error) {
	v, err := version.NewSemanticVersion(versionStr)
	if err != nil {
		return nil, err
	}
	return &SemanticVersionWrapper{version: v}, nil
}

// Check implements VersionChecker interface using hashicorp constraints
func (w *SemanticVersionWrapper) Check(constraintStr string) (bool, error) {
	constraint, err := hashicorp.NewConstraint(constraintStr)
	if err != nil {
		return false, err
	}
	return constraint.Check(w.version), nil
}

package types

import (
	"strings"

	diggity "github.com/carbonetes/diggity/pkg/types"
)

type ScanType int
type Format string

const (
	JSON         Format = "json"
	Table        Format = "table"
	SPDXJSON     Format = "spdx-json"
	SPDXXML      Format = "spdx-xml"
	SPDXTag      Format = "spdx-tag"
	SnapshotJSON Format = "snapshot-json"
)

type Parameters struct {
	Quiet         bool
	Format        Format
	File          string
	CI            bool
	Token         string
	Plugin        string
	SkipDBUpdate  bool
	ForceDBUpdate bool

	// Diggity tool parameters to be passed to the scan engine
	Diggity diggity.Parameters
}

func (o Format) String() string {
	return string(o)
}

func GetAllOutputFormat() string {
	return strings.Join([]string{JSON.String(), Table.String(), SPDXJSON.String(), SPDXXML.String(), SPDXTag.String(), SnapshotJSON.String()}, ", ")
}

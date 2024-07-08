package compare

import (
	"sync"

	"github.com/CycloneDX/cyclonedx-go"
)

var lock = &sync.Mutex{}


// addVex will append the incoming vulnerabilities from all comparer. 
// Mutex is used to prevent cases where multiple goroutines are trying to append to the same slice.
func addVex(vex *[]cyclonedx.Vulnerability, incoming *[]cyclonedx.Vulnerability) *[]cyclonedx.Vulnerability {
	lock.Lock()
	defer lock.Unlock()

	if len(*incoming) == 0 {
		return vex
	}

	*vex = append(*vex, *incoming...)
	return vex
}

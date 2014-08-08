package storage

import (
	"testing"

	"github.com/rafrombrc/gospec/src/gospec"
)

func TestAllSpecs(t *testing.T) {
	r := gospec.NewRunner()
	r.Parallel = false

	r.AddSpec(RcsSpec)

	gospec.MainGoTest(r, t)
}

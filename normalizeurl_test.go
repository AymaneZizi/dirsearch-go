package dirsearch

import (
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	const normalized = "https://github.com/"
	tt := []struct {
		name string
		in   string
	}{
		{"normalized URL", "https://github.com/"},
		{"no schema URL", "github.com/"},
		{"no trailing slash URL", "https://github.com"},
		{"no schema and no trailing slash URL", "github.com"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeURL(tc.in)
			if err != nil {
				t.Fatalf("having %s got %s want %s", tc.in, got, normalized)
			}
		})
	}
}

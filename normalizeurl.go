package dirsearch

import (
	"errors"
	"fmt"
	"strings"
)

// NormalizeURL takes any domain or URL as input and normalizes
// it adding (if needed) default schema and path.
func NormalizeURL(u string) (string, error) {
	if u == "" {
		return "", errors.New("empty URL")
	}

	// add schema
	if !strings.Contains(u, "://") {
		u = fmt.Sprintf("http://%s", u)
	}

	// add path
	if !strings.HasSuffix(u, "/") {
		u = fmt.Sprintf("%s/", u)
	}

	return u, nil
}

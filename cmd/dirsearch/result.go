package main

import (
	"fmt"
	"net/http"
	"os"
)

// Result is a bruteforced result.
type Result struct {
	url      string
	status   int
	size     int64
	location string
	err      error
}

// Print prints useful information of a result.
func (r Result) Print() {
	switch {
	case r.status == http.StatusNotFound:
		return

	case r.err != nil:
		fmt.Fprintf(os.Stderr, "%s : %v\n", r.url, r.err)

	case r.status >= 200 && r.status < 300:
		fmt.Printf("%-3d %-9d %s\n", r.status, r.size, r.url)

	case r.status >= 300 && r.status < 400:
		fmt.Printf("%-3d %-9d %s -> %s\n", r.status, r.size, r.url, r.location)

	case r.status >= 400 && r.status < 500:
		fmt.Printf("%-3d %-9d %s\n", r.status, r.size, r.url)

	case r.status >= 500 && r.status < 600:
		fmt.Printf("%-3d %-9d %s\n", r.status, r.size, r.url)
	}
}

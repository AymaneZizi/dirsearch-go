package main

import (
	"net/http"
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
func (res Result) Print() {
	switch {
	case res.status == http.StatusNotFound && !*verbose:
		return

	case res.err != nil:
		return

	case res.status < 200:
		y.Printf("%-3d %-9d %s\n", res.status, res.size, res.url)

	case res.status >= 400 && res.status < 500:
		r.Printf("%-3d %-9d %s\n", res.status, res.size, res.url)

	case res.status >= 300 && res.status < 400:
		b.Printf("%-3d %-9d %s -> %s\n", res.status, res.size, res.url, res.location)

	case res.status >= 200 && res.status < 300:
		g.Printf("%-3d %-9d %s\n", res.status, res.size, res.url)

	case res.status >= 500:
		n.Printf("%-3d %-9d %s\n", res.status, res.size, res.url)
	}
}

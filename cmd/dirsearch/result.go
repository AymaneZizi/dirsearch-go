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
		fmt.Fprintf(os.Stderr, "%s%s : %v%s\n", FgRed, r.url, r.err, Reset)

	case r.status >= 200 && r.status < 300:
		fmt.Printf("%s%-3d %-9d %s%s\n", FgGreen, r.status, r.size, r.url, Reset)

	case r.status >= 300 && r.status < 400:
		fmt.Printf("%s%-3d %-9d %s -> %s%s\n", FgBlue, r.status, r.size, r.url, r.location, Reset)

	case r.status >= 400 && r.status < 500:
		fmt.Printf("%s%-3d %-9d %s%s\n", FgYellow, r.status, r.size, r.url, Reset)

	case r.status >= 500 && r.status < 600:
		fmt.Printf("%s%-3d %-9d %s%s\n", FgRed, r.status, r.size, r.url, Reset)
	}
}

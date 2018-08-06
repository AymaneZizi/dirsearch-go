// color constants

package main

const escape = "\x1b"

const (
	Reset    string = escape + "[0m"
	FgRed    string = escape + "[31m"
	FgGreen  string = escape + "[32m"
	FgYellow string = escape + "[33m"
	FgBlue   string = escape + "[34m"
)

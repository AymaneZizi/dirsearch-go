package brutemachine

import (
	"time"
)

// Statistics contains runtime statistics.
type Statistics struct {
	// Time the execution started
	Start time.Time
	// Time the execution finished
	Stop time.Time
	// Total duration of the execution
	Total time.Duration
	// Total number of inputs from the wordlist
	Inputs uint64
	// Executions per second
	Eps float64
	// Total number of executions
	Execs uint64
	// Total number of executions with positive results.
	Results uint64
}

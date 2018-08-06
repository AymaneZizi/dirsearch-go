package brutemachine

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Printer interface is a printable brutemachine result.
type Printer interface {
	Print()
}

// RunHandler handles brutemachine logic.
type RunHandler func(line, ext string) Printer

// ResHandler handles brutemachine results.
type ResHandler func(result Printer)

// Machine represents a bruteforcing machine.
type Machine struct {
	// Runtime statistics.
	Stats Statistics
	// Number of input consumers.
	consumers uint
	// Wordlist from where items are read.
	wordlist string
	// Extensions
	extensions []string
	// Positive results channel.
	output chan Printer
	// Inputs channel.
	input chan string
	// WaitGroup to stop while the machine is running.
	wait sync.WaitGroup
	// Main logic handler.
	runHandler RunHandler
	// Positive results handler.
	resHandler ResHandler
}

// New builds a new machine object.
//
// If consumers is less or equal than 0, CPU*2 will be used as default value.
func New(consumers int, wordlist string, extensions []string, runHandler RunHandler, resHandler ResHandler) *Machine {
	var workers uint
	if consumers <= 0 {
		workers = uint(runtime.NumCPU() * 2)
	} else {
		workers = uint(consumers)
	}

	return &Machine{
		Stats:      Statistics{},
		consumers:  workers,
		wordlist:   wordlist,
		extensions: extensions,
		output:     make(chan Printer),
		input:      make(chan string),
		wait:       sync.WaitGroup{},
		runHandler: runHandler,
		resHandler: resHandler,
	}
}

func (m *Machine) inputConsumer() {
	for in := range m.input {
		for _, ex := range m.extensions {
			atomic.AddUint64(&m.Stats.Execs, 1)

			res := m.runHandler(in, ex)
			if res != nil {
				atomic.AddUint64(&m.Stats.Results, 1)
				m.output <- res
			}
			m.wait.Done()
		}
	}
}

func (m *Machine) outputConsumer() {
	for res := range m.output {
		m.resHandler(res)
	}
}

// Start the machine.
func (m *Machine) Start() error {
	// start a fixed amount of consumers for inputs
	for i := uint(0); i < m.consumers; i++ {
		go m.inputConsumer()
	}

	// start the output consumer on a goroutine
	go m.outputConsumer()

	m.Stats.Start = time.Now()

	// count the inputs we have
	lines, err := LineReader(m.wordlist, 0)
	if err != nil {
		return err
	}
	for range lines {
		m.Stats.Inputs++
	}

	lines, err = LineReader(m.wordlist, 0)
	if err != nil {
		return err
	}
	for line := range lines {
		m.input <- line
		for range m.extensions {
			m.wait.Add(1)
		}
	}

	return nil
}

// UpdateStats updates machine statistics.
func (m *Machine) UpdateStats() {
	m.Stats.Stop = time.Now()
	m.Stats.Total = m.Stats.Stop.Sub(m.Stats.Start)
	m.Stats.Eps = float64(m.Stats.Execs) / m.Stats.Total.Seconds()
}

// Wait for all jobs to be completed.
func (m *Machine) Wait() {
	// wait for everything to be completed
	m.wait.Wait()
	m.UpdateStats()
}

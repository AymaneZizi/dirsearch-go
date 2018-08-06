package brutemachine

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// LineReader returns wordlist lines.
func LineReader(wordlist string, noff int64) (chan string, error) {
	f, err := os.Open(wordlist)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %v", wordlist, err)
	}

	// if offset defined then start from there
	if noff > 0 {
		// and go to the start of the line
		b := make([]byte, 1)
		for b[0] != '\n' {
			noff--
			_, err := f.Seek(noff, io.SeekStart)
			if err != nil {
				return nil, fmt.Errorf("could not seek: %v", err)
			}
			_, err = f.Read(b)
			if err != nil {
				return nil, fmt.Errorf("could not read: %v", err)
			}
		}
		noff++
	}

	out := make(chan string)
	go func() {
		defer f.Close()
		defer close(out)

		scanner := bufio.NewScanner(f)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			var err error
			noff, err = f.Seek(0, io.SeekCurrent)
			if err != nil {
				return
			}
			out <- scanner.Text()
		}
	}()

	return out, nil
}

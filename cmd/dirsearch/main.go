// This software is a Go implementation of dirsearch by Mauro Soria
// (maurosoria at gmail dot com) written by Simone Margaritelli
// (evilsocket at gmail dot com).
// further development by @eur0pa and @jimen0

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/eur0pa/dirsearch-go"
	"github.com/eur0pa/dirsearch-go/brutemachine"
)

var (
	base     = flag.String("u", "", "URL to enumerate")
	wordlist = flag.String("w", "dict.txt", "Wordlist file")
	method   = flag.String("M", "GET", "Request method (HEAD / GET)")
	ext      = flag.String("e", "", "Extension to add to requests (comma sep)")
	cookie   = flag.String("c", "", "Cookies (format: name=value;name=value)")
	skipCode = flag.String("x", "", "Status codes to exclude (comma sep)")
	skipSize = flag.String("s", "", "Skip sizes (comma sep)")

	maxerrors = flag.Uint64("E", 10, "Max. errors before exiting")
	delay     = flag.Int64("d", 0, "Delay between requests (milliseconds)")
	sizeMin   = flag.Int64("sm", -1, "Skip size (min value)")
	sizeMax   = flag.Int64("sM", -1, "Skip size (max value)")
	threads   = flag.Int("t", 10, "Number of concurrent goroutines")
	timeout   = flag.Int("T", 10, "Timeout before killing the request")

	only200 = flag.Bool("2", false, "Only display responses with 200 status code")
	follow  = flag.Bool("f", false, "Follow redirects")
	extAll  = flag.Bool("ef", false, "Add extension to all requests (dirbuster style)")
	waf     = flag.Bool("waf", false, "Inject 'WAF bypass' headers")

	client = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        *threads,
			MaxIdleConnsPerHost: *threads,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Duration(*timeout) * time.Second,
	}

	m          *brutemachine.Machine
	normalized string
	extensions []string
	errors     = uint64(0)
	skipCodes  = make(map[int]struct{})
	skipSizes  = make(map[int64]struct{})
)

// isAlive checks if host is alive before going all the trouble
func isAlive(url string) bool {
	res, err := client.Get(*base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%scould not connect to %s: %v%s\n", FgRed, *base, err, Reset)
		return false
	}

	defer res.Body.Close()

	// no :(
	io.Copy(ioutil.Discard, res.Body)

	return true
}

// returns the content-length or the size of the body
// note: content-length can lie
func contentLenght(res *http.Response) (int64, error) {
	cl := res.Header.Get("Content-Length")
	size, err := strconv.ParseInt(cl, 10, 64)
	if size <= 0 || err != nil {
		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return 0, err
		}
		size = int64(len(b))
	} else {
		// no :( don't touch this
		io.Copy(ioutil.Discard, res.Body)
	}

	return size, nil
}

// check404 makes a bogus request to calibrate the 404 engine
func check404(url string) (int, int64, error) {
	res, err := client.Get(*base + "s0m3th1ng-r4nd0m-w1th0ut-p4ck4g3s")
	if err != nil {
		return 0, 0, err
	}

	defer res.Body.Close()

	size, err := contentLenght(res)
	if err != nil {
		return 0, 0, err
	}

	return res.StatusCode, size, nil
}

// do sends HTTP requests to the page.
func do(page, ext string) brutemachine.Printer {
	// base url + word
	url := *base + page

	// add .ext to every request, or
	if ext != "" && *extAll {
		url = url + "." + ext
	}

	// replace .ext where needed
	if ext != "" && !*extAll {
		url = strings.Replace(url, "%EXT%", ext, -1)
	}

	// build request
	req, err := http.NewRequest(*method, url, nil)
	if err != nil {
		atomic.AddUint64(&errors, 1)
		return &Result{
			url: url,
			err: fmt.Errorf("%scould not create request: %v%s", FgRed, err, Reset),
		}
	}

	// some servers have issues with */*, some others will serve
	// different content
	req.Header.Set("User-Agent", dirsearch.GetRandomUserAgent())
	req.Header.Set("Accept", "*/*")
	//req.Close = true

	// add cookies
	if *cookie != "" {
		req.Header.Set("Cookie", *cookie)
	}

	// attempt to bypass waf if asked to do so
	if *waf {
		req.Header.Set("X-Client-IP", "127.0.0.1")
		req.Header.Set("X-Remote-IP", "127.0.0.1")
		req.Header.Set("X-Remote-Addr", "127.0.0.1")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Originating-IP", "127.0.0.1")
	}

	res, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&errors, 1)
		return &Result{
			url: req.RequestURI,
			err: fmt.Errorf("%scould not request %s: %v%s", FgRed, req.RequestURI, err, Reset),
		}
	}

	defer res.Body.Close()

	_, skip := skipCodes[res.StatusCode]

	// skip certain status codes (auto-skip, and user defined)
	if (res.StatusCode == http.StatusOK && *only200) || (!skip && !*only200) {
		location := res.Header.Get("Location")

		size, err := contentLenght(res)
		if err != nil {
			return &Result{url, res.StatusCode, 0, location, err}
		}

		// skip certain sizes (auto-skip, and user defined)
		_, skip := skipSizes[size]
		if skip {
			return nil
		}

		// skip a range of sizes
		if size >= *sizeMin && size <= *sizeMax {
			return nil
		}

		return &Result{
			url:      url,
			status:   res.StatusCode,
			size:     size,
			location: location,
		}
	}

	// bad jimeno :(
	io.Copy(ioutil.Discard, res.Body)

	return nil
}

// onResult handles each result.
var onResult = func(res brutemachine.Printer) {
	if errors > *maxerrors {
		fmt.Fprintf(os.Stderr, "\n%sExceeded %d errors, quitting...%s\n", FgRed, *maxerrors, Reset)
		os.Exit(1)
	}
	res.Print()
}

// summary prints a short summary.
func summary() {
	codes := make([]int, 0, len(skipCodes))
	for key := range skipCodes {
		codes = append(codes, key)
	}

	sizes := make([]int64, 0, len(skipSizes))
	for key := range skipSizes {
		sizes = append(sizes, key)
	}

	fmt.Fprintf(os.Stderr, "\nSkip codes: %v\nSkip sizes: %v\nExtensions: %v\n     Delay: %d ms\n\n", codes, sizes, extensions, *delay)
}

func main() {
	setup()

	// create a list of extensions
	extensions = append(extensions, "")
	if *ext != "" {
		extensions = append(extensions, strings.Split(*ext, ",")...)
	}

	// create a list of exclusions
	if *skipCode != "" {
		for _, x := range strings.Split(*skipCode, ",") {
			y, err := strconv.Atoi(x)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%scould not parse code '%v'%s\n", FgRed, x, Reset)
				continue
			}
			skipCodes[y] = struct{}{}
		}
	}

	// exclude sizes
	if *skipSize != "" {
		for _, x := range strings.Split(*skipSize, ",") {
			y, err := strconv.ParseInt(x, 10, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%scould not parse size '%v'%s\n", FgRed, x, Reset)
				continue
			}
			skipSizes[y] = struct{}{}
		}
	}

	// set redirects policy
	if !*follow {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// check if host is alive.
	if !isAlive(*base) {
		return
	}

	// calibrate the 404 detection engine.
	x, y, err := check404(*base)
	if err != nil {
		return
	}

	// add found codes and sizes to the skip list
	skipCodes[x] = struct{}{}
	skipSizes[y] = struct{}{}

	// print a short summary.
	summary()

	m = brutemachine.New(*threads, *wordlist, extensions, *delay, do, onResult)
	if err := m.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "%scould not start bruteforce: %v%s\n", FgRed, err, Reset)
	}
	m.Wait()

	fmt.Fprintf(os.Stderr, "\n%sDONE%s\n", FgGreen, Reset)
	printStats()
}

// Do some initialization.
// NOTE: We can't call this in the 'init' function otherwise
// are gonna be mandatory for unit test modules.
func setup() {
	flag.Parse()

	var err error
	*base, err = dirsearch.NormalizeURL(*base)
	if err != nil {
		fmt.Println(err)
		flag.Usage()
		os.Exit(1)
	}

	// seed RNG
	rand.Seed(time.Now().Unix())

	// if interrupted, print statistics and exit
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		fmt.Fprintf(os.Stderr, "\n%sINTERRUPTING...%s\n", FgRed, Reset)
		printStats()
		os.Exit(0)
	}()
}

// Print some stats
func printStats() {
	m.UpdateStats()

	fmt.Fprintln(os.Stderr, "Requests:", m.Stats.Execs)
	fmt.Fprintln(os.Stderr, "Errors  :", errors)
	fmt.Fprintln(os.Stderr, "Results :", m.Stats.Results)
	fmt.Fprintln(os.Stderr, "Time    :", m.Stats.Total.Seconds(), "s")
	fmt.Fprintln(os.Stderr, "Req/s   :", m.Stats.Eps)
}

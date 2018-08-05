// This software is a Go implementation of dirsearch by Mauro Soria
// (maurosoria at gmail dot com) written by Simone Margaritelli
// (evilsocket at gmail dot com).
// further development by @eur0pa

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
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
	"github.com/gofrs/uuid"
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

	normalized string
	m          *brutemachine.Machine
	errors     = uint64(0)
	extensions []string
	skipCodes  = make(map[int]struct{})
	skipSizes  = make(map[int64]struct{})
)

// isAlive checks if host is alive before going all the trouble
func isAlive(url string) bool {
	res, err := client.Get(*base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not connect to %s: %v\n", *base, err)
		return false
	}
	defer res.Body.Close()

	return true
}

func contentLenght(res *http.Response) (int64, error) {
	cl := res.Header.Get("Content-Length")
	if cl != "" {
		size, err := strconv.ParseInt(cl, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("could not parse Content-Length header value")
		}
		return size, nil
	}

	// if not Content-Length header was found, read the entire body.
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}

	size := int64(len(b))
	return size, nil
}

// check404 makes a bogus request to calibrate the 404 engine
func check404(url string) (int, int64, error) {
	test := uuid.Must(uuid.NewV4()).String()

	res, err := client.Get(*base + test)
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
		return &Result{url: url, err: fmt.Errorf("could not create request: %v", err)}
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
		return &Result{url: req.RequestURI, err: fmt.Errorf("could not request %s: %v", req.RequestURI, err)}
	}
	// https://gist.github.com/mholt/eba0f2cc96658be0f717
	defer res.Body.Close()

	_, ok := skipCodes[res.StatusCode]
	if (res.StatusCode == http.StatusOK && *only200) || (!ok && !*only200) {
		location := res.Header.Get("Location")

		size, err := contentLenght(res)
		if err != nil {
			return &Result{url, res.StatusCode, 0, location, err}
		}

		// skip if size is as requested, or included in a given range
		_, ok := skipSizes[size]
		if !ok {
			return nil
		}

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

	return nil
}

// onResult handles each result.
var onResult = func(res brutemachine.Printer) {
	if errors > *maxerrors {
		fmt.Fprintf(os.Stderr, "\nExceeded %d errors, quitting...", *maxerrors)
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

	fmt.Fprintf(os.Stderr, "Skipping codes: %v\n", codes)
	fmt.Fprintf(os.Stderr, "Skipping sizes: %v\n", sizes)
	fmt.Fprintf(os.Stderr, "Extensions: %v\n", extensions)
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
				fmt.Fprintf(os.Stderr, "could not parse code '%v'\n", x)
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
				fmt.Fprintf(os.Stderr, "could not parse size '%v'\n", x)
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

	m = brutemachine.New(*threads, *wordlist, extensions, do, onResult)
	if err := m.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "could not start bruteforce: %v\n", err)
	}
	m.Wait()

	fmt.Fprintf(os.Stderr, "\nDONE\n")
	printStats()
}

// Do some initialization.
// NOTE: We can't call this in the 'init' function otherwise
// are gonna be mandatory for unit test modules.
func setup() {
	flag.Parse()

	var err error
	normalized, err = dirsearch.NormalizeURL(*base)
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
		fmt.Fprintf(os.Stderr, "\nINTERRUPTING...\n")
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

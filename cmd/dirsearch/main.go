// This software is a Go implementation of dirsearch by Mauro Soria
// (maurosoria at gmail dot com) written by Simone Margaritelli
// (evilsocket at gmail dot com).
// further development by @eur0pa

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/eur0pa/dirsearch-go"
	"github.com/eur0pa/dirsearch-go/brutemachine"
	"github.com/fatih/color"
	"github.com/gofrs/uuid"
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
)

type Result struct {
	url      string
	status   int
	size     int64
	location string
	err      error
}

var (
	m *brutemachine.Machine

	g = color.New(color.FgGreen)
	y = color.New(color.FgYellow)
	r = color.New(color.FgRed)
	b = color.New(color.FgBlue)

	errors     = uint64(0)
	extensions []string
	skip_codes = make(map[int]bool)
	skip_sizes = make(map[int64]bool)

	tr = &http.Transport{
		MaxIdleConns:        *threads,
		MaxIdleConnsPerHost: *threads,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client = &http.Client{
		Transport: tr,
		Timeout:   time.Duration(*timeout) * time.Second,
	}

	base      = flag.String("u", "", "URL to enumerate")
	wordlist  = flag.String("w", "dict.txt", "Wordlist file")
	method    = flag.String("M", "GET", "Request method (HEAD / GET)")
	ext       = flag.String("e", "", "Extension to add to requests (comma sep)")
	cookie    = flag.String("c", "", "Cookies (format: name=value;name=value)")
	skip_code = flag.String("x", "", "Status codes to exclude (comma sep)")
	skip_size = flag.String("s", "", "Skip sizes (comma sep)")

	maxerrors = flag.Uint64("E", 10, "Max. errors before exiting")
	size_min  = flag.Int64("sm", -1, "Skip size (min value)")
	size_max  = flag.Int64("sM", -1, "Skip size (max value)")
	threads   = flag.Int("t", 10, "Number of concurrent goroutines")
	timeout   = flag.Int("T", 10, "Timeout before killing the request")

	only200 = flag.Bool("2", false, "Only display responses with 200 status code")
	follow  = flag.Bool("f", false, "Follow redirects")
	ext_all = flag.Bool("ef", false, "Add extension to all requests (dirbuster style)")
	waf     = flag.Bool("waf", false, "Inject 'WAF bypass' headers")
)

// check if host is alive before going all the trouble
func IsAlive(url string) bool {
	res, err := client.Get(*base)
	if err != nil {
		r.Fprintf(os.Stderr, "Could not connect to %s: %v\n", *base, err)
		return false
	}

	defer res.Body.Close()

	io.Copy(ioutil.Discard, res.Body)

	return true
}

// make a bogus request to calibrate the 404 engine
func Check404(url string) (int, int64, error) {
	test := uuid.Must(uuid.NewV4()).String()

	res, err := client.Get(*base + test)
	if err != nil {
		return 0, 0, err
	}

	defer res.Body.Close()

	size, _ := strconv.ParseInt(res.Header.Get("content-length"), 10, 64)

	if size <= 0 {
		content, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return 0, 0, err
		}
		size = int64(len(content))
	} else {
		io.Copy(ioutil.Discard, res.Body)
	}

	return res.StatusCode, size, nil
}

// handles requests. moved some stuff out for speed
// reduced error output for practical reasons
func DoRequest(page string, ext string) interface{} {
	// base url + word
	url := *base + page

	// add .ext to every request, or
	if ext != "" && *ext_all {
		url = url + "." + ext
	}

	// replace .ext where needed
	if ext != "" && !*ext_all {
		url = strings.Replace(url, "%EXT%", ext, -1)
	}

	// build request
	req, err := http.NewRequest(*method, url, nil)
	if err != nil {
		return nil
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

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&errors, 1)
		return Result{url, 0, 0, "", err}
	}

	// https://gist.github.com/mholt/eba0f2cc96658be0f717
	defer resp.Body.Close()

	size := int64(0)

	// useful comment
	if (resp.StatusCode == http.StatusOK && *only200) || (!skip_codes[resp.StatusCode] && !*only200) {
		// try content-length first
		size, _ = strconv.ParseInt(resp.Header.Get("content-length"), 10, 64)

		// fallback to body length
		if size <= 0 {
			content, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				size = int64(len(content))
			}
		} else {
			io.Copy(ioutil.Discard, resp.Body)
		}

		// skip if size is as requested, or included in a given range
		if skip_sizes[size] {
			return nil
		}

		if size >= *size_min && size <= *size_max {
			return nil
		}

		return Result{url, resp.StatusCode, size, resp.Header.Get("location"), nil}
	}

	io.Copy(ioutil.Discard, resp.Body)

	return nil
}

func OnResult(res interface{}) {
	result, ok := res.(Result)

	if !ok {
		r.Fprintf(os.Stderr, "Error while converting result.")
		return
	}

	switch {
	case result.status == http.StatusNotFound:
		return

	case result.err != nil:
		r.Fprintf(os.Stderr, "%s : %v\n", result.url, result.err)

	case result.status >= 200 && result.status < 300:
		g.Printf("%-3d %-9d %s\n", result.status, result.size, result.url)

	case result.status >= 300 && result.status < 400:
		b.Printf("%-3d %-9d %s -> %s\n", result.status, result.size, result.url, result.location)

	case result.status >= 400 && result.status < 500:
		y.Printf("%-3d %-9d %s\n", result.status, result.size, result.url)

	case result.status >= 500 && result.status < 600:
		r.Printf("%-3d %-9d %s\n", result.status, result.size, result.url)
	}

	if errors > *maxerrors {
		r.Fprintf(os.Stderr, "\nExceeded %d errors, quitting...", *maxerrors)
		os.Exit(1)
	}
}

func main() {
	setup()

	// create a list of extensions
	extensions = append(extensions, "")
	if *ext != "" {
		for _, x := range strings.Split(*ext, ",") {
			extensions = append(extensions, x)
		}
	}

	// create a list of exclusions
	if *skip_code != "" {
		for _, x := range strings.Split(*skip_code, ",") {
			y, _ := strconv.Atoi(x)
			skip_codes[y] = true
		}
	}

	// exclude sizes
	if *skip_size != "" {
		for _, x := range strings.Split(*skip_size, ",") {
			y, _ := strconv.ParseInt(x, 10, 64)
			skip_sizes[y] = true
		}
	}

	// set redirects policy
	if !*follow {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// check if alive or fuck off
	if !IsAlive(*base) {
		os.Exit(0)
	}

	// calibrate the 404 detection engine, let's do it a few times
	x, y, err := Check404(*base)
	if err != nil {
		os.Exit(0)
	}

	// add found codes and sizes to the skip list
	if !skip_codes[x] && !skip_sizes[y] {
		skip_codes[x] = true
		skip_sizes[y] = true
	}

	// print a short summary
	var keys []string
	for key, _ := range skip_codes {
		keys = append(keys, strconv.Itoa(key))
	}
	fmt.Fprintf(os.Stderr, "\nSkipping codes: %s\n", strings.Join(keys, ","))

	keys = nil
	for key, _ := range skip_sizes {
		keys = append(keys, strconv.FormatInt(key, 10))
	}
	fmt.Fprintf(os.Stderr, "Skipping sizes: %s\n\n", strings.Join(keys, ","))

	// start
	m = brutemachine.New(*threads, *wordlist, extensions, DoRequest, OnResult)

	if err := m.Start(); err != nil {
		panic(err)
	}

	m.Wait()

	g.Fprintln(os.Stderr, "\nDONE")

	printStats()
}

// Do some initialization.
// NOTE: We can't call this in the 'init' function otherwise
// are gonna be mandatory for unit test modules.
func setup() {
	flag.Parse()

	if err := dirsearch.NormalizeURL(base); err != nil {
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
		r.Fprintln(os.Stderr, "\nINTERRUPTING...")
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

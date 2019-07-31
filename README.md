# dirsearch-go
A Go implementation of dirsearch.

##  Overview

The repo is forked from @eur0pa
as he published on on Twitter about this repo :"my own fork; I customized it heavily and added features I found useful as a bounty hunter, I use it every day. Bear in mind it's undocumented and requires anyone to read cmd/dirsearch/main.go to understand the added features".
Let's Talk about it a bit ;)

##  Features

```
  base      = -u  URL to enumerate, use {} to replace keyword
	wordlist  = -w  dict.txt (Wordlist file)
	method    = -M  GET (Request method)
	ext       = -e  Extension to add to requests ('.ext,.ext')
  cookie    = -c  Cookies (format: name=value;name=value)
	skipCode  = -x  Status codes to exclude (403,500,...)
	onlyCode  = -X  Status codes to include (200,405,...)
	skipSize  = -s  kip sizes (10,20,30-50,...)
	useragent = -U  Custom user agent
	headers   = -H  Add custom header (name:value;name=value)
	maxerrors = -E", 10, "Max. errors before exiting")
	delay     = -d", 0, "Delay between requests (milliseconds)
	threads   = -t", 10, "Number of concurrent goroutines
	timeout   = -T", 10, "Timeout before killing the goroutine
	follow    = -f  Follow redirects
	waf       = -waf  Inject 'WAF bypass' headers
	verbose   = -v  Verbose: print all results
	debug     = -vv  
```
##  Planning
* Merge it with LazyRecon .
* ....

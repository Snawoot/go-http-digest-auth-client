# go-http-digest-auth-client

Golang Http Digest Authentication Client

This client implements [RFC7616 HTTP Digest Access Authentication](https://www.rfc-editor.org/rfc/rfc7616.txt)
and by now the basic features should work.

This implementation presents pluggable HTTP transport with `http.RoundTripper` interface, stackable on top of other RoundTripper. DigestTransport intercepts server responses requiring Digest authentication and restarts them with Authentication header. Authentication challenge is reused whereever possible and it's expiration (server reject) is handled automatically.

# Usage

Complete example from E2E test:

```go

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	dac "github.com/Snawoot/go-http-digest-auth-client"
)

const (
	username = "test"
	password = "test123"
	uri      = "http://172.16.1.5"
)

func main() {
	client := &http.Client{
		Transport: dac.NewDigestTransport(username, password, http.DefaultTransport),
	}

	resp, err := client.Get(uri)
	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf(string(body))
}
```

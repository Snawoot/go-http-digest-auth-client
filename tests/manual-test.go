package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

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

	fmt.Println(string(body))

	// Sleep double nonce expiration interval
	time.Sleep(10*time.Second)

	resp, err = client.Get(uri)
	if err != nil {
		log.Fatalln(err)
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(body))
}

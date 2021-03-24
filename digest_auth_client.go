package digest_auth_client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
)

type DigestTransport struct {
	password  string
	username  string
	auth      *authorization
	authmux   sync.Mutex
	wa        *wwwAuthenticate
	wamux     sync.RWMutex
	transport http.RoundTripper
}

// NewRequest creates a new DigestTransport object
func NewRequest(username, password string, transport http.RoundTripper) *DigestTransport {
	return &DigestTransport{
		username:  username,
		password:  password,
		transport: transport,
	}
}

func (dt *DigestTransport) getWA() *wwwAuthenticate {
	dt.wamux.RLock()
	defer dt.wamux.RUnlock()
	return dt.wa
}

func (dt *DigestTransport) setWA(wa *wwwAuthenticate) {
	dt.wamux.Lock()
	defer dt.wamux.Unlock()
	dt.wa = wa
}

// Execute initialise the request and get a response
func (dt *DigestTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {

	dt.authmux.Lock()
	auth := dt.auth
	dt.authmux.Unlock()

	if auth != nil {
		return dt.executeExistingDigest(req)
	}

	reqCopy := req.Clone(req.Context())
	if req.Body != nil {
		defer req.Body.Close()
	}

	var bodyRead io.ReadWriter
	var bodyLeft io.Reader
	if req.Body != nil && req.GetBody == nil {
		bodyRead = new(bytes.Buffer)
		bodyLeft = io.TeeReader(req.Body, bodyRead)
		reqCopy.Body = io.NopCloser(bodyLeft)
	}

	// fire first request
	if resp, err = dt.transport.RoundTrip(reqCopy); err != nil {
		return nil, err
	}

	if resp.StatusCode == 401 {
		if req.Body != nil {
			if req.GetBody == nil {
				// TODO: rewind bodyRead
				reqCopy.Body = io.NopCloser(io.MultiReader(bodyRead, bodyLeft))
			} else {
				newBody, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				reqCopy.Body = newBody
			}
		}
		return dt.executeNewDigest(reqCopy, resp)
	}

	return resp, nil
}

func (dt *DigestTransport) executeNewDigest(req *http.Request, resp *http.Response) (resp2 *http.Response, err error) {
	var (
		auth     *authorization
		wa       *wwwAuthenticate
		waString string
	)

	if waString = resp.Header.Get("WWW-Authenticate"); waString == "" {
		return nil, fmt.Errorf("failed to get WWW-Authenticate header, please check your server configuration")
	}
	wa = newWwwAuthenticate(waString)
	dt.setWA(wa)

	if auth, err = newAuthorization(wa, dt.username, dt.password, req); err != nil {
		return nil, err
	}

	if resp2, err = dt.executeRequest(req, auth.toString()); err != nil {
		return nil, err
	}

	dt.authmux.Lock()
	dt.auth = auth
	dt.authmux.Unlock()
	return resp2, nil
}

func (dt *DigestTransport) executeExistingDigest(req *http.Request) (resp *http.Response, err error) {
	dt.authmux.Lock()
	var auth *authorization

	if auth, err = dt.auth.refreshAuthorization(req); err != nil {
		dt.authmux.Unlock()
		return nil, err
	}
	dt.auth = auth
	dt.authmux.Unlock()

	return dt.executeRequest(req, auth.toString())
}

func (dt *DigestTransport) executeRequest(req *http.Request, authString string) (resp *http.Response, err error) {
	req.Header.Add("Authorization", authString)
	return dt.transport.RoundTrip(req)
}

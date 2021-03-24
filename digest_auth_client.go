package digest_auth_client

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

type DigestTransport struct {
	Password  string
	Username  string
	Auth      *authorization
	Wa        *wwwAuthenticate
	transport http.RoundTripper
}


// NewRequest creates a new DigestTransport object
func NewRequest(username, password string, transport http.RoundTripper) *DigestTransport {
	return &DigestTransport{
		username: username,
		password: password,
		transport: transport,
	}
}

// Execute initialise the request and get a response
func (dt *DigestTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {

	if dt.Auth != nil {
		return dr.executeExistingDigest(req)
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
	if resp, err = tr.Transport.RoundTrip(reqCopy); err != nil {
		return nil, err
	}

	if resp.StatusCode == 401 {
		if req.Body != nil {
			if req.GetBody == nil {
				reqCopy.Body = io.NopCloser(io.MultiReader(bodyRead, bodyLeft))
			} else {
				newBody, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				reqCopy.Body = newBody
			}
		}
		return dr.executeNewDigest(reqCopy, resp)
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
	dt.Wa = wa

	if auth, err = newAuthorization(dt); err != nil {
		return nil, err
	}

	if resp2, err = dt.executeRequest(req, auth.toString()); err != nil {
		return nil, err
	}

	dt.Auth = auth
	return resp2, nil
}

func (dt *DigestTransport) executeExistingDigest(req *http.Request) (resp *http.Response, err error) {
	var auth *authorization

	if auth, err = dt.Auth.refreshAuthorization(dt); err != nil {
		return nil, err
	}
	dt.Auth = auth

	return dr.executeRequest(req, dr.Auth.toString())
}

func (dt *DigestTransport) executeRequest(req *http.Request, authString string) (resp *http.Response, err error) {
	req.Header.Add("Authorization", authString)
	return dt.transport.RoundTrip(req)
}

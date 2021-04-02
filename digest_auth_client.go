package digest_auth_client

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
)

type DigestTransport struct {
	password  string
	username  string
	auth      *authorization
	authmux   sync.Mutex
	transport http.RoundTripper
}

const (
	READ_LIMIT int64 = 128 * 1024
)

var (
	AuthRetryNeeded = errors.New("retry request with authentication")
)

// NewRequest creates a new DigestTransport object
func NewDigestTransport(username, password string, transport http.RoundTripper) *DigestTransport {
	return &DigestTransport{
		username:  username,
		password:  password,
		transport: transport,
	}
}

// Execute initialise the request and get a response
func (dt *DigestTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	reqCopy := req.Clone(req.Context())
	if req.Body != nil {
		defer req.Body.Close()
	}

	var bodyRead *bytes.Buffer
	var bodyLeft io.Reader
	if req.Body != nil && req.GetBody == nil {
		bodyRead = new(bytes.Buffer)
		bodyLeft = io.TeeReader(req.Body, bodyRead)
		reqCopy.Body = io.NopCloser(bodyLeft)
	}

	// fire first request
	if resp, err = dt.tryReq(reqCopy); err != nil {
		if err == AuthRetryNeeded {
			cleanupBody(resp.Body)
			// rearm request body and retry with new auth
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
			resp, err = dt.tryReq(reqCopy)
			if err == AuthRetryNeeded {
				return resp, nil
			}
			return resp, err
		} else {
			return nil, err
		}
	} else {
		return resp, nil
	}
}

func (dt *DigestTransport) tryReq(req *http.Request) (*http.Response, error) {
	var (
		auth     *authorization
		wa       *wwwAuthenticate
		waString string
		err      error
		resp     *http.Response
	)

	dt.authmux.Lock()

	auth = dt.auth

	if auth != nil {
		// Having existing auth
		auth, err = dt.auth.refreshAuthorization(req)
		if err != nil {
			dt.authmux.Unlock()
			return nil, err
		}
		dt.auth = auth
		dt.authmux.Unlock()

		resp, err = dt.executeAuthorizedRequest(req, auth.toString())
		if err != nil {
			return nil, err
		}
	} else {
		dt.authmux.Unlock()
		// Never seen auth challenge from server
		resp, err = dt.transport.RoundTrip(req)
		if err != nil {
			return nil, err
		}
	}

	if resp.StatusCode != 401 {
		return resp, nil
	}

	if waString = resp.Header.Get("WWW-Authenticate"); waString == "" {
		return resp, err
	}

	wa, err = newWwwAuthenticate(waString)
	if err != nil {
		return nil, err
	}

	if wa.Type != "Digest" {
		return resp, nil
	}

	auth, err = newAuthorization(wa, dt.username, dt.password, req)
	if err != nil {
		return nil, err
	}

	dt.authmux.Lock()
	dt.auth = auth
	dt.authmux.Unlock()

	return resp, AuthRetryNeeded
}

func (dt *DigestTransport) executeAuthorizedRequest(req *http.Request, authString string) (resp *http.Response, err error) {
	req.Header.Set("Authorization", authString)
	return dt.transport.RoundTrip(req)
}

// Does cleanup of HTTP response in order to make it reusable by keep-alive
// logic of HTTP transport
func cleanupBody(body io.ReadCloser) {
	io.Copy(ioutil.Discard, &io.LimitedReader{
		R: body,
		N: READ_LIMIT,
	})
	body.Close()
}

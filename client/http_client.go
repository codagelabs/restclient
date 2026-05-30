// Package client defines the HttpClient interface which abstracts the underlying HTTP client.
// This allows for mocking the HTTP requests during testing and provides a clean separation of concerns.
package client

import (
	"net/http"
)

// HttpClient defines the interface for an HTTP client that can send HTTP requests and receive HTTP responses.
// Any custom HTTP client wrapper or standard library *http.Client can implement this interface.
type HttpClient interface {
	// Do sends an HTTP request and returns an HTTP response, or an error if the request fails.
	Do(req *http.Request) (resp *http.Response, err error)
}

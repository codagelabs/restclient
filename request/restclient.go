package request

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"math"
	"math/rand"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/codagelabs/restclient/client"
)

//go:generate mockgen --source=restclient/request/restclient.go -destination=restclient/mocks/mock_restclient.go --package=mocks 
type HTTPRequest interface {
	// WithJson creates a new HTTP request with JSON payload.
	//
	// This function abstracts the complexities of request creation and provides a simple interface for
	// developers to craft and execute HTTP requests with JSON payloads.
	//
	// Parameters:
	//   requestModel: An interface{} representing the request model to be serialized to JSON.
	//
	// Returns:
	//   An HTTPRequest interface representing the generated HTTP request.
	//
	// Example:
	//   // Creating a POST request with JSON payload
	//   request := WithJSON(requestModel{"key": "value"})
	WithJson(requestModel interface{}) HTTPRequest

	// WithXml creates a new HTTP request with XML payload.
	//
	// This function abstracts the complexities of request creation and provides a simple interface for
	// developers to craft and execute HTTP requests with XML payloads.
	//
	// Parameters:
	//   requestModel: An interface{} representing the request model to be serialized to XML.
	//
	// Returns:
	//   An HTTPRequest interface representing the generated HTTP request.
	//
	// Example:
	//   // Creating a POST request with XML payload
	//   request := WithXML(requestModel{"key": "value"})
	WithXml(requestModel interface{}) HTTPRequest

	// WithFromURLEncoded creates a new HTTPRequest configured to send form data encoded in URL form.
	// The formData parameter is a map[string]interface{} containing the form data to be sent.
	// Each key-value pair in the map represents a form field and its corresponding value.
	// The values in formData can be of any type, as they will be converted to strings.
	//
	// Example:
	//   // Create a new HTTPRequest with form data encoded in URL form
	//   req := WithFromURLEncoded(map[string]interface{}{
	//       "username": "john_doe",
	//       "password": "password123",
	//       "age":      30,
	//   })
	//
	WithFromURLEncoded(formData map[string]interface{}) HTTPRequest

	// WithContext creates a new HTTPRequest with the provided context.
	// The context parameter allows for request cancellation, timeout, and other request-scoped values.
	// It is recommended to use a context.Context with cancellation propagation,
	// such as context.WithCancel or context.WithTimeout, to manage the lifecycle of the request.
	// The context can be used to control the behavior of the request, including cancellation,
	// deadline, and request-scoped values, such as authentication tokens or request-specific data.
	//
	// Example:
	//   // Create a new HTTPRequest with a context that has a timeout of 5 seconds
	//   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	//   defer cancel() // Cancel the context to release resources when done
	//   req := WithContext(ctx)

	WithContext(context context.Context) HTTPRequest

	// WithBasicAuth creates a new HTTPRequest with HTTP Basic Authentication credentials.
	// The username and password parameters are used to construct the Basic Authentication header.
	// Basic Authentication is a simple authentication scheme built into the HTTP protocol,
	// where the username and password are encoded and sent as part of the request header.
	//
	// Example:
	//   // Create a new HTTPRequest with Basic Authentication credentials
	//   req := WithBasicAuth("username", "password")

	WithBasicAuth(username string, password string) HTTPRequest

	// WithJWTAuth creates a new HTTPRequest with JWT (JSON Web Token) authentication.
	// The token parameter represents the JWT token used for authentication.
	//
	// Example:
	//   // Create a new HTTPRequest with JWT authentication
	//   req := WithJWTAuth("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

	WithJWTAuth(token string) HTTPRequest

	// WithQueryParameters creates a new HTTPRequest with query parameters.
	// The queryParam parameter is a map[string]string containing the query parameters to be added to the request URL.
	// Each key-value pair in the map represents a query parameter key and its corresponding value.
	// Query parameters are commonly used in HTTP requests to pass additional data to the server.
	//
	// Example:
	//   // Create a new HTTPRequest with query parameters
	//   queryParams := map[string]string{
	//       "page":  "1",
	//       "limit": "10",
	//   }
	//   req := WithQueryParameters(queryParams)
	WithQueryParameters(queryParam map[string]string) HTTPRequest

	// WithOAuth creates a new HTTPRequest with OAuth 2.0 authentication.
	// The token parameter represents the OAuth token used for authentication.
	// OAuth 2.0 is an authorization framework widely used for secure authorization and authentication.
	// It enables third-party applications to obtain limited access to an HTTP service on behalf of a resource owner.
	//
	// Example:
	//   // Create a new HTTPRequest with OAuth 2.0 authentication
	//   req := WithOAuth("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBHb3VwZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	WithOauth(token string) HTTPRequest

	// AddHeaders creates a new HTTPRequest with additional custom headers.
	// The key parameter represents the name of the header, and the value parameter represents its corresponding value.
	// Custom headers can be used to include additional information in the HTTP request headers.
	//
	// Example:
	//   // Create a new HTTPRequest with custom headers
	//   req := AddHeaders("Authorization", "Bearer token123").
	//          AddHeaders("Content-Type", "application/json").
	//          AddHeaders("X-Custom-Header", "custom-value")
	AddHeaders(key string, value string) HTTPRequest

	// WithCustomRequestModifier allows providing a custom function to modify the underlying *http.Request
	// before it is sent. This is useful for advanced use-cases such as adding custom signing logic,
	// tracing headers, or request-level interceptors.
	//
	// Example:
	//   req := NewRequest().WithCustomRequestModifier(func(r *http.Request) error {
	//       r.Header.Set("X-Trace-ID", generateTraceID())
	//       return nil
	//   })
	WithCustomRequestModifier(fn func(*http.Request) error) HTTPRequest

	// WithRetry configures the request to automatically retry on the specified HTTP status codes.
	// The request will be retried up to maxNoOfRetries times whenever the server responds
	// with one of the provided statusCodes. No delay is applied between retries.
	//
	// Parameters:
	//   - maxNoOfRetries: Maximum number of retry attempts.
	//   - statusCodes: HTTP status codes that should trigger a retry.
	//
	// Example:
	//   err := NewRequest().
	//       WithJson(payload).
	//       WithRetry(3, []int{500, 502, 503}).
	//       POST("https://example.com/api")
	WithRetry(maxNoOfRetries uint, statusCodes []int) HTTPRequest

	// WithRetryAndBackoff configures the request to automatically retry on the specified HTTP status
	// codes with a fixed delay between each attempt.
	//
	// Parameters:
	//   - maxNoOfRetries: Maximum number of retry attempts.
	//   - statusCodes: HTTP status codes that should trigger a retry.
	//   - backoff: Fixed duration to wait between each retry attempt.
	//
	// Example:
	//   err := NewRequest().
	//       WithJson(payload).
	//       WithRetryAndBackoff(3, []int{500, 502, 503}, 2*time.Second).
	//       POST("https://example.com/api")
	WithRetryAndBackoff(maxNoOfRetries uint, statusCodes []int, backoff time.Duration) HTTPRequest

	// WithRetryAndExponentialBackoff configures the request to automatically retry on the specified
	// HTTP status codes using exponential backoff with jitter.
	// The wait time between retries grows as: initialBackoff * 2^attempt + random jitter (up to initialBackoff).
	//
	// Parameters:
	//   - maxNoOfRetries: Maximum number of retry attempts.
	//   - statusCodes: HTTP status codes that should trigger a retry.
	//   - initialBackoff: Base duration for the first retry; subsequent retries double this value.
	//
	// Example:
	//   err := NewRequest().
	//       WithJson(payload).
	//       WithRetryAndExponentialBackoff(5, []int{500, 502, 503}, 500*time.Millisecond).
	//       POST("https://example.com/api")
	WithRetryAndExponentialBackoff(maxNoOfRetries uint, statusCodes []int, initialBackoff time.Duration) HTTPRequest

	// AddCookies creates a new HTTPRequest with additional cookies.
	// The cookies parameter represents the cookie(s) to be added to the request.
	// Cookies are small pieces of data sent from a server and stored on the client side.
	// They are commonly used for session management, authentication, and tracking.
	//
	// Example:
	//   // Create a new HTTPRequest with additional cookies
	//   cookie := &http.Cookie{
	//       Name:  "sessionID",
	//       Value: "abcdef123456",
	//   }
	//   req := AddCookies(cookie)
	AddCookies(cookies *http.Cookie) HTTPRequest

	// GetResponseAs retrieves the HTTP response and deserializes it into the provided response model based on the response Content-Type.
	// The responseModel parameter represents the model into which the HTTP response will be deserialized.
	// It should be a pointer to the struct or a variable with the appropriate type to store the response data.
	// This method automatically detects the response Content-Type and deserializes the response body accordingly.
	//
	// Example:
	//   // Define a struct representing the expected response model
	//   type User struct {
	//       ID       int    `json:"id"`
	//       Username string `json:"username"`
	//   }
	//   // Create a new HTTPRequest and send it to retrieve user data
	//   err := NewRequest().GetResponseAs(&user)
	//   if err != nil {
	//       // Handle error
	//   }
	//   // Now 'user' contains the parsed response data
	//
	// Note:
	//   The responseModel parameter should be a pointer to a struct or variable with the appropriate type to store the response data.
	//   If responseModel itself is a string, the method returns the response body as a string.
	//   If responseModel itself is a []byte, the method returns the response body as a []byte.
	//   If the response Content-Type is "application/xml", the method deserializes the XML response body into the provided response model.
	//   If the response Content-Type is "application/json", the method deserializes the JSON response body into the provided response model.
	//   Ensure that the response body is in a format compatible with the provided response model.
	//   Error handling should be implemented to handle deserialization errors or unexpected response formats.
	GetResponseAs(responseModel interface{}) HTTPRequest

	// GetResponseStatusCodeAs retrieves the HTTP response status code and stores it in the provided integer pointer.
	// The httpStatusCode parameter is a pointer to an integer variable where the HTTP response status code will be stored.
	// This method is useful for retrieving the HTTP status code without parsing the entire response body.
	//
	// Example:
	//   // Create a new HTTPRequest and send it to retrieve the response status code
	//   req := NewRequest()
	//   var statusCode int
	//   err := req.GetResponseStatusCodeAs(&statusCode)
	//   if err != nil {
	//       // Handle error
	//   }
	//   // Now 'statusCode' contains the HTTP response status code
	GetResponseStatusCodeAs(httpStatusCode *int) HTTPRequest

	// GetResponseCookiesAs retrieves the HTTP response cookies and stores them in the provided slice of *http.Cookie pointers.
	// The cookies parameter is a pointer to a slice of *http.Cookie where the HTTP response cookies will be stored.
	// This method is useful for extracting cookies from an HTTP response for further processing.
	//
	// Example:
	//   // Create a new HTTPRequest and send it to retrieve the response cookies
	//   req := NewRequest()
	//   var responseCookies []*http.Cookie
	//   err := req.GetResponseCookiesAs(&responseCookies)
	//   if err != nil {
	//       // Handle error
	//   }
	//   // Now 'responseCookies' contains the cookies from the HTTP response
	//
	GetResponseCookiesAs(cookies *[]*http.Cookie) HTTPRequest

	// GetResponseHeadersAs retrieves the HTTP response headers and stores them in the provided map of string slices.
	// The respHeaders parameter is a pointer to a map[string][]string where the HTTP response headers will be stored.
	// This method is useful for extracting headers from an HTTP response for further processing.
	//
	// Example:
	//   // Create a new HTTPRequest and send it to retrieve the response headers
	//   req := NewRequest()
	//   var responseHeaders map[string][]string
	//   err := req.GetResponseHeadersAs(&responseHeaders)
	//   if err != nil {
	//       // Handle error
	//   }
	//   // Now 'responseHeaders' contains the headers from the HTTP response
	GetResponseHeadersAs(respHeaders *map[string][]string) HTTPRequest

	// GET sends a GET request to the specified URL.
	// If a response model is provided, the function binds the response body, headers, and status code to the model.
	// It returns an error if the request fails or if the response status code is not in the 2xx range.
	//
	// Parameters:
	//   - url: The URL to which the GET request will be sent.
	//
	// Example:
	//   // Create a new HTTPRequest and send it to retrieve the response status code.
	//   var statusCode int
	//   err := NewRequest().GetResponseStatusCodeAs(&statusCode).GET("https://example.com")
	//   if err != nil {
	//       // Handle error
	//   }
	//   // Now 'statusCode' contains the HTTP response status code.
	//
	// Note:
	//   This function is a convenient wrapper for sending simple GET requests.
	//   If a response model is provided, the function binds the response body, headers, and status code to the model.
	//   Error handling should be implemented to handle communication errors or unexpected responses.
	GET(url string) error

	// POST sends a POST request to the specified URL.
	// It returns an error if the request fails or if the response status code is not in the 2xx range.
	//
	// Parameters:
	//   - url: The URL to which the POST request will be sent.
	//
	// Example:
	//   // Send a POST request to the specified URL and retrieve the response status code
	//   var statusCode int
	//   err := NewRequest().GetResponseStatusCodeAs(&statusCode).POST("https://example.com")
	//   if err != nil {
	//       // Handle error
	//   }
	//
	// Note:
	//   This function is a convenient wrapper for sending simple POST requests.
	//   Error handling should be implemented to handle communication errors or unexpected responses.
	POST(url string) error

	// PUT sends a PUT request to the specified URL.
	// It returns an error if the request fails or if the response status code is not in the 2xx range.
	//
	// Parameters:
	//   - url: The URL to which the PUT request will be sent.
	//
	// Example:
	//   // Send a PUT request to the specified URL and retrieve the response status code
	//   var statusCode int
	//   err := NewRequest().GetResponseStatusCodeAs(&statusCode).PUT("https://example.com")
	//   if err != nil {
	//       // Handle error
	//   }
	//
	// Note:
	//   This function is a convenient wrapper for sending simple PUT requests.
	//   Error handling should be implemented to handle communication errors or unexpected responses.
	PUT(url string) error

	// PATCH sends a PATCH request to the specified URL.
	// It returns an error if the request fails or if the response status code is not in the 2xx range.
	//
	// Parameters:
	//   - url: The URL to which the PATCH request will be sent.
	//
	// Example:
	//   // Send a PATCH request to the specified URL and retrieve the response status code
	//   var statusCode int
	//   err := NewRequest().GetResponseStatusCodeAs(&statusCode).PATCH("https://example.com")
	//   if err != nil {
	//       // Handle error
	//   }
	//
	// Note:
	//   This function is a convenient wrapper for sending simple PATCH requests.
	//   Error handling should be implemented to handle communication errors or unexpected responses.
	PATCH(url string) error

	// DELETE sends a DELETE request to the specified URL.
	// It returns an error if the request fails or if the response status code is not in the 2xx range.
	//
	// Parameters:
	//   - url: The URL to which the DELETE request will be sent.
	//
	// Example:
	//   // Send a DELETE request to the specified URL and retrieve the response status code
	//   var statusCode int
	//   err := NewRequest().GetResponseStatusCodeAs(&statusCode).DELETE("https://example.com")
	//   if err != nil {
	//       // Handle error
	//   }
	//
	// Note:
	//   This function is a convenient wrapper for sending simple DELETE requests.
	//   Error handling should be implemented to handle communication errors or unexpected responses.
	DELETE(url string) error

	// Execute sends an HTTP request with the specified method and URL.
	// It returns an error if the request fails or encounters any issues during execution.
	//
	// Parameters:
	//   - Method: The HTTP method to use for the request (e.g., "GET", "POST", "PUT").
	//   - url: The URL to which the HTTP request will be sent.
	//
	// Example:
	//   // Send a POST request to the specified URL
	//   err := req.Execute("POST", "https://example.com")
	//   if err != nil {
	//       // Handle error
	//   }
	//
	// Note:
	//   This method allows for sending HTTP requests with custom HTTP methods (e.g., "PUT", "DELETE").
	//   For a convenient wrapper for sending simple POST requests, see the POST method.
	//   Error handling should be implemented to handle communication errors or unexpected responses.
	Execute(Method string, url string) error

	// Error returns an error.
	Error() error
}


// BackoffStrategy defines the algorithm used to compute the delay between retry attempts.
type BackoffStrategy int

const (
	// BackoffNone applies no delay between retries.
	BackoffNone BackoffStrategy = iota
	// BackoffFixed applies a constant delay between retries.
	BackoffFixed
	// BackoffExponential applies an exponentially growing delay with jitter between retries.
	BackoffExponential
)

type httpRequest struct {
	resStatus         *int
	resModel          interface{}
	resCookies        *[]*http.Cookie
	reqModel          interface{}
	reqHeaders        map[string]string
	reqCookies        []*http.Cookie
	httpClient        client.HttpClient
	context           context.Context
	reqBytes          []byte
	err               error
	queryParams       map[string]string
	resHeaders        *map[string][]string
	retries           restRetries
	customReqModifier func(*http.Request) error
}

type restRetries struct {
	maxRetries      uint
	statusCodes     []int
	retryCounter    uint
	backoffStrategy BackoffStrategy
	backoffDuration time.Duration
}

func (req httpRequest) GetResponseHeadersAs(respHeaders *map[string][]string) HTTPRequest {
	req.resHeaders = respHeaders
	return req
}

func (req httpRequest) WithJson(requestModel interface{}) HTTPRequest {
	req.reqModel = requestModel
	req.reqHeaders["Content-Type"] = "application/json"
	reqBytes, err := json.Marshal(req.reqModel)
	if err != nil {
		req.err = err
	}
	req.reqBytes = reqBytes
	return req
}

func (req httpRequest) WithXml(requestModel interface{}) HTTPRequest {
	req.reqModel = requestModel
	req.reqHeaders["Content-Type"] = "application/xml"
	requestBytes, err := xml.Marshal(req.reqModel)
	if err != nil {
		req.err = err
	}
	req.reqBytes = requestBytes
	return req
}

func (req httpRequest) WithFromURLEncoded(formData map[string]interface{}) HTTPRequest {
	req.reqModel = formData
	bodyBuffer := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuffer)
	for key, value := range formData {
		switch value.(type) {
		case string:
			if err := bodyWriter.WriteField(key, value.(string)); err != nil {
				req.err = err
			}
		default:
			req.err = errors.New("invalid request type: only multipart string is supported ")
		}
	}
	if err := bodyWriter.Close(); err != nil {
		req.err = err
	}
	req.reqHeaders["Content-Type"] = bodyWriter.FormDataContentType()
	req.reqBytes = bodyBuffer.Bytes()
	return req
}

func (req httpRequest) WithContext(context context.Context) HTTPRequest {
	req.context = context
	return req
}

func (req httpRequest) WithBasicAuth(username, password string) HTTPRequest {
	req.reqHeaders["Authorization"] = "Basic " + req.basicAuth(username, password)
	return req
}

func (req httpRequest) WithJWTAuth(token string) HTTPRequest {
	req.reqHeaders["Authorization"] = "Bearer " + token
	return req
}

func (req httpRequest) WithOauth(token string) HTTPRequest {
	req.reqHeaders["Authorization"] = "Bearer " + token
	return req
}

func (req httpRequest) WithCustomRequestModifier(fn func(*http.Request) error) HTTPRequest {
	req.customReqModifier = fn
	return req
}

func (req httpRequest) WithRetry(maxNoOfRetries uint, statusCodes []int) HTTPRequest {
	req.retries = restRetries{
		maxRetries:      maxNoOfRetries,
		statusCodes:     statusCodes,
		backoffStrategy: BackoffNone,
	}
	return req
}

func (req httpRequest) WithRetryAndBackoff(maxNoOfRetries uint, statusCodes []int, backoff time.Duration) HTTPRequest {
	req.retries = restRetries{
		maxRetries:      maxNoOfRetries,
		statusCodes:     statusCodes,
		backoffStrategy: BackoffFixed,
		backoffDuration: backoff,
	}
	return req
}

func (req httpRequest) WithRetryAndExponentialBackoff(maxNoOfRetries uint, statusCodes []int, initialBackoff time.Duration) HTTPRequest {
	req.retries = restRetries{
		maxRetries:      maxNoOfRetries,
		statusCodes:     statusCodes,
		backoffStrategy: BackoffExponential,
		backoffDuration: initialBackoff,
	}
	return req
}

func (req httpRequest) GetResponseAs(resp interface{}) HTTPRequest {
	req.resModel = resp
	return req
}

func (req httpRequest) GetResponseStatusCodeAs(httpStatusCode *int) HTTPRequest {
	req.resStatus = httpStatusCode
	return req
}

func (req httpRequest) GetResponseCookiesAs(cookies *[]*http.Cookie) HTTPRequest {
	req.resCookies = cookies
	return req
}

func (req httpRequest) AddHeaders(key, value string) HTTPRequest {
	req.reqHeaders[key] = value
	return req
}

func (req httpRequest) WithQueryParameters(queryParam map[string]string) HTTPRequest {
	req.queryParams = queryParam
	return req
}

func (req httpRequest) AddCookies(cookies *http.Cookie) HTTPRequest {
	req.reqCookies = append(req.reqCookies, cookies)
	return req
}

func (req httpRequest) GET(url string) error {
	return req.executeRequest("GET", url)
}

func (req httpRequest) POST(url string) error {
	return req.executeRequest("POST", url)
}

func (req httpRequest) PUT(url string) error {
	return req.executeRequest("PUT", url)
}

func (req httpRequest) PATCH(url string) error {
	return req.executeRequest("PATCH", url)
}

func (req httpRequest) DELETE(url string) error {
	return req.executeRequest("DELETE", url)
}

func (req httpRequest) Execute(method string, url string) error {
	if !isValidMethod(method) {
		req.err = errors.New("invalid HTTP method")
	}
	return req.executeRequest(method, url)
}

func (req httpRequest) Error() error {
	return req.err
}

// isValidMethod checks if the provided HTTP method is valid.
func isValidMethod(method string) bool {
	// Define a list of allowed HTTP methods
	allowedMethods := map[string]bool{
		"GET":     true,
		"HEAD":    true,
		"POST":    true,
		"PUT":     true,
		"PATCH":   true,
		"DELETE":  true,
		"CONNECT": true,
		"OPTIONS": true,
		"TRACE":   true,
	}

	// Check if the provided method is in the list of allowed methods
	_, ok := allowedMethods[method]
	return ok
}

func (req httpRequest) executeRequest(method, url string) error {
	if req.err != nil {
		return req.err
	}
	httpReq, reqErr := http.NewRequest(method, url, bytes.NewBuffer(req.reqBytes))
	if reqErr != nil {
		return reqErr
	}
	for key, value := range req.reqHeaders {
		httpReq.Header.Add(key, value)
	}

	if req.context != nil {
		httpReq = httpReq.WithContext(req.context)
	}
	query := httpReq.URL.Query()
	for paramKey, paramValue := range req.queryParams {
		query.Add(paramKey, paramValue)
	}
	httpReq.URL.RawQuery = query.Encode()

	for _, cookie := range req.reqCookies {
		httpReq.AddCookie(cookie)
	}

	if req.customReqModifier != nil {
		if modErr := req.customReqModifier(httpReq); modErr != nil {
			return modErr
		}
	}

	response, httpErr := req.httpClient.Do(httpReq)
	if httpErr != nil {
		return httpErr
	}
	defer func() {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
	}()

	if response != nil && req.resStatus != nil {
		*req.resStatus = response.StatusCode
	}
	if response != nil && req.resHeaders != nil {
		*req.resHeaders = response.Header
	}

	// Determine whether this response should trigger a retry.
	shouldRetry := req.retries.maxRetries > 0 &&
		len(req.retries.statusCodes) > 0 &&
		req.retries.retryCounter < req.retries.maxRetries &&
		req.matchesRetryStatus(response.StatusCode)

	if shouldRetry {
		// Do not populate the caller's output pointers with data from an intermediate
		// failing attempt — wait until the final response (success or last retry).
		req.retries.retryCounter++
		req.applyBackoff()
		return req.executeRequest(method, url)
	}

	// Final response: bind body, cookies, etc.
	if req.resModel != nil {
		if err := req.processResponseModel(response); err != nil {
			return err
		}
	}

	if req.resCookies != nil {
		*req.resCookies = response.Cookies()
	}

	return nil
}

// matchesRetryStatus returns true if the given status code is in the retry status codes list.
func (req httpRequest) matchesRetryStatus(statusCode int) bool {
	for _, retryStatus := range req.retries.statusCodes {
		if retryStatus == statusCode {
			return true
		}
	}
	return false
}

// applyBackoff pauses execution according to the configured backoff strategy.
func (req httpRequest) applyBackoff() {
	switch req.retries.backoffStrategy {
	case BackoffFixed:
		time.Sleep(req.retries.backoffDuration)
	case BackoffExponential:
		// delay = initialBackoff * 2^attempt + jitter in [0, initialBackoff)
		attempt := int(req.retries.retryCounter)
		multiplier := math.Pow(2, float64(attempt-1))
		delay := time.Duration(float64(req.retries.backoffDuration) * multiplier)
		jitter := time.Duration(rand.Int63n(int64(req.retries.backoffDuration) + 1))
		time.Sleep(delay + jitter)
	default:
		// BackoffNone — no sleep
	}
}

func (req httpRequest) basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (req httpRequest) processResponseModel(resp *http.Response) error {

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return readErr
	}
	if strPtr, isStr := req.resModel.(*string); isStr {
		*strPtr = string(body)
	} else if byteArrPtr, isByteArrPtr := req.resModel.(*[]byte); isByteArrPtr {
		*byteArrPtr = body
	} else {
		contentType := resp.Header.Get("Content-Type")
		var unmarshalerErr error
		if strings.Contains(contentType, "application/xml") {
			unmarshalerErr = xml.Unmarshal(body, req.resModel)
		} else if strings.Contains(contentType, "application/json") {
			unmarshalerErr = json.Unmarshal(body, req.resModel)
		}
		if unmarshalerErr != nil {
			return unmarshalerErr
		}
	}
	return nil
}

type RestClient interface {
	// NewRequest generates a new HTTP request object implementing the HTTPRequest interface.
	//
	// This function abstracts the complexities of request creation and provides a simple interface for
	// developers to craft and execute HTTP requests programmatically.
	NewRequest() HTTPRequest

	// NewRequestWithRetries creates a new HTTPRequest with retry functionality.
	// It retries the request for a maximum number of times specified by maxNoOfRetries
	// if the API fails with any of the expected status codes specified in statusCodes.
	//
	// Parameters:
	//   - maxNoOfRetries: The maximum number of retries allowed for the request if it fails.
	//   - statusCodes: A slice of integers representing the HTTP status codes on which
	//     retrying the request is desired.
	//
	// Example:
	//
	//	// Create a new HTTPRequest with retry functionality
	//	req := NewRequestWithRetries(3, []int{500, 502})
	//	// Perform the request with retries
	//	resp, err := req.Send(url)
	//
	// Note:
	//
	//	The statusCodes parameter should contain the HTTP status codes for which
	//	retries are desired. If the request fails with any of the specified status codes,
	//	it will be retried up to maxNoOfRetries times.
	NewRequestWithRetries(maxNoOfRetries uint, statusCodes []int) HTTPRequest

	// NewRequestWithRetryAndBackoff creates a new HTTPRequest with retry functionality and
	// a fixed backoff delay between retry attempts.
	//
	// Parameters:
	//   - maxNoOfRetries: The maximum number of retries allowed for the request if it fails.
	//   - statusCodes: A slice of integers representing the HTTP status codes that should trigger a retry.
	//   - backoff: Fixed duration to wait between each retry attempt.
	//
	// Example:
	//
	//	req := NewRequestWithRetryAndBackoff(3, []int{500, 502}, 2*time.Second)
	NewRequestWithRetryAndBackoff(maxNoOfRetries uint, statusCodes []int, backoff time.Duration) HTTPRequest

	// NewRequestWithRetryAndExponentialBackoff creates a new HTTPRequest with retry functionality
	// and exponential backoff with jitter between retry attempts.
	// The delay grows as: initialBackoff * 2^attempt + random jitter in [0, initialBackoff).
	//
	// Parameters:
	//   - maxNoOfRetries: The maximum number of retries allowed for the request if it fails.
	//   - statusCodes: A slice of integers representing the HTTP status codes that should trigger a retry.
	//   - initialBackoff: Base duration for the exponential backoff calculation.
	//
	// Example:
	//
	//	req := NewRequestWithRetryAndExponentialBackoff(5, []int{500, 502, 503}, 500*time.Millisecond)
	NewRequestWithRetryAndExponentialBackoff(maxNoOfRetries uint, statusCodes []int, initialBackoff time.Duration) HTTPRequest
}

type restClient struct {
	httpClient client.HttpClient
}

func (builder restClient) NewRequest() HTTPRequest {
	return httpRequest{
		reqHeaders: map[string]string{},
		reqCookies: []*http.Cookie{},
		httpClient: builder.httpClient,
	}
}

func (builder restClient) NewRequestWithRetries(maxNoOfRetries uint, statusCodes []int) HTTPRequest {
	return httpRequest{
		reqHeaders: map[string]string{},
		reqCookies: []*http.Cookie{},
		httpClient: builder.httpClient,
		retries: restRetries{
			maxRetries:      maxNoOfRetries,
			statusCodes:     statusCodes,
			backoffStrategy: BackoffNone,
		},
	}
}

func (builder restClient) NewRequestWithRetryAndBackoff(maxNoOfRetries uint, statusCodes []int, backoff time.Duration) HTTPRequest {
	return httpRequest{
		reqHeaders: map[string]string{},
		reqCookies: []*http.Cookie{},
		httpClient: builder.httpClient,
		retries: restRetries{
			maxRetries:      maxNoOfRetries,
			statusCodes:     statusCodes,
			backoffStrategy: BackoffFixed,
			backoffDuration: backoff,
		},
	}
}

func (builder restClient) NewRequestWithRetryAndExponentialBackoff(maxNoOfRetries uint, statusCodes []int, initialBackoff time.Duration) HTTPRequest {
	return httpRequest{
		reqHeaders: map[string]string{},
		reqCookies: []*http.Cookie{},
		httpClient: builder.httpClient,
		retries: restRetries{
			maxRetries:      maxNoOfRetries,
			statusCodes:     statusCodes,
			backoffStrategy: BackoffExponential,
			backoffDuration: initialBackoff,
		},
	}
}

func NewRestClient(httpClient client.HttpClient) RestClient {
	return restClient{httpClient: httpClient}
}

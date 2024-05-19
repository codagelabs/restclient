package request

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

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


type httpRequest struct {
	resStatus   *int
	resModel    interface{}
	resCookies  *[]*http.Cookie
	reqModel    interface{}
	reqHeaders  map[string]string
	reqCookies  []*http.Cookie
	httpClient  client.HttpClient
	context     context.Context
	reqBytes    []byte
	err         error
	queryParams map[string]string
	resHeaders  *map[string][]string
	retries     restRetries
}

type restRetries struct {
	maxRetries   uint
	statusCodes  []int
	retryCounter uint
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
			err := bodyWriter.WriteField(key, value.(string))
			if err != nil {
				fmt.Printf("Error: %+v,", err)
				req.err = err
			}
		default:
			req.err = errors.New("invalid request type: only multipart string is supported ")
		}
	}
	err := bodyWriter.Close()
	if err != nil {
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
	httpRequest, reqErr := http.NewRequest(method, url, bytes.NewBuffer(req.reqBytes))
	if reqErr != nil {
		return req.err
	}
	for key, value := range req.reqHeaders {
		httpRequest.Header.Add(key, value)
	}

	if req.context != nil {
		httpRequest = httpRequest.WithContext(req.context)
	}
	query := httpRequest.URL.Query()
	for paramKey, paramValue := range req.queryParams {
		query.Add(paramKey, paramValue)
	}
	httpRequest.URL.RawQuery = query.Encode()

	for _, cookie := range req.reqCookies {
		httpRequest.AddCookie(cookie)
	}
	response, httpErr := req.httpClient.Do(httpRequest)
	if httpErr != nil {
		return httpErr
	}
	if response != nil && req.resStatus != nil {
		*req.resStatus = response.StatusCode
	}
	if response != nil && req.resHeaders != nil {
		*req.resHeaders = response.Header
	}

	if req.resModel != nil {
		err := req.processResponseModel(response)
		if err != nil {
			return err
		}
	}

	if req.resCookies != nil {
		*req.resCookies = response.Cookies()
		fmt.Println(response.Cookies())
	}
	closeErr := response.Body.Close()
	if closeErr != nil {
		return closeErr
	}

	if req.retries.maxRetries > 0 && len(req.retries.statusCodes) > 0 {
		if req.retries.retryCounter < req.retries.maxRetries {
			for _, retryStatus := range req.retries.statusCodes {
				if retryStatus == response.StatusCode {
					req.retries.retryCounter = req.retries.retryCounter + 1
					return req.executeRequest(method, url)
				}
			}
		}
	}

	return nil
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
		var unmarshalerErr error
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/xml") {
			unmarshalerErr = xml.Unmarshal(body, req.resModel)
		}
		if strings.Contains(contentType, "application/json") {
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
			maxRetries:  maxNoOfRetries,
			statusCodes: statusCodes,
		},
	}
}

func NewRestClient(httpClient client.HttpClient) RestClient {
	return restClient{httpClient: httpClient}
}

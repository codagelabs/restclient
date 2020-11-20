package request

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/codagelabs/restclient/client"
)

type HTTPRequest interface {
	WithJson(requestModel interface{}) HTTPRequest
	WithXml(requestModel interface{}) HTTPRequest
	WithFromURLEncoded(formData map[string]interface{}) HTTPRequest
	WithContext(context context.Context) HTTPRequest
	WithBasicAuth(username string, password string) HTTPRequest
	WithJWTAuth(token string) HTTPRequest
	WithQueryParameters(queryParam map[string]string) HTTPRequest
	WithOauth(token string) HTTPRequest
	AddHeaders(key string, value string) HTTPRequest
	AddCookies(cookies *http.Cookie) HTTPRequest
	GetResponseAs(responseModel interface{}) HTTPRequest
	GetResponseStatusCodeAs(httpStatusCode *int) HTTPRequest
	GetResponseCookiesAs(cookies *[]*http.Cookie) HTTPRequest
	GetResponseHeadersAs(respHeaders *map[string][]string) HTTPRequest
	GET(url string) error
	POST(url string) error
	PUT(url string) error
	PATCH(url string) error
	DELETE(url string) error
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
			req.err = errors.New("Invalid request type: only multipart string is supported ")
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
	_ = req.executeRequest("GET", url)
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

func (req httpRequest) Error() error {
	return req.err
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
	return nil
}

func (req httpRequest) basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (req httpRequest) processResponseModel(resp *http.Response) error {

	body, readErr := ioutil.ReadAll(resp.Body)
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
	NewRequest() HTTPRequest
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

func NewRestClient(httpClient client.HttpClient) RestClient {
	return restClient{httpClient: httpClient}
}

package request

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/suite"
)

type testServerResp struct {
	Error string `json:"error" xml:"error"`
	Data  string `json:"data" xml:"data"`
}

func newSuccessResp() testServerResp {
	return testServerResp{
		Data: "success",
	}
}

func newErrorResp() testServerResp {
	return testServerResp{
		Error: "error",
	}
}

type HTTPRequestTestSuite struct {
	suite.Suite
	ctx        context.Context
	restClient RestClient
}

const (
	jwtTestSecret = "jwt-test-secret"
)

func TestHTTPRequestTestSuite(t *testing.T) {
	suite.Run(t, new(HTTPRequestTestSuite))
}

func (suite *HTTPRequestTestSuite) SetupTest() {
	suite.ctx = context.Background()
	suite.restClient = NewRestClient(http.DefaultClient)
}

func (suite *HTTPRequestTestSuite) TearDownTest() {

}

func (suite *HTTPRequestTestSuite) setupTestServer(handleFunc func(res http.ResponseWriter, req *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handleFunc))
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithXmlBodyShouldSuccessWithXmlResponse() {

	serverResponse := newSuccessResp()
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := testServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/xml")
		res.WriteHeader(serverStatus)
		marshal, err := xml.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithXml(serverResponse).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithXmlBodyShouldReturnAnErrorStatusNotFound() {

	type ServerResp struct {
		Data  string `xml:"data"`
		Error string `xml:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusNotFound
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/xml")
		res.WriteHeader(serverStatus)
		marshal, err := xml.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(http.StatusNotFound, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithXmlBodyShouldReturnAnErrorWhenErrorInRequestParsing() {

	serverResponse := map[string]interface{}{
		"test": make(chan int),
	}
	var expectedStatus int

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/xml")
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.NotNil(err)
}

func (suite *HTTPRequestTestSuite) Test_PostRequestWithJsonBodyShouldRetunAnErrorResponseNotFound() {

	serverResponse := newErrorResp()
	serverStatus := http.StatusNotFound
	var expectedStatus int
	clientResp := testServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) Test_PostRequestWithJsonBodyShouldSuccess() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) Test_PostRequestWithJsonBodyShouldSuccessWithResponseHeader() {

	serverResponse := newSuccessResp()
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := testServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()
	var respHeaders map[string][]string
	err := suite.restClient.NewRequest().WithJson(serverResponse).GetResponseHeadersAs(&respHeaders).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.NotNil(respHeaders)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) Test_PostRequestWithJsonBodyAndOauthShouldSuccess() {

	serverStatus := http.StatusOK
	var expectedStatus int

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		suite.Equal("test-Token", suite.extractJwtToken(req))
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithOauth("test-Token").GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) Test_PostRequestWithJsonBodyAndOauthShouldReturnErrorStatusUnauthorized() {

	serverStatus := http.StatusUnauthorized
	var expectedStatus int

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		suite.Equal("test-Token", suite.extractJwtToken(req))
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithOauth("test-Token").GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) Test_PatchRequestWithJsonBodyShouldSuccess() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).PATCH(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestPostRequestFormURLEncodedShouldReturnJsonDataWithSuccessResponse() {

	serverResponse := newSuccessResp()
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := testServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		for key, value := range req.Form {
			fmt.Printf("Key: %v, Value: %v ", key, value)
		}
		res.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(res).Encode(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		res.WriteHeader(serverStatus)
	}

	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	formData := map[string]interface{}{
		"name": "foo",
		"key":  "bar",
	}
	err := suite.restClient.NewRequest().WithFromURLEncoded(formData).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestPostRequestFormURLEncodedShouldReturnJsonDataWithShouldReturnAnErrorContentTypeNotSupported() {

	formData := map[string]interface{}{
		"name": map[string]string{
			"test": "test",
		},
	}
	err := suite.restClient.NewRequest().WithFromURLEncoded(formData).Error()
	suite.Equal(errors.New("invalid request type: only multipart string is supported "), err)

}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithJsonBodyAndWithContextShouldSuccess() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).WithContext(context.Background()).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) Test_PostRequestWithJsonBodyAndAddCookiesShouldSuccess() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()
	cookie := http.Cookie{
		Name:  "test-cookies",
		Value: "test-value",
	}

	err := suite.restClient.NewRequest().WithJson(serverResponse).AddCookies(&cookie).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) Test_PostRequestShouldRetrievesTestCookiesWhenSuccess() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var clientStatus int
	clientResp := ServerResp{}
	serverCookie := http.Cookie{
		Name:    "name",
		Value:   "value",
		Expires: time.Now().Add(time.Duration(10) * time.Second),
	}
	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}

		http.SetCookie(res, &serverCookie)
		_, _ = res.Write(marshal)
		res.WriteHeader(serverStatus)
	}
	clientCookies := []*http.Cookie{}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).GetResponseCookiesAs(&clientCookies).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&clientStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, clientStatus)
	suite.NotNil(clientCookies[0])
}

func (suite *HTTPRequestTestSuite) Test_DeleteRequestWithUrlQueryParameterShouldSuccess() {
	serverResponse := newSuccessResp()
	serverStatus := http.StatusOK
	var clientStatus int
	clientResp := testServerResp{}
	queryData := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		suite.Equal("value1", req.URL.Query().Get("key1"))
		suite.Equal("value2", req.URL.Query().Get("key2"))
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
		res.WriteHeader(serverStatus)
	}
	clientCookies := []*http.Cookie{}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithQueryParameters(queryData).GetResponseCookiesAs(&clientCookies).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&clientStatus).DELETE(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, clientStatus)
}

func (suite *HTTPRequestTestSuite) Test_GetRequestWithUrlQueryParameterShouldSuccess() {

	serverResponse := newSuccessResp()
	serverStatus := http.StatusOK
	var clientStatus int
	clientResp := testServerResp{}
	queryData := map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		suite.Equal("value1", req.URL.Query().Get("key1"))
		suite.Equal("value2", req.URL.Query().Get("key2"))
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
		res.WriteHeader(serverStatus)
	}
	clientCookies := []*http.Cookie{}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithQueryParameters(queryData).GetResponseCookiesAs(&clientCookies).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&clientStatus).GET(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, clientStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestShouldRetrievesTestCookiesShouldBeNilIfServersSuccess() {

	serverResponse := newSuccessResp()
	serverStatus := http.StatusOK
	var clientStatus int
	clientResp := testServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
		res.WriteHeader(serverStatus)
	}
	clientCookies := []*http.Cookie{}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).GetResponseCookiesAs(&clientCookies).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&clientStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, clientStatus)
	suite.Empty(clientCookies)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithJsonBodyAndAddHeadersShouldSuccess() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).AddHeaders("Content_type", "application/json").GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithJsonBodyShouldReturnAnErrorNotFound() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusNotFound
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithJsonAndBasicAuthBodyShouldSuccess() {
	testUsername := "test-username"
	testPassword := "test-pass"
	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		auth, password, ok := req.BasicAuth()
		if !ok || !(auth == testUsername && password == testPassword) {
			res.WriteHeader(http.StatusUnauthorized)
			fmt.Println("inside block block")
			return
		}

		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)

	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).WithBasicAuth(testUsername, testPassword).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	fmt.Println(expectedStatus)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithJsonAndBasicAuthBodyShouldReturnAnUnAuthorizedError() {
	testUsername := "test-username"
	testPassword := "test-pass"
	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "",
		Data:  "",
	}
	serverStatus := http.StatusUnauthorized
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		auth, password, ok := req.BasicAuth()
		if !ok || !(auth == testUsername && password == testPassword) {
			res.WriteHeader(http.StatusUnauthorized)
			marshal, err := json.Marshal(serverResponse)
			if err != nil {
				suite.Error(errors.New("error in marshalling"))
			}
			_, _ = res.Write(marshal)
			return
		}

	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().WithJson(serverResponse).WithBasicAuth("testUsername", testPassword).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	fmt.Println(expectedStatus)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithJsonAndJWtAuthShouldSuccess() {
	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		_, err := suite.verifyJwtTestToken(req)
		if err != nil {
			res.WriteHeader(http.StatusUnauthorized)
			marshal, err := json.Marshal(serverResponse)
			if err != nil {
				suite.Error(errors.New("error in marshalling"))
			}
			_, _ = res.Write(marshal)
			return
		}

		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)

	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()
	token, _ := suite.createJwtTestToken(1)
	err := suite.restClient.NewRequest().WithJson(serverResponse).WithJWTAuth(token).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithJsonAndJWtAuthShouldReturnStatusUnAuthorized() {
	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		_, err := suite.verifyJwtTestToken(req)
		if err != nil {
			res.WriteHeader(http.StatusUnauthorized)
			marshal, err := json.Marshal(serverResponse)
			if err != nil {
				suite.Error(errors.New("error in marshalling"))
			}
			_, _ = res.Write(marshal)
			return
		}

		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)

	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()
	token := "invalid-token"
	err := suite.restClient.NewRequest().WithJson(serverResponse).WithJWTAuth(token).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(http.StatusUnauthorized, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPutRequestWithJsonAndJWtAuthShouldSuccess() {
	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		_, err := suite.verifyJwtTestToken(req)
		if err != nil {
			res.WriteHeader(http.StatusUnauthorized)
			marshal, err := json.Marshal(serverResponse)
			if err != nil {
				suite.Error(errors.New("error in marshalling"))
			}
			_, _ = res.Write(marshal)
			return
		}

		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)

	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()
	token, _ := suite.createJwtTestToken(1)
	err := suite.restClient.NewRequest().WithJson(serverResponse).WithJWTAuth(token).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).PUT(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPutRequestWithJsonAndJWtAuthShouldReturnStatusUnAuthorized() {
	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "error",
		Data:  "data",
	}
	serverStatus := http.StatusOK
	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")

		_, err := suite.verifyJwtTestToken(req)
		if err != nil {
			res.WriteHeader(http.StatusUnauthorized)
			marshal, err := json.Marshal(serverResponse)
			if err != nil {
				suite.Error(errors.New("error in marshalling"))
			}
			_, _ = res.Write(marshal)
			return
		}

		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)

	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()
	token := "invalid-token"
	err := suite.restClient.NewRequest().WithJson(serverResponse).WithJWTAuth(token).GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).PUT(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(http.StatusUnauthorized, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestWithXml_ShouldReturnAnErrorWhenInvalidDataForMarshal() {
	test := map[string]interface{}{
		"test": make(chan int),
	}
	err := suite.restClient.NewRequest().WithXml(test).Error()
	suite.NotNil(err)
}
func (suite *HTTPRequestTestSuite) TestWithJson_ShouldReturnAnErrorWhenInvalidDataForMarshal() {
	test := map[string]interface{}{
		"test": make(chan int),
	}
	err := suite.restClient.NewRequest().WithJson(test).Error()
	suite.NotNil(err)
}

func (suite *HTTPRequestTestSuite) createJwtTestToken(userid uint64) (string, error) {
	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userid
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(jwtTestSecret))
	if err != nil {
		suite.Error(err)
		return "", err
	}
	return token, nil
}

func (suite *HTTPRequestTestSuite) verifyJwtTestToken(r *http.Request) (*jwt.Token, error) {
	tokenString := suite.extractJwtToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtTestSecret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (suite *HTTPRequestTestSuite) extractJwtToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithRetriesWithJsonBodyAndAddHeadersShouldFailedAfter3Retries() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}

	serverResponse := ServerResp{
		Error: "",
		Data:  "",
	}
	serverStatus := http.StatusInternalServerError

	var expectedStatus int
	clientResp := ServerResp{}

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(serverStatus)
		marshal, err := json.Marshal(serverResponse)
		if err != nil {
			suite.Error(errors.New("error in marshalling"))
		}
		_, _ = res.Write(marshal)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequestWithRetries(3, []int{500}).WithJson(serverResponse).AddHeaders("Content_type", "application/json").GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(serverResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

func (suite *HTTPRequestTestSuite) TestTestPostRequestWithRetriesWithJsonBodyAndAddHeadersShouldFailedAfter1Retries2ndRetrySuccess() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}
	expectedResponse := ServerResp{
		Error: "",
		Data:  "data",
	}

	serverStatus := http.StatusOK

	var expectedStatus int
	clientResp := ServerResp{}
	count := 0
	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		if count == 0 {
			serverResponse := ServerResp{
				Error: "error",
				Data:  "",
			}
			res.Header().Set("Content-Type", "application/json")
			res.WriteHeader(500)
			marshal, err := json.Marshal(serverResponse)
			if err != nil {
				suite.Error(errors.New("error in marshalling"))
			}
			_, _ = res.Write(marshal)
			count = count + 1
		} else {
			serverResponse := ServerResp{
				Error: "",
				Data:  "data",
			}
			res.Header().Set("Content-Type", "application/json")
			res.WriteHeader(200)
			marshal, err := json.Marshal(serverResponse)
			if err != nil {
				suite.Error(errors.New("error in marshalling"))
			}
			_, _ = res.Write(marshal)
		}
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequestWithRetries(1, []int{500}).WithJson(expectedResponse).AddHeaders("Content_type", "application/json").GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(expectedResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}


func (suite *HTTPRequestTestSuite) TestTestPostRequestWithRetriesWithJsonBodyAndAddHeadersShouldFailedAfter1and2Retries3rdRetrySuccess() {

	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}
	expectedResponse := ServerResp{
		Error: "",
		Data:  "data",
	}

	serverStatus := http.StatusOK

	var expectedStatus int
	clientResp := ServerResp{}
	count1 := 0
	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		if count1 <2 {
			serverResponse := ServerResp{
				Error: "error",
				Data:  "",
			}
			res.Header().Set("Content-Type", "application/json")
			res.WriteHeader(500)
			marshal, err := json.Marshal(serverResponse)
			if err != nil {
				suite.Error(errors.New("error in marshalling"))
			}
			_, _ = res.Write(marshal)
			count1 = count1 + 1
		} else {
			serverResponse := ServerResp{
				Error: "",
				Data:  "data",
			}
			res.Header().Set("Content-Type", "application/json")
			res.WriteHeader(200)
			marshal, err := json.Marshal(serverResponse)
			if err != nil {
				suite.Error(errors.New("error in marshalling"))
			}
			_, _ = res.Write(marshal)
		}
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequestWithRetries(3, []int{500}).WithJson(expectedResponse).AddHeaders("Content_type", "application/json").GetResponseAs(&clientResp).GetResponseStatusCodeAs(&expectedStatus).POST(testServer.URL)
	suite.Nil(err)
	suite.Equal(expectedResponse, clientResp)
	suite.Equal(serverStatus, expectedStatus)
}

// ---------------------------------------------------------------------------
// WithRetry (chainable on HTTPRequest)
// ---------------------------------------------------------------------------

func (suite *HTTPRequestTestSuite) Test_WithRetry_ShouldRetryAndEventuallySucceed() {
	type ServerResp struct {
		Data  string `json:"data"`
		Error string `json:"error"`
	}
	successResp := ServerResp{Data: "ok"}
	var expectedStatus int
	clientResp := ServerResp{}
	callCount := 0

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.Header().Set("Content-Type", "application/json")
		if callCount < 3 {
			res.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(res).Encode(ServerResp{Error: "unavailable"})
		} else {
			res.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(res).Encode(successResp)
		}
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithJson(successResp).
		WithRetry(3, []int{503}).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&expectedStatus).
		POST(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, expectedStatus)
	suite.Equal(3, callCount) // 2 failures + 1 success
}

func (suite *HTTPRequestTestSuite) Test_WithRetry_ShouldNotRetryOnUnregisteredStatusCode() {
	var expectedStatus int
	callCount := 0

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.WriteHeader(http.StatusNotFound)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	// 404 is not in the retry list, so no retry should happen
	err := suite.restClient.NewRequest().
		WithRetry(3, []int{500, 503}).
		GetResponseStatusCodeAs(&expectedStatus).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusNotFound, expectedStatus)
	suite.Equal(1, callCount) // called exactly once, no retry
}

func (suite *HTTPRequestTestSuite) Test_WithRetry_ShouldExhaustRetriesAndReturnLastResponse() {
	type ServerResp struct {
		Error string `json:"error"`
	}
	var expectedStatus int
	clientResp := ServerResp{}
	callCount := 0

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(res).Encode(ServerResp{Error: "always fails"})
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithJson(struct{}{}).
		WithRetry(2, []int{500}).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&expectedStatus).
		POST(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusInternalServerError, expectedStatus)
	suite.Equal(3, callCount) // initial + 2 retries
}

// ---------------------------------------------------------------------------
// WithRetryAndBackoff (chainable on HTTPRequest)
// ---------------------------------------------------------------------------

func (suite *HTTPRequestTestSuite) Test_WithRetryAndBackoff_ShouldRetryWithFixedDelayAndSucceed() {
	type ServerResp struct {
		Data string `json:"data"`
	}
	successResp := ServerResp{Data: "done"}
	var expectedStatus int
	clientResp := ServerResp{}
	callCount := 0

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			res.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(res).Encode(ServerResp{})
		} else {
			res.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(res).Encode(successResp)
		}
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithJson(successResp).
		WithRetryAndBackoff(2, []int{502}, 1*time.Millisecond).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&expectedStatus).
		POST(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, expectedStatus)
	suite.Equal(successResp, clientResp)
	suite.Equal(2, callCount)
}

// ---------------------------------------------------------------------------
// WithRetryAndExponentialBackoff (chainable on HTTPRequest)
// ---------------------------------------------------------------------------

func (suite *HTTPRequestTestSuite) Test_WithRetryAndExponentialBackoff_ShouldRetryAndSucceed() {
	type ServerResp struct {
		Data string `json:"data"`
	}
	successResp := ServerResp{Data: "recovered"}
	var expectedStatus int
	clientResp := ServerResp{}
	callCount := 0

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.Header().Set("Content-Type", "application/json")
		if callCount < 3 {
			res.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(res).Encode(ServerResp{})
		} else {
			res.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(res).Encode(successResp)
		}
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithJson(successResp).
		WithRetryAndExponentialBackoff(4, []int{500}, 1*time.Millisecond).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&expectedStatus).
		POST(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, expectedStatus)
	suite.Equal(successResp, clientResp)
	suite.Equal(3, callCount)
}

// ---------------------------------------------------------------------------
// NewRequestWithRetryAndBackoff (RestClient constructor)
// ---------------------------------------------------------------------------

func (suite *HTTPRequestTestSuite) Test_NewRequestWithRetryAndBackoff_ShouldRetryAndSucceed() {
	type ServerResp struct {
		Data string `json:"data"`
	}
	successResp := ServerResp{Data: "ok"}
	var expectedStatus int
	clientResp := ServerResp{}
	callCount := 0

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			res.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(res).Encode(ServerResp{})
		} else {
			res.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(res).Encode(successResp)
		}
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequestWithRetryAndBackoff(2, []int{503}, 1*time.Millisecond).
		WithJson(successResp).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&expectedStatus).
		POST(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, expectedStatus)
	suite.Equal(successResp, clientResp)
	suite.Equal(2, callCount)
}

func (suite *HTTPRequestTestSuite) Test_NewRequestWithRetryAndBackoff_ShouldExhaustRetries() {
	callCount := 0
	var expectedStatus int

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.WriteHeader(http.StatusServiceUnavailable)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequestWithRetryAndBackoff(2, []int{503}, 1*time.Millisecond).
		GetResponseStatusCodeAs(&expectedStatus).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusServiceUnavailable, expectedStatus)
	suite.Equal(3, callCount) // initial + 2 retries
}

// ---------------------------------------------------------------------------
// NewRequestWithRetryAndExponentialBackoff (RestClient constructor)
// ---------------------------------------------------------------------------

func (suite *HTTPRequestTestSuite) Test_NewRequestWithRetryAndExponentialBackoff_ShouldRetryAndSucceed() {
	type ServerResp struct {
		Data string `json:"data"`
	}
	successResp := ServerResp{Data: "exponential-ok"}
	var expectedStatus int
	clientResp := ServerResp{}
	callCount := 0

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.Header().Set("Content-Type", "application/json")
		if callCount < 3 {
			res.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(res).Encode(ServerResp{})
		} else {
			res.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(res).Encode(successResp)
		}
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequestWithRetryAndExponentialBackoff(4, []int{502}, 1*time.Millisecond).
		WithJson(successResp).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&expectedStatus).
		POST(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, expectedStatus)
	suite.Equal(successResp, clientResp)
	suite.Equal(3, callCount)
}

func (suite *HTTPRequestTestSuite) Test_NewRequestWithRetryAndExponentialBackoff_ShouldExhaustRetries() {
	callCount := 0
	var expectedStatus int

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.WriteHeader(http.StatusBadGateway)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequestWithRetryAndExponentialBackoff(3, []int{502}, 1*time.Millisecond).
		GetResponseStatusCodeAs(&expectedStatus).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusBadGateway, expectedStatus)
	suite.Equal(4, callCount) // initial + 3 retries
}

// ---------------------------------------------------------------------------
// WithCustomRequestModifier
// ---------------------------------------------------------------------------

func (suite *HTTPRequestTestSuite) Test_WithCustomRequestModifier_ShouldInjectCustomHeader() {
	const traceHeader = "X-Trace-ID"
	const traceValue = "test-trace-123"
	var expectedStatus int

	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		suite.Equal(traceValue, req.Header.Get(traceHeader))
		res.WriteHeader(http.StatusOK)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithCustomRequestModifier(func(r *http.Request) error {
			r.Header.Set(traceHeader, traceValue)
			return nil
		}).
		GetResponseStatusCodeAs(&expectedStatus).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, expectedStatus)
}

func (suite *HTTPRequestTestSuite) Test_WithCustomRequestModifier_ShouldReturnErrorWhenModifierFails() {
	handlerFunc := func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
	}
	testServer := suite.setupTestServer(handlerFunc)
	defer testServer.Close()

	expectedErr := errors.New("modifier error")
	err := suite.restClient.NewRequest().
		WithCustomRequestModifier(func(r *http.Request) error {
			return expectedErr
		}).
		GET(testServer.URL)

	suite.NotNil(err)
	suite.Equal(expectedErr, err)
}

// ---------------------------------------------------------------------------
// Execute — custom HTTP method
// ---------------------------------------------------------------------------

// Test_Execute_WithValidMethod_ShouldSuccess verifies that Execute dispatches a request
// using the supplied method string and returns the server response without error.
func (suite *HTTPRequestTestSuite) Test_Execute_WithValidMethod_ShouldSuccess() {
	serverStatus := http.StatusOK
	var expectedStatus int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		suite.Equal("OPTIONS", req.Method)
		res.WriteHeader(serverStatus)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		GetResponseStatusCodeAs(&expectedStatus).
		Execute("OPTIONS", testServer.URL)

	suite.Nil(err)
	suite.Equal(serverStatus, expectedStatus)
}

// Test_Execute_WithInvalidMethod_ShouldReturnError ensures that Execute rejects
// an unrecognised HTTP method before sending any network request.
func (suite *HTTPRequestTestSuite) Test_Execute_WithInvalidMethod_ShouldReturnError() {
	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		// should never be reached
		res.WriteHeader(http.StatusOK)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		Execute("INVALID_METHOD", testServer.URL)

	suite.NotNil(err)
	suite.Equal("invalid HTTP method", err.Error())
}

// Test_Execute_HeadMethod_ShouldSuccess verifies HEAD is a valid method.
func (suite *HTTPRequestTestSuite) Test_Execute_HeadMethod_ShouldSuccess() {
	var expectedStatus int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		suite.Equal("HEAD", req.Method)
		res.WriteHeader(http.StatusOK)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		GetResponseStatusCodeAs(&expectedStatus).
		Execute("HEAD", testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, expectedStatus)
}

// ---------------------------------------------------------------------------
// Response binding — *string and *[]byte
// ---------------------------------------------------------------------------

// Test_GetResponseAs_String_ShouldReturnRawBody verifies that when the caller
// passes a *string to GetResponseAs, the raw response body is written into it
// regardless of Content-Type.
func (suite *HTTPRequestTestSuite) Test_GetResponseAs_String_ShouldReturnRawBody() {
	rawBody := `{"message":"hello"}`

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		_, _ = res.Write([]byte(rawBody))
	})
	defer testServer.Close()

	var body string
	var status int

	err := suite.restClient.NewRequest().
		GetResponseAs(&body).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(rawBody, body)
	suite.Equal(http.StatusOK, status)
}

// Test_GetResponseAs_Bytes_ShouldReturnRawBody verifies that a *[]byte target
// receives the exact raw bytes returned by the server.
func (suite *HTTPRequestTestSuite) Test_GetResponseAs_Bytes_ShouldReturnRawBody() {
	rawBody := `<data>xml-content</data>`

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/xml")
		res.WriteHeader(http.StatusOK)
		_, _ = res.Write([]byte(rawBody))
	})
	defer testServer.Close()

	var body []byte

	err := suite.restClient.NewRequest().
		GetResponseAs(&body).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal([]byte(rawBody), body)
}

// Test_GetResponseAs_String_WithNon2xxStatus verifies that the raw body is still
// captured even when the server returns an error status code.
func (suite *HTTPRequestTestSuite) Test_GetResponseAs_String_WithNon2xxStatus() {
	errBody := `{"error":"not found"}`

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusNotFound)
		_, _ = res.Write([]byte(errBody))
	})
	defer testServer.Close()

	var body string
	var status int

	err := suite.restClient.NewRequest().
		GetResponseAs(&body).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(errBody, body)
	suite.Equal(http.StatusNotFound, status)
}

// ---------------------------------------------------------------------------
// Transport-level error
// ---------------------------------------------------------------------------

// Test_GET_NetworkError_ShouldReturnError ensures that a transport-level failure
// (e.g. connection refused) is surfaced as an error rather than silently ignored.
func (suite *HTTPRequestTestSuite) Test_GET_NetworkError_ShouldReturnError() {
	// Use an address where nothing is listening.
	err := suite.restClient.NewRequest().
		GET("http://127.0.0.1:1") // port 1 is privileged and always refused

	suite.NotNil(err)
}

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

// Test_WithContext_CancelledBeforeRequest_ShouldReturnError verifies that a
// pre-cancelled context causes the request to fail immediately.
func (suite *HTTPRequestTestSuite) Test_WithContext_CancelledBeforeRequest_ShouldReturnError() {
	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
	})
	defer testServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := suite.restClient.NewRequest().
		WithContext(ctx).
		GET(testServer.URL)

	suite.NotNil(err)
}

// Test_WithContext_TimedOut_ShouldReturnError verifies that a very short deadline
// causes a timeout error.
func (suite *HTTPRequestTestSuite) Test_WithContext_TimedOut_ShouldReturnError() {
	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		time.Sleep(100 * time.Millisecond) // slow handler
		res.WriteHeader(http.StatusOK)
	})
	defer testServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	err := suite.restClient.NewRequest().
		WithContext(ctx).
		GET(testServer.URL)

	suite.NotNil(err)
}

// ---------------------------------------------------------------------------
// Retry — multiple status codes trigger retry
// ---------------------------------------------------------------------------

// Test_WithRetry_MultipleStatusCodes_ShouldRetryForEach verifies that any of the
// supplied status codes individually triggers a retry.
func (suite *HTTPRequestTestSuite) Test_WithRetry_MultipleStatusCodes_ShouldRetryForEach() {
	type ServerResp struct {
		Data string `json:"data"`
	}
	successResp := ServerResp{Data: "ok"}
	responses := []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusOK}
	callIndex := 0
	var expectedStatus int
	clientResp := ServerResp{}

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		code := responses[callIndex]
		callIndex++
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(code)
		if code == http.StatusOK {
			_ = json.NewEncoder(res).Encode(successResp)
		} else {
			_ = json.NewEncoder(res).Encode(ServerResp{})
		}
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithRetry(5, []int{500, 502}).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&expectedStatus).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, expectedStatus)
	suite.Equal(successResp, clientResp)
	suite.Equal(3, callIndex) // 500 → retry → 502 → retry → 200
}

// ---------------------------------------------------------------------------
// Retry — correct final-response binding (bug regression)
// ---------------------------------------------------------------------------

// Test_WithRetry_ResponseModelOnlyFromFinalAttempt verifies the bug fix:
// the caller's response struct must only contain data from the final (successful)
// attempt, not from any intermediate failing attempt.
func (suite *HTTPRequestTestSuite) Test_WithRetry_ResponseModelOnlyFromFinalAttempt() {
	type ServerResp struct {
		Data string `json:"data"`
	}
	finalResp := ServerResp{Data: "final-data"}
	callCount := 0
	var expectedStatus int
	clientResp := ServerResp{}

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			// First attempt returns 500 with different data
			res.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(res).Encode(ServerResp{Data: "error-data"})
		} else {
			// Second attempt (retry) returns 200 with the real data
			res.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(res).Encode(finalResp)
		}
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithRetry(1, []int{500}).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&expectedStatus).
		POST(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, expectedStatus)
	// Must equal the FINAL response, not the intermediate 500 body.
	suite.Equal(finalResp, clientResp)
	suite.Equal(2, callCount)
}

// ---------------------------------------------------------------------------
// Retry on different HTTP methods
// ---------------------------------------------------------------------------

// Test_WithRetry_OnGET_ShouldRetryAndSucceed confirms that retry works for GET.
func (suite *HTTPRequestTestSuite) Test_WithRetry_OnGET_ShouldRetryAndSucceed() {
	type ServerResp struct {
		Data string `json:"data"`
	}
	successResp := ServerResp{Data: "get-ok"}
	callCount := 0
	var status int
	clientResp := ServerResp{}

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		suite.Equal("GET", req.Method)
		res.Header().Set("Content-Type", "application/json")
		if callCount < 2 {
			res.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(res).Encode(ServerResp{})
		} else {
			res.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(res).Encode(successResp)
		}
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithRetry(2, []int{503}).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, status)
	suite.Equal(successResp, clientResp)
}

// Test_WithRetry_OnPUT_ShouldRetryAndSucceed confirms that retry works for PUT.
func (suite *HTTPRequestTestSuite) Test_WithRetry_OnPUT_ShouldRetryAndSucceed() {
	type ServerResp struct {
		Data string `json:"data"`
	}
	successResp := ServerResp{Data: "put-ok"}
	callCount := 0
	var status int
	clientResp := ServerResp{}

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		suite.Equal("PUT", req.Method)
		res.Header().Set("Content-Type", "application/json")
		if callCount < 2 {
			res.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(res).Encode(ServerResp{})
		} else {
			res.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(res).Encode(successResp)
		}
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithJson(successResp).
		WithRetry(2, []int{500}).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&status).
		PUT(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, status)
	suite.Equal(successResp, clientResp)
}

// Test_WithRetry_OnPATCH_ShouldRetryAndSucceed confirms that retry works for PATCH.
func (suite *HTTPRequestTestSuite) Test_WithRetry_OnPATCH_ShouldRetryAndSucceed() {
	type ServerResp struct {
		Data string `json:"data"`
	}
	successResp := ServerResp{Data: "patch-ok"}
	callCount := 0
	var status int
	clientResp := ServerResp{}

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		suite.Equal("PATCH", req.Method)
		res.Header().Set("Content-Type", "application/json")
		if callCount < 2 {
			res.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(res).Encode(ServerResp{})
		} else {
			res.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(res).Encode(successResp)
		}
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithJson(successResp).
		WithRetry(2, []int{502}).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&status).
		PATCH(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, status)
	suite.Equal(successResp, clientResp)
}

// Test_WithRetry_OnDELETE_ShouldRetryAndSucceed confirms that retry works for DELETE.
func (suite *HTTPRequestTestSuite) Test_WithRetry_OnDELETE_ShouldRetryAndSucceed() {
	callCount := 0
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		suite.Equal("DELETE", req.Method)
		if callCount < 2 {
			res.WriteHeader(http.StatusInternalServerError)
		} else {
			res.WriteHeader(http.StatusNoContent)
		}
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithRetry(2, []int{500}).
		GetResponseStatusCodeAs(&status).
		DELETE(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusNoContent, status)
	suite.Equal(2, callCount)
}

// ---------------------------------------------------------------------------
// WithRetry — edge cases
// ---------------------------------------------------------------------------

// Test_WithRetry_ZeroMaxRetries_ShouldNotRetry verifies that setting maxRetries=0
// disables retry entirely, even when the status code matches.
func (suite *HTTPRequestTestSuite) Test_WithRetry_ZeroMaxRetries_ShouldNotRetry() {
	callCount := 0
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.WriteHeader(http.StatusInternalServerError)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithRetry(0, []int{500}).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusInternalServerError, status)
	suite.Equal(1, callCount, "should not retry when maxRetries=0")
}

// Test_WithRetry_EmptyStatusCodes_ShouldNotRetry verifies that an empty status
// code list means retry is never triggered, regardless of maxRetries.
func (suite *HTTPRequestTestSuite) Test_WithRetry_EmptyStatusCodes_ShouldNotRetry() {
	callCount := 0
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.WriteHeader(http.StatusInternalServerError)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithRetry(5, []int{}). // no status codes → never retry
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusInternalServerError, status)
	suite.Equal(1, callCount, "should not retry when status code list is empty")
}

// Test_WithRetry_ExactMaxBoundary_ShouldRespectLimit verifies that the retry
// counter stops at exactly maxRetries and never overshoots.
func (suite *HTTPRequestTestSuite) Test_WithRetry_ExactMaxBoundary_ShouldRespectLimit() {
	const maxRetries = 3
	callCount := 0
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.WriteHeader(http.StatusInternalServerError) // always fail
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithRetry(maxRetries, []int{500}).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	// total calls = 1 initial + maxRetries
	suite.Equal(maxRetries+1, callCount, "call count must equal 1 initial + maxRetries")
	suite.Equal(http.StatusInternalServerError, status)
}

// ---------------------------------------------------------------------------
// WithCustomRequestModifier + retry
// ---------------------------------------------------------------------------

// Test_WithCustomRequestModifier_CalledOnEveryRetry verifies that the modifier
// function is applied on each retry attempt, not just the first request.
func (suite *HTTPRequestTestSuite) Test_WithCustomRequestModifier_CalledOnEveryRetry() {
	const traceHeader = "X-Retry-Count"
	modifierCallCount := 0
	serverCallCount := 0
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		serverCallCount++
		// The modifier must have run before each server call
		suite.NotEmpty(req.Header.Get(traceHeader))
		if serverCallCount < 3 {
			res.WriteHeader(http.StatusInternalServerError)
		} else {
			res.WriteHeader(http.StatusOK)
		}
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithCustomRequestModifier(func(r *http.Request) error {
			modifierCallCount++
			r.Header.Set(traceHeader, fmt.Sprintf("attempt-%d", modifierCallCount))
			return nil
		}).
		WithRetry(3, []int{500}).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, status)
	suite.Equal(3, serverCallCount)
	// The modifier must have been invoked once per attempt
	suite.Equal(3, modifierCallCount)
}

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

// Test_WithQueryParameters_ShouldEncodeMultipleParams verifies that multiple
// query parameters are all present and correctly encoded in the URL.
func (suite *HTTPRequestTestSuite) Test_WithQueryParameters_ShouldEncodeMultipleParams() {
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		suite.Equal("alice", req.URL.Query().Get("name"))
		suite.Equal("30", req.URL.Query().Get("age"))
		suite.Equal("admin", req.URL.Query().Get("role"))
		res.WriteHeader(http.StatusOK)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithQueryParameters(map[string]string{
			"name": "alice",
			"age":  "30",
			"role": "admin",
		}).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, status)
}

// ---------------------------------------------------------------------------
// Response headers
// ---------------------------------------------------------------------------

// Test_GetResponseHeadersAs_ShouldCaptureCustomHeader verifies that a custom
// header set by the server is available in the captured headers map.
func (suite *HTTPRequestTestSuite) Test_GetResponseHeadersAs_ShouldCaptureCustomHeader() {
	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("X-Request-ID", "abc-123")
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		_, _ = res.Write([]byte(`{}`))
	})
	defer testServer.Close()

	var headers map[string][]string
	var status int

	err := suite.restClient.NewRequest().
		GetResponseHeadersAs(&headers).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, status)
	suite.NotNil(headers)
	// http.Header.Get is case-insensitive and handles canonical form (X-Request-Id).
	suite.Equal("abc-123", http.Header(headers).Get("X-Request-ID"))
}

// ---------------------------------------------------------------------------
// XML request and response
// ---------------------------------------------------------------------------

// Test_WithXml_PUT_ShouldSucceedWithXmlResponse verifies that an XML body is
// sent correctly on a PUT and that an XML response is unmarshalled properly.
func (suite *HTTPRequestTestSuite) Test_WithXml_PUT_ShouldSucceedWithXmlResponse() {
	type Item struct {
		XMLName xml.Name `xml:"item"`
		Name    string   `xml:"name"`
		Value   int      `xml:"value"`
	}

	payload := Item{Name: "widget", Value: 42}
	var clientResp Item
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		suite.Equal("PUT", req.Method)
		suite.Contains(req.Header.Get("Content-Type"), "application/xml")
		res.Header().Set("Content-Type", "application/xml")
		res.WriteHeader(http.StatusOK)
		b, _ := xml.Marshal(payload)
		_, _ = res.Write(b)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithXml(payload).
		GetResponseAs(&clientResp).
		GetResponseStatusCodeAs(&status).
		PUT(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, status)
	suite.Equal(payload.Name, clientResp.Name)
	suite.Equal(payload.Value, clientResp.Value)
}

// ---------------------------------------------------------------------------
// Multiple cookies on a single request
// ---------------------------------------------------------------------------

// Test_AddCookies_MultipleValues_ShouldAllReachServer verifies that multiple
// cookies appended via AddCookies are all forwarded to the server.
func (suite *HTTPRequestTestSuite) Test_AddCookies_MultipleValues_ShouldAllReachServer() {
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		session, _ := req.Cookie("session")
		token, _ := req.Cookie("token")
		suite.NotNil(session)
		suite.NotNil(token)
		suite.Equal("sess-abc", session.Value)
		suite.Equal("tok-xyz", token.Value)
		res.WriteHeader(http.StatusOK)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		AddCookies(&http.Cookie{Name: "session", Value: "sess-abc"}).
		AddCookies(&http.Cookie{Name: "token", Value: "tok-xyz"}).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, status)
}

// ---------------------------------------------------------------------------
// Response with no Content-Type (plain text body)
// ---------------------------------------------------------------------------

// Test_GetResponseAs_String_PlainTextContentType verifies that even when the
// server sends text/plain, the body is captured correctly into a *string.
func (suite *HTTPRequestTestSuite) Test_GetResponseAs_String_PlainTextContentType() {
	rawBody := "hello, world"

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Content-Type", "text/plain")
		res.WriteHeader(http.StatusOK)
		_, _ = res.Write([]byte(rawBody))
	})
	defer testServer.Close()

	var body string
	err := suite.restClient.NewRequest().
		GetResponseAs(&body).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(rawBody, body)
}

// ---------------------------------------------------------------------------
// WithRetryAndBackoff — validates status-code-only targeting (no false trigger)
// ---------------------------------------------------------------------------

// Test_WithRetryAndBackoff_ShouldNotRetryWhenStatusNotInList verifies that
// a fixed-backoff retry setup does NOT retry when the actual status code is
// not in the retry list.
func (suite *HTTPRequestTestSuite) Test_WithRetryAndBackoff_ShouldNotRetryWhenStatusNotInList() {
	callCount := 0
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.WriteHeader(http.StatusBadRequest) // 400 is NOT in the retry list
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		WithRetryAndBackoff(3, []int{500, 503}, 1*time.Millisecond).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusBadRequest, status)
	suite.Equal(1, callCount, "must not retry on 400 when list contains only 500,503")
}

// ---------------------------------------------------------------------------
// WithRetryAndExponentialBackoff — validates exhaustion behaviour
// ---------------------------------------------------------------------------

// Test_WithRetryAndExponentialBackoff_AllAttemptsFailShouldReturnLastStatus verifies
// that when every attempt fails, the last server status is what the caller sees.
func (suite *HTTPRequestTestSuite) Test_WithRetryAndExponentialBackoff_AllAttemptsFailShouldReturnLastStatus() {
	const maxRetries = 2
	callCount := 0
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		callCount++
		res.WriteHeader(http.StatusBadGateway)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequestWithRetryAndExponentialBackoff(
		maxRetries, []int{502}, 1*time.Millisecond,
	).
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusBadGateway, status)
	suite.Equal(maxRetries+1, callCount)
}

// ---------------------------------------------------------------------------
// AddHeaders — multiple chained headers
// ---------------------------------------------------------------------------

// Test_AddHeaders_MultipleHeaders_ShouldAllReachServer confirms that chaining
// AddHeaders multiple times sends all headers to the server.
func (suite *HTTPRequestTestSuite) Test_AddHeaders_MultipleHeaders_ShouldAllReachServer() {
	var status int

	testServer := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		suite.Equal("app-v1", req.Header.Get("X-App-Version"))
		suite.Equal("req-999", req.Header.Get("X-Request-ID"))
		suite.Equal("tenant-42", req.Header.Get("X-Tenant-ID"))
		res.WriteHeader(http.StatusOK)
	})
	defer testServer.Close()

	err := suite.restClient.NewRequest().
		AddHeaders("X-App-Version", "app-v1").
		AddHeaders("X-Request-ID", "req-999").
		AddHeaders("X-Tenant-ID", "tenant-42").
		GetResponseStatusCodeAs(&status).
		GET(testServer.URL)

	suite.Nil(err)
	suite.Equal(http.StatusOK, status)
}

// ---------------------------------------------------------------------------
// Error() accessor
// ---------------------------------------------------------------------------

// Test_Error_ShouldReturnNilWhenNoError confirms Error() returns nil on a
// freshly created request with no builder errors.
func (suite *HTTPRequestTestSuite) Test_Error_ShouldReturnNilWhenNoError() {
	err := suite.restClient.NewRequest().Error()
	suite.Nil(err)
}

// Test_Error_ShouldReturnErrorAfterInvalidJson confirms Error() surfaces the
// JSON marshal error when WithJson is called with an un-marshalable value.
func (suite *HTTPRequestTestSuite) Test_Error_ShouldReturnErrorAfterInvalidJson() {
	err := suite.restClient.NewRequest().
		WithJson(map[string]interface{}{"ch": make(chan int)}).
		Error()

	suite.NotNil(err)
}

// Test_Error_ShouldReturnErrorAfterInvalidXml confirms Error() surfaces the
// XML marshal error when WithXml is called with an un-marshalable value.
func (suite *HTTPRequestTestSuite) Test_Error_ShouldReturnErrorAfterInvalidXml() {
	err := suite.restClient.NewRequest().
		WithXml(map[string]interface{}{"ch": make(chan int)}).
		Error()

	suite.NotNil(err)
}

// ---------------------------------------------------------------------------
// Chained method ordering (builder immutability)
// ---------------------------------------------------------------------------

// Test_BuilderImmutability_IndependentRequests verifies that two separately created
// requests do not share header state.
//
// NOTE: Because reqHeaders is a map (a reference type), requests that share a base
// via value-copy DO share the same underlying map. Callers must start from a fresh
// NewRequest() for each independent request if they need isolated headers.
func (suite *HTTPRequestTestSuite) Test_BuilderImmutability_IndependentRequests() {
	var statusA, statusB int

	serverA := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		suite.Equal("token-A", req.Header.Get("X-Token"))
		res.WriteHeader(http.StatusOK)
	})
	defer serverA.Close()

	serverB := suite.setupTestServer(func(res http.ResponseWriter, req *http.Request) {
		suite.Equal("token-B", req.Header.Get("X-Token"))
		res.WriteHeader(http.StatusAccepted)
	})
	defer serverB.Close()

	// Each request starts from a fresh NewRequest() to avoid sharing the header map.
	reqA := suite.restClient.NewRequest().
		AddHeaders("X-Token", "token-A").
		GetResponseStatusCodeAs(&statusA)

	reqB := suite.restClient.NewRequest().
		AddHeaders("X-Token", "token-B").
		GetResponseStatusCodeAs(&statusB)

	suite.Nil(reqA.GET(serverA.URL))
	suite.Nil(reqB.GET(serverB.URL))

	suite.Equal(http.StatusOK, statusA)
	suite.Equal(http.StatusAccepted, statusB)
}

// ---------------------------------------------------------------------------
// WithRetry — network error should not retry (only HTTP status codes trigger it)
// ---------------------------------------------------------------------------

// Test_WithRetry_ShouldNotRetryOnNetworkError verifies that a transport-level
// error (connection refused) is returned immediately without retry.
func (suite *HTTPRequestTestSuite) Test_WithRetry_ShouldNotRetryOnNetworkError() {
	// port 1 is always refused — no server is set up
	err := suite.restClient.NewRequest().
		WithRetry(5, []int{500}).
		GET("http://127.0.0.1:1")

	suite.NotNil(err, "network error should be returned even when retry is configured")
}

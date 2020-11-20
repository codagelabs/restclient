package request

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/suite"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func (suite HTTPRequestTestSuite) setupTestServer(handleFunc func(res http.ResponseWriter, req *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(handleFunc))
}

func (suite HTTPRequestTestSuite) TestTestPostRequestWithXmlBodyShouldSuccessWithXmlResponse() {

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

func (suite HTTPRequestTestSuite) TestTestPostRequestWithXmlBodyShouldReturnAnErrorStatusNotFound() {

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

func (suite HTTPRequestTestSuite) TestTestPostRequestWithXmlBodyShouldReturnAnErrorWhenErrorInRequestParsing() {

	serverResponse := map[string]interface{}{
		"test": make(chan int, 0),
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

func (suite HTTPRequestTestSuite) Test_PostRequestWithJsonBodyShouldRetunAnErrorResponseNotFound() {

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

func (suite HTTPRequestTestSuite) Test_PostRequestWithJsonBodyShouldSuccess() {

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

func (suite HTTPRequestTestSuite) Test_PostRequestWithJsonBodyShouldSuccessWithResponseHeader() {

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

func (suite HTTPRequestTestSuite) Test_PostRequestWithJsonBodyAndOauthShouldSuccess() {

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

func (suite HTTPRequestTestSuite) Test_PostRequestWithJsonBodyAndOauthShouldReturnErrorStatusUnauthorized() {

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

func (suite HTTPRequestTestSuite) Test_PatchRequestWithJsonBodyShouldSuccess() {

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

func (suite HTTPRequestTestSuite) TestPostRequestFormURLEncodedShouldReturnJsonDataWithSuccessResponse() {

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

func (suite HTTPRequestTestSuite) TestPostRequestFormURLEncodedShouldReturnJsonDataWithShouldReturnAnErrorContentTypeNotSupported() {

	formData := map[string]interface{}{
		"name": map[string]string{
			"test": "test",
		},
	}
	err := suite.restClient.NewRequest().WithFromURLEncoded(formData).Error()
	suite.Equal(errors.New("Invalid request type: only multipart string is supported "), err)

}

func (suite HTTPRequestTestSuite) TestTestPostRequestWithJsonBodyAndWithContextShouldSuccess() {

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

func (suite HTTPRequestTestSuite) Test_PostRequestWithJsonBodyAndAddCookiesShouldSuccess() {

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

func (suite HTTPRequestTestSuite) Test_PostRequestShouldRetrievesTestCookiesWhenSuccess() {

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

func (suite HTTPRequestTestSuite) Test_DeleteRequestWithUrlQueryParameterShouldSuccess() {
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

func (suite HTTPRequestTestSuite) Test_GetRequestWithUrlQueryParameterShouldSuccess() {

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

func (suite HTTPRequestTestSuite) TestTestPostRequestShouldRetrievesTestCookiesShouldBeNilIfServersSuccess() {

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

func (suite HTTPRequestTestSuite) TestTestPostRequestWithJsonBodyAndAddHeadersShouldSuccess() {

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

func (suite HTTPRequestTestSuite) TestTestPostRequestWithJsonBodyShouldReturnAnErrorNotFound() {

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

func (suite HTTPRequestTestSuite) TestTestPostRequestWithJsonAndBasicAuthBodyShouldSuccess() {
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

func (suite HTTPRequestTestSuite) TestTestPostRequestWithJsonAndBasicAuthBodyShouldReturnAnUnAuthorizedError() {
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

func (suite HTTPRequestTestSuite) TestTestPostRequestWithJsonAndJWtAuthShouldSuccess() {
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

func (suite HTTPRequestTestSuite) TestTestPostRequestWithJsonAndJWtAuthShouldReturnStatusUnAuthorized() {
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

func (suite HTTPRequestTestSuite) TestTestPutRequestWithJsonAndJWtAuthShouldSuccess() {
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

func (suite HTTPRequestTestSuite) TestTestPutRequestWithJsonAndJWtAuthShouldReturnStatusUnAuthorized() {
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

func (suite HTTPRequestTestSuite) TestWithXml_ShouldReturnAnErrorWhenInvalidDataForMarshal() {
	test := map[string]interface{}{
		"test": make(chan int, 0),
	}
	err := suite.restClient.NewRequest().WithXml(test).Error()
	suite.NotNil(err)
}
func (suite HTTPRequestTestSuite) TestWithJson_ShouldReturnAnErrorWhenInvalidDataForMarshal() {
	test := map[string]interface{}{
		"test": make(chan int, 0),
	}
	err := suite.restClient.NewRequest().WithJson(test).Error()
	suite.NotNil(err)
}

func (suite HTTPRequestTestSuite) createJwtTestToken(userid uint64) (string, error) {
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

func (suite HTTPRequestTestSuite) verifyJwtTestToken(r *http.Request) (*jwt.Token, error) {
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

func (suite HTTPRequestTestSuite) extractJwtToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

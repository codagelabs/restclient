package main

import (
	"github.com/codagelabs/restclient/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"

	"testing"
)

type downstreamServiceTestSuite struct {
	suite.Suite
	mockCtrl          *gomock.Controller
	restClient        *mocks.MockRestClient
	httpRequest       *mocks.MockHTTPRequest
	downstreamService DownstreamService
}

func TestDownstreamServiceTestSuite(t *testing.T) {
	suite.Run(t, new(downstreamServiceTestSuite))
}

func (suite *downstreamServiceTestSuite) SetupTest() {
	suite.mockCtrl = gomock.NewController(suite.T())
	suite.restClient = mocks.NewMockRestClient(suite.mockCtrl)
	suite.httpRequest = mocks.NewMockHTTPRequest(suite.mockCtrl)
	suite.downstreamService = NewDownstreamService(suite.restClient)

}

func (suite *downstreamServiceTestSuite) TearDownTest() {

}

func (suite downstreamServiceTestSuite) TestDownstreamService_ExecRequestShouldReturnSuccess() {
	expected := &respModel{ErrorMessage: "something-went-wrong", Status: "200"}
	suite.restClient.EXPECT().NewRequest().Return(suite.httpRequest)
	suite.httpRequest.EXPECT().GetResponseAs(gomock.Any()).Return(suite.httpRequest).Do(func(expected *respModel) {
		expected.ErrorMessage = "something-went-wrong"
		expected.Status = "200"
	})
	suite.httpRequest.EXPECT().GET(gomock.Any()).Return(nil)
	request, err := suite.downstreamService.ExecRequest()
	suite.Nil(err)
	suite.Equal(*expected, request)
}

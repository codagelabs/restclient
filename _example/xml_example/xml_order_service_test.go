package main

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/codagelabs/restclient/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
)

type orderServiceTestSuite struct {
	suite.Suite
	ctrl        *gomock.Controller
	mockClient  *mocks.MockRestClient
	mockRequest *mocks.MockHTTPRequest
	svc         OrderService
}

func TestOrderServiceSuite(t *testing.T) {
	suite.Run(t, new(orderServiceTestSuite))
}

func (s *orderServiceTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockClient = mocks.NewMockRestClient(s.ctrl)
	s.mockRequest = mocks.NewMockHTTPRequest(s.ctrl)
	s.svc = NewOrderService(s.mockClient, "secret")
}

func (s *orderServiceTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

// ── GetOrder ─────────────────────────────────────────────────────────────────

// TestGetOrder_Success verifies that an XML response is bound and returned.
func (s *orderServiceTestSuite) TestGetOrder_Success() {
	want := Order{ID: 42, Product: "Widget", Quantity: 10, TotalCost: 99.9}

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithBasicAuth("api-user", "secret").Return(s.mockRequest)
	s.mockRequest.EXPECT().AddHeaders("Accept", "application/xml").Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseAs(gomock.Any()).
		DoAndReturn(func(dest *Order) interface{} {
			*dest = want
			return s.mockRequest
		})
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(func(p *int) { *p = http.StatusOK }).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(nil)

	got, err := s.svc.GetOrder(context.Background(), 42)

	s.Nil(err)
	s.Equal(want, got)
}

// TestGetOrder_NotFound verifies that a 404 is converted to an error.
func (s *orderServiceTestSuite) TestGetOrder_NotFound() {
	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithBasicAuth("api-user", "secret").Return(s.mockRequest)
	s.mockRequest.EXPECT().AddHeaders("Accept", "application/xml").Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(func(p *int) { *p = http.StatusNotFound }).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(nil)

	_, err := s.svc.GetOrder(context.Background(), 99)

	s.NotNil(err)
	s.Contains(err.Error(), "not found")
}

// TestGetOrder_TransportError verifies a low-level error is propagated.
func (s *orderServiceTestSuite) TestGetOrder_TransportError() {
	netErr := errors.New("connection timeout")

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithBasicAuth(gomock.Any(), gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().AddHeaders(gomock.Any(), gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseStatusCodeAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(netErr)

	_, err := s.svc.GetOrder(context.Background(), 1)

	s.NotNil(err)
	s.ErrorIs(err, netErr)
}

// ── CreateOrder ───────────────────────────────────────────────────────────────

// TestCreateOrder_Success verifies that a POST with XML body returns the created order.
func (s *orderServiceTestSuite) TestCreateOrder_Success() {
	payload := CreateOrderRequest{Product: "Gadget", Quantity: 5}
	want := Order{ID: 100, Product: "Gadget", Quantity: 5, TotalCost: 49.95}

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithBasicAuth("api-user", "secret").Return(s.mockRequest)
	s.mockRequest.EXPECT().WithXml(payload).Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseAs(gomock.Any()).
		DoAndReturn(func(dest *Order) interface{} {
			*dest = want
			return s.mockRequest
		})
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(func(p *int) { *p = http.StatusCreated }).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().POST(gomock.Any()).Return(nil)

	got, err := s.svc.CreateOrder(context.Background(), payload)

	s.Nil(err)
	s.Equal(want, got)
}

// TestCreateOrder_TransportError verifies network errors are surfaced.
func (s *orderServiceTestSuite) TestCreateOrder_TransportError() {
	netErr := errors.New("write: broken pipe")
	payload := CreateOrderRequest{Product: "Widget", Quantity: 1}

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithBasicAuth(gomock.Any(), gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithXml(payload).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseStatusCodeAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().POST(gomock.Any()).Return(netErr)

	_, err := s.svc.CreateOrder(context.Background(), payload)

	s.NotNil(err)
	s.ErrorIs(err, netErr)
}

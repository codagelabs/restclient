// Package main contains unit tests for UserService that use GoMock to mock
// both RestClient and HTTPRequest — no real network calls are made.
//
// # How mocks work in this package
//
// The mocks package provides two generated mocks:
//   - MockRestClient  — replaces request.RestClient
//   - MockHTTPRequest — replaces the fluent request chain returned by NewRequest()
//
// The typical pattern for every test is:
//
//  1. Create a gomock controller:
//     ctrl := gomock.NewController(t)
//
//  2. Instantiate the mocks:
//     mockClient  := mocks.NewMockRestClient(ctrl)
//     mockRequest := mocks.NewMockHTTPRequest(ctrl)
//
//  3. Wire expectations using EXPECT():
//     mockClient.EXPECT().NewRequest().Return(mockRequest)
//     mockRequest.EXPECT().WithJson(gomock.Any()).Return(mockRequest)
//     mockRequest.EXPECT().POST(gomock.Any()).Return(nil)
//
//  4. Inject the mock into the service under test:
//     svc := NewUserService(mockClient, "token")
//
//  5. Call the method and assert results.
//
// Use .Do() to capture arguments and simulate response population:
//
//	mockRequest.EXPECT().GetResponseAs(gomock.Any()).
//	    DoAndReturn(func(dest *User) request.HTTPRequest {
//	        *dest = User{ID: 1, Name: "Alice"}
//	        return mockRequest
//	    })
package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/codagelabs/restclient/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
)

// ────────────────────────────────────────────────────────────────────────────
// Test suite setup
// ────────────────────────────────────────────────────────────────────────────

// userServiceTestSuite groups all UserService tests. It is run by
// TestUserServiceSuite via testify/suite which calls SetupTest before
// every individual test, giving each test a clean set of mocks.
type userServiceTestSuite struct {
	suite.Suite
	ctrl        *gomock.Controller
	mockClient  *mocks.MockRestClient
	mockRequest *mocks.MockHTTPRequest
	svc         UserService
}

// TestUserServiceSuite is the entry-point registered with go test.
func TestUserServiceSuite(t *testing.T) {
	suite.Run(t, new(userServiceTestSuite))
}

// SetupTest is called automatically before each test method.
// It creates fresh mocks and a new service instance.
func (s *userServiceTestSuite) SetupTest() {
	s.ctrl = gomock.NewController(s.T())
	s.mockClient = mocks.NewMockRestClient(s.ctrl)
	s.mockRequest = mocks.NewMockHTTPRequest(s.ctrl)
	s.svc = NewUserService(s.mockClient, "test-token")
}

// TearDownTest is called after each test. gomock.Controller.Finish() verifies
// that all expected calls were actually made (catches missing calls).
func (s *userServiceTestSuite) TearDownTest() {
	s.ctrl.Finish()
}

// ────────────────────────────────────────────────────────────────────────────
// Helper — populate a status code pointer via Do()
// ────────────────────────────────────────────────────────────────────────────

func setStatus(code int) func(*int) {
	return func(p *int) { *p = code }
}

// ────────────────────────────────────────────────────────────────────────────
// GetUser tests
// ────────────────────────────────────────────────────────────────────────────

// TestGetUser_Success verifies the happy path: 200 OK returns a populated User.
func (s *userServiceTestSuite) TestGetUser_Success() {
	want := User{ID: 1, Name: "Alice", Email: "alice@example.com"}

	// The service calls: NewRequest() → WithContext → WithJWTAuth → AddHeaders
	//                    → GetResponseAs → GetResponseStatusCodeAs → GET
	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().AddHeaders("Accept", "application/json").Return(s.mockRequest)

	// Use DoAndReturn to populate the destination pointer, simulating real HTTP binding.
	s.mockRequest.EXPECT().
		GetResponseAs(gomock.Any()).
		DoAndReturn(func(dest *User) interface{} {
			*dest = want
			return s.mockRequest
		})

	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusOK)).
		Return(s.mockRequest)

	s.mockRequest.EXPECT().GET(gomock.Any()).Return(nil)

	got, err := s.svc.GetUser(context.Background(), 1)

	s.Nil(err)
	s.Equal(want, got)
}

// TestGetUser_NotFound verifies that a 404 response is converted to an error.
func (s *userServiceTestSuite) TestGetUser_NotFound() {
	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().AddHeaders("Accept", "application/json").Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusNotFound)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(nil)

	_, err := s.svc.GetUser(context.Background(), 99)

	s.NotNil(err)
	s.Contains(err.Error(), "not found")
}

// TestGetUser_UnexpectedStatus verifies non-200/404 status codes cause an error.
func (s *userServiceTestSuite) TestGetUser_UnexpectedStatus() {
	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().AddHeaders("Accept", "application/json").Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusInternalServerError)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(nil)

	_, err := s.svc.GetUser(context.Background(), 1)

	s.NotNil(err)
	s.Contains(err.Error(), "unexpected status 500")
}

// TestGetUser_TransportError verifies that a network-level error bubbles up.
func (s *userServiceTestSuite) TestGetUser_TransportError() {
	transportErr := errors.New("connection refused")

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().AddHeaders("Accept", "application/json").Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseStatusCodeAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(transportErr)

	_, err := s.svc.GetUser(context.Background(), 1)

	s.NotNil(err)
	s.ErrorIs(err, transportErr)
}

// ────────────────────────────────────────────────────────────────────────────
// ListUsers tests
// ────────────────────────────────────────────────────────────────────────────

// TestListUsers_Success verifies pagination query params are passed and the
// response slice is returned correctly.
func (s *userServiceTestSuite) TestListUsers_Success() {
	want := []User{
		{ID: 1, Name: "Alice"},
		{ID: 2, Name: "Bob"},
	}

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().
		WithQueryParameters(map[string]string{"page": "1", "limit": "20"}).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseAs(gomock.Any()).
		DoAndReturn(func(dest *[]User) interface{} {
			*dest = want
			return s.mockRequest
		})
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusOK)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(nil)

	got, err := s.svc.ListUsers(context.Background(), 1, 20)

	s.Nil(err)
	s.Equal(want, got)
}

// TestListUsers_ServerError verifies that a 500 from the server is reported.
func (s *userServiceTestSuite) TestListUsers_ServerError() {
	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().WithQueryParameters(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusInternalServerError)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(nil)

	_, err := s.svc.ListUsers(context.Background(), 1, 20)

	s.NotNil(err)
	s.Contains(err.Error(), "unexpected status 500")
}

// ────────────────────────────────────────────────────────────────────────────
// CreateUser tests
// ────────────────────────────────────────────────────────────────────────────

// TestCreateUser_Success verifies that the JSON payload is forwarded and the
// created resource is returned.
func (s *userServiceTestSuite) TestCreateUser_Success() {
	payload := CreateUserRequest{Name: "Carol", Email: "carol@example.com"}
	want := User{ID: 3, Name: "Carol", Email: "carol@example.com"}

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJson(payload).Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseAs(gomock.Any()).
		DoAndReturn(func(dest *User) interface{} {
			*dest = want
			return s.mockRequest
		})
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusCreated)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().POST(gomock.Any()).Return(nil)

	got, err := s.svc.CreateUser(context.Background(), payload)

	s.Nil(err)
	s.Equal(want, got)
}

// TestCreateUser_ValidationError verifies a 422 from the server is an error.
func (s *userServiceTestSuite) TestCreateUser_ValidationError() {
	payload := CreateUserRequest{Name: "", Email: "bad-email"}

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJson(payload).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusUnprocessableEntity)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().POST(gomock.Any()).Return(nil)

	_, err := s.svc.CreateUser(context.Background(), payload)

	s.NotNil(err)
	s.Contains(err.Error(), "unexpected status 422")
}

// TestCreateUser_TransportError verifies that a low-level error is returned.
func (s *userServiceTestSuite) TestCreateUser_TransportError() {
	netErr := errors.New("dial tcp: connection reset by peer")
	payload := CreateUserRequest{Name: "Dave", Email: "dave@example.com"}

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJson(payload).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseStatusCodeAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().POST(gomock.Any()).Return(netErr)

	_, err := s.svc.CreateUser(context.Background(), payload)

	s.NotNil(err)
	s.ErrorIs(err, netErr)
}

// ────────────────────────────────────────────────────────────────────────────
// UpdateUser tests
// ────────────────────────────────────────────────────────────────────────────

// TestUpdateUser_Success verifies a PUT with JSON payload returns the updated record.
func (s *userServiceTestSuite) TestUpdateUser_Success() {
	payload := UpdateUserRequest{Name: "Alice Updated"}
	want := User{ID: 1, Name: "Alice Updated", Email: "alice@example.com"}

	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJson(payload).Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseAs(gomock.Any()).
		DoAndReturn(func(dest *User) interface{} {
			*dest = want
			return s.mockRequest
		})
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusOK)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().PUT(gomock.Any()).Return(nil)

	got, err := s.svc.UpdateUser(context.Background(), 1, payload)

	s.Nil(err)
	s.Equal(want, got)
}

// ────────────────────────────────────────────────────────────────────────────
// DeleteUser tests
// ────────────────────────────────────────────────────────────────────────────

// TestDeleteUser_Success verifies a DELETE returning 204 causes no error.
func (s *userServiceTestSuite) TestDeleteUser_Success() {
	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusNoContent)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().DELETE(gomock.Any()).Return(nil)

	err := s.svc.DeleteUser(context.Background(), 1)
	s.Nil(err)
}

// TestDeleteUser_NotFound verifies that a 404 causes a meaningful error.
func (s *userServiceTestSuite) TestDeleteUser_NotFound() {
	s.mockClient.EXPECT().NewRequest().Return(s.mockRequest)
	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusNotFound)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().DELETE(gomock.Any()).Return(nil)

	err := s.svc.DeleteUser(context.Background(), 999)
	s.NotNil(err)
	s.Contains(err.Error(), "unexpected status 404")
}

// ────────────────────────────────────────────────────────────────────────────
// GetUserWithRetry tests — mocking the retry constructor
// ────────────────────────────────────────────────────────────────────────────

// TestGetUserWithRetry_Success mocks NewRequestWithRetryAndExponentialBackoff
// and verifies the retry-enabled path works on success.
func (s *userServiceTestSuite) TestGetUserWithRetry_Success() {
	want := User{ID: 5, Name: "Eve"}

	// Note: the service uses NewRequestWithRetryAndExponentialBackoff, not NewRequest.
	s.mockClient.EXPECT().
		NewRequestWithRetryAndExponentialBackoff(
			uint(3),
			[]int{500, 502, 503},
			200*time.Millisecond,
		).
		Return(s.mockRequest)

	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseAs(gomock.Any()).
		DoAndReturn(func(dest *User) interface{} {
			*dest = want
			return s.mockRequest
		})
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusOK)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(nil)

	got, err := s.svc.GetUserWithRetry(context.Background(), 5)

	s.Nil(err)
	s.Equal(want, got)
}

// TestGetUserWithRetry_UserNotFound verifies 404 converts to an error even
// when the retry constructor is used.
func (s *userServiceTestSuite) TestGetUserWithRetry_UserNotFound() {
	s.mockClient.EXPECT().
		NewRequestWithRetryAndExponentialBackoff(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(s.mockRequest)

	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().
		GetResponseStatusCodeAs(gomock.Any()).
		Do(setStatus(http.StatusNotFound)).
		Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(nil)

	_, err := s.svc.GetUserWithRetry(context.Background(), 99)

	s.NotNil(err)
	s.Contains(err.Error(), "not found")
}

// TestGetUserWithRetry_NetworkError verifies transport-level errors are propagated.
func (s *userServiceTestSuite) TestGetUserWithRetry_NetworkError() {
	netErr := errors.New("i/o timeout")

	s.mockClient.EXPECT().
		NewRequestWithRetryAndExponentialBackoff(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(s.mockRequest)

	s.mockRequest.EXPECT().WithContext(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().WithJWTAuth("test-token").Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GetResponseStatusCodeAs(gomock.Any()).Return(s.mockRequest)
	s.mockRequest.EXPECT().GET(gomock.Any()).Return(netErr)

	_, err := s.svc.GetUserWithRetry(context.Background(), 1)

	s.NotNil(err)
	s.ErrorIs(err, netErr)
}

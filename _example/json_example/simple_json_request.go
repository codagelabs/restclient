// Package main demonstrates how to build a real-world service layer on top of
// the restclient library, covering JSON / XML requests, auth, retries, and
// how to accept a RestClient via dependency injection so the service stays
// fully unit-testable without hitting the network.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/codagelabs/restclient/request"
)

// ────────────────────────────────────────────────────────────────────────────
// Domain models
// ────────────────────────────────────────────────────────────────────────────

// User represents a user record returned by the downstream API.
type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// CreateUserRequest is the payload sent when creating a new user.
type CreateUserRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// UpdateUserRequest is the payload sent when updating an existing user.
type UpdateUserRequest struct {
	Name string `json:"name"`
}

// APIError is the error envelope returned by the downstream API.
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.Code, e.Message)
}

// ────────────────────────────────────────────────────────────────────────────
// Service interface — what callers depend on
// ────────────────────────────────────────────────────────────────────────────

const baseURL = "https://api.example.com"

// UserService exposes CRUD operations backed by an HTTP API.
type UserService interface {
	GetUser(ctx context.Context, id int) (User, error)
	ListUsers(ctx context.Context, page, limit int) ([]User, error)
	CreateUser(ctx context.Context, req CreateUserRequest) (User, error)
	UpdateUser(ctx context.Context, id int, req UpdateUserRequest) (User, error)
	DeleteUser(ctx context.Context, id int) error
	GetUserWithRetry(ctx context.Context, id int) (User, error)
}

// ────────────────────────────────────────────────────────────────────────────
// Service implementation
// ────────────────────────────────────────────────────────────────────────────

type userService struct {
	client   request.RestClient
	apiToken string
}

// NewUserService creates a UserService. Pass any request.RestClient —
// in production pass request.NewRestClient(&http.Client{...}),
// in tests pass a mock.
func NewUserService(client request.RestClient, apiToken string) UserService {
	return &userService{client: client, apiToken: apiToken}
}

// GetUser fetches a single user by ID.
func (s *userService) GetUser(ctx context.Context, id int) (User, error) {
	var user User
	var statusCode int

	url := fmt.Sprintf("%s/users/%d", baseURL, id)
	err := s.client.NewRequest().
		WithContext(ctx).
		WithJWTAuth(s.apiToken).
		AddHeaders("Accept", "application/json").
		GetResponseAs(&user).
		GetResponseStatusCodeAs(&statusCode).
		GET(url)

	if err != nil {
		return User{}, fmt.Errorf("GetUser: transport error: %w", err)
	}
	if statusCode == http.StatusNotFound {
		return User{}, fmt.Errorf("GetUser: user %d not found", id)
	}
	if statusCode != http.StatusOK {
		return User{}, fmt.Errorf("GetUser: unexpected status %d", statusCode)
	}
	return user, nil
}

// ListUsers fetches a paginated list of users.
func (s *userService) ListUsers(ctx context.Context, page, limit int) ([]User, error) {
	var users []User
	var statusCode int

	err := s.client.NewRequest().
		WithContext(ctx).
		WithJWTAuth(s.apiToken).
		WithQueryParameters(map[string]string{
			"page":  fmt.Sprintf("%d", page),
			"limit": fmt.Sprintf("%d", limit),
		}).
		GetResponseAs(&users).
		GetResponseStatusCodeAs(&statusCode).
		GET(baseURL + "/users")

	if err != nil {
		return nil, fmt.Errorf("ListUsers: transport error: %w", err)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("ListUsers: unexpected status %d", statusCode)
	}
	return users, nil
}

// CreateUser posts a new user and returns the created record.
func (s *userService) CreateUser(ctx context.Context, req CreateUserRequest) (User, error) {
	var created User
	var statusCode int

	err := s.client.NewRequest().
		WithContext(ctx).
		WithJWTAuth(s.apiToken).
		WithJson(req).
		GetResponseAs(&created).
		GetResponseStatusCodeAs(&statusCode).
		POST(baseURL + "/users")

	if err != nil {
		return User{}, fmt.Errorf("CreateUser: transport error: %w", err)
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return User{}, fmt.Errorf("CreateUser: unexpected status %d", statusCode)
	}
	return created, nil
}

// UpdateUser modifies an existing user record.
func (s *userService) UpdateUser(ctx context.Context, id int, req UpdateUserRequest) (User, error) {
	var updated User
	var statusCode int

	url := fmt.Sprintf("%s/users/%d", baseURL, id)
	err := s.client.NewRequest().
		WithContext(ctx).
		WithJWTAuth(s.apiToken).
		WithJson(req).
		GetResponseAs(&updated).
		GetResponseStatusCodeAs(&statusCode).
		PUT(url)

	if err != nil {
		return User{}, fmt.Errorf("UpdateUser: transport error: %w", err)
	}
	if statusCode != http.StatusOK {
		return User{}, fmt.Errorf("UpdateUser: unexpected status %d", statusCode)
	}
	return updated, nil
}

// DeleteUser removes a user by ID.
func (s *userService) DeleteUser(ctx context.Context, id int) error {
	var statusCode int

	url := fmt.Sprintf("%s/users/%d", baseURL, id)
	err := s.client.NewRequest().
		WithContext(ctx).
		WithJWTAuth(s.apiToken).
		GetResponseStatusCodeAs(&statusCode).
		DELETE(url)

	if err != nil {
		return fmt.Errorf("DeleteUser: transport error: %w", err)
	}
	if statusCode != http.StatusNoContent && statusCode != http.StatusOK {
		return fmt.Errorf("DeleteUser: unexpected status %d", statusCode)
	}
	return nil
}

// GetUserWithRetry fetches a user and automatically retries on 500/502/503
// using exponential backoff, making the call resilient to transient failures.
func (s *userService) GetUserWithRetry(ctx context.Context, id int) (User, error) {
	var user User
	var statusCode int

	url := fmt.Sprintf("%s/users/%d", baseURL, id)
	err := s.client.NewRequestWithRetryAndExponentialBackoff(
		3,                    // max 3 retries
		[]int{500, 502, 503}, // retry on these status codes
		200*time.Millisecond, // initial backoff (doubles each attempt)
	).
		WithContext(ctx).
		WithJWTAuth(s.apiToken).
		GetResponseAs(&user).
		GetResponseStatusCodeAs(&statusCode).
		GET(url)

	if err != nil {
		return User{}, fmt.Errorf("GetUserWithRetry: %w", err)
	}
	if statusCode == http.StatusNotFound {
		return User{}, errors.New("GetUserWithRetry: user not found")
	}
	return user, nil
}

// ────────────────────────────────────────────────────────────────────────────
// main — wiring everything together for a quick smoke-test run
// ────────────────────────────────────────────────────────────────────────────

func main() {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	restClient := request.NewRestClient(httpClient)

	svc := NewUserService(restClient, "my-api-token")
	ctx := context.Background()

	// GET a user
	user, err := svc.GetUser(ctx, 1)
	if err != nil {
		fmt.Println("GetUser error:", err)
	} else {
		fmt.Printf("GetUser: %+v\n", user)
	}

	// POST a new user
	newUser, err := svc.CreateUser(ctx, CreateUserRequest{
		Name:  "Alice",
		Email: "alice@example.com",
	})
	if err != nil {
		fmt.Println("CreateUser error:", err)
	} else {
		fmt.Printf("CreateUser: %+v\n", newUser)
	}
}

// Package main demonstrates how to build a resilient notification service that
// retries transient HTTP failures using fixed and exponential backoff strategies.
package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/codagelabs/restclient/request"
)

// ────────────────────────────────────────────────────────────────────────────
// Domain models
// ────────────────────────────────────────────────────────────────────────────

// Notification is the payload sent to the notification API.
type Notification struct {
	UserID  int    `json:"userId"`
	Message string `json:"message"`
	Channel string `json:"channel"` // "email" | "sms" | "push"
}

// NotificationResponse is the API response after delivering a notification.
type NotificationResponse struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ────────────────────────────────────────────────────────────────────────────
// Service
// ────────────────────────────────────────────────────────────────────────────

const notifBase = "https://notify.example.com"

// NotificationService sends notifications with built-in retry resilience.
type NotificationService interface {
	// Send sends a notification with no retry.
	Send(ctx context.Context, n Notification) (NotificationResponse, error)

	// SendWithFixedBackoff retries on 5xx with a constant delay between attempts.
	SendWithFixedBackoff(ctx context.Context, n Notification) (NotificationResponse, error)

	// SendWithExponentialBackoff retries on 5xx with exponentially growing delays.
	SendWithExponentialBackoff(ctx context.Context, n Notification) (NotificationResponse, error)
}

type notificationService struct {
	client request.RestClient
	token  string
}

// NewNotificationService constructs the service. Inject a real or mock RestClient.
func NewNotificationService(client request.RestClient, token string) NotificationService {
	return &notificationService{client: client, token: token}
}

// Send fires the notification exactly once.
func (s *notificationService) Send(ctx context.Context, n Notification) (NotificationResponse, error) {
	var resp NotificationResponse
	var status int

	err := s.client.NewRequest().
		WithContext(ctx).
		WithJWTAuth(s.token).
		WithJson(n).
		GetResponseAs(&resp).
		GetResponseStatusCodeAs(&status).
		POST(notifBase + "/send")

	if err != nil {
		return NotificationResponse{}, fmt.Errorf("Send: %w", err)
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusAccepted {
		return NotificationResponse{}, fmt.Errorf("Send: unexpected status %d", status)
	}
	return resp, nil
}

// SendWithFixedBackoff retries up to 3 times with a 1-second pause between
// attempts when the server returns 500, 502, or 503.
func (s *notificationService) SendWithFixedBackoff(ctx context.Context, n Notification) (NotificationResponse, error) {
	var resp NotificationResponse
	var status int

	err := s.client.NewRequestWithRetryAndBackoff(
		3,
		[]int{500, 502, 503},
		1*time.Second,
	).
		WithContext(ctx).
		WithJWTAuth(s.token).
		WithJson(n).
		GetResponseAs(&resp).
		GetResponseStatusCodeAs(&status).
		POST(notifBase + "/send")

	if err != nil {
		return NotificationResponse{}, fmt.Errorf("SendWithFixedBackoff: %w", err)
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusAccepted {
		return NotificationResponse{}, fmt.Errorf("SendWithFixedBackoff: unexpected status %d", status)
	}
	return resp, nil
}

// SendWithExponentialBackoff retries up to 5 times with exponential delay starting
// at 500 ms — ideal for high-traffic environments to avoid thundering-herd.
func (s *notificationService) SendWithExponentialBackoff(ctx context.Context, n Notification) (NotificationResponse, error) {
	var resp NotificationResponse
	var status int

	err := s.client.NewRequestWithRetryAndExponentialBackoff(
		5,
		[]int{500, 502, 503},
		500*time.Millisecond,
	).
		WithContext(ctx).
		WithJWTAuth(s.token).
		WithJson(n).
		GetResponseAs(&resp).
		GetResponseStatusCodeAs(&status).
		POST(notifBase + "/send")

	if err != nil {
		return NotificationResponse{}, fmt.Errorf("SendWithExponentialBackoff: %w", err)
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusAccepted {
		return NotificationResponse{}, fmt.Errorf("SendWithExponentialBackoff: unexpected status %d", status)
	}
	return resp, nil
}

// ────────────────────────────────────────────────────────────────────────────
// main
// ────────────────────────────────────────────────────────────────────────────

func main() {
	client := request.NewRestClient(&http.Client{Timeout: 15 * time.Second})
	svc := NewNotificationService(client, "my-token")
	ctx := context.Background()

	notif := Notification{
		UserID:  42,
		Message: "Your order has shipped!",
		Channel: "email",
	}

	// Try the resilient path first.
	resp, err := svc.SendWithExponentialBackoff(ctx, notif)
	if err != nil {
		fmt.Println("notification failed:", err)
		return
	}
	fmt.Printf("Notification sent: id=%s status=%s\n", resp.ID, resp.Status)
}

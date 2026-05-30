// Package main demonstrates how to build an order service that calls a
// downstream XML API. The pattern is identical to the JSON example but the
// payload and response use encoding/xml tags.
package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/codagelabs/restclient/request"
)

// ────────────────────────────────────────────────────────────────────────────
// Domain models (XML-tagged)
// ────────────────────────────────────────────────────────────────────────────

// Order represents an order record returned by the downstream XML API.
type Order struct {
	XMLName   xml.Name `xml:"order"`
	ID        int      `xml:"id"`
	Product   string   `xml:"product"`
	Quantity  int      `xml:"quantity"`
	TotalCost float64  `xml:"totalCost"`
}

// CreateOrderRequest is the XML payload sent to create an order.
type CreateOrderRequest struct {
	XMLName  xml.Name `xml:"createOrder"`
	Product  string   `xml:"product"`
	Quantity int      `xml:"quantity"`
}

// ────────────────────────────────────────────────────────────────────────────
// Service
// ────────────────────────────────────────────────────────────────────────────

const xmlAPIBase = "https://orders.example.com"

// OrderService defines XML-backed CRUD for orders.
type OrderService interface {
	GetOrder(ctx context.Context, id int) (Order, error)
	CreateOrder(ctx context.Context, req CreateOrderRequest) (Order, error)
}

type orderService struct {
	client request.RestClient
	token  string
}

// NewOrderService creates an OrderService. Inject a real or mock RestClient.
func NewOrderService(client request.RestClient, token string) OrderService {
	return &orderService{client: client, token: token}
}

// GetOrder fetches a single order as XML.
func (s *orderService) GetOrder(ctx context.Context, id int) (Order, error) {
	var order Order
	var status int

	url := fmt.Sprintf("%s/orders/%d", xmlAPIBase, id)
	err := s.client.NewRequest().
		WithContext(ctx).
		WithBasicAuth("api-user", s.token).
		AddHeaders("Accept", "application/xml").
		GetResponseAs(&order).
		GetResponseStatusCodeAs(&status).
		GET(url)

	if err != nil {
		return Order{}, fmt.Errorf("GetOrder: %w", err)
	}
	if status == http.StatusNotFound {
		return Order{}, fmt.Errorf("GetOrder: order %d not found", id)
	}
	if status != http.StatusOK {
		return Order{}, fmt.Errorf("GetOrder: unexpected status %d", status)
	}
	return order, nil
}

// CreateOrder posts a new order using an XML body and returns the created record.
func (s *orderService) CreateOrder(ctx context.Context, req CreateOrderRequest) (Order, error) {
	var created Order
	var status int

	err := s.client.NewRequest().
		WithContext(ctx).
		WithBasicAuth("api-user", s.token).
		WithXml(req).
		GetResponseAs(&created).
		GetResponseStatusCodeAs(&status).
		POST(xmlAPIBase + "/orders")

	if err != nil {
		return Order{}, fmt.Errorf("CreateOrder: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return Order{}, fmt.Errorf("CreateOrder: unexpected status %d", status)
	}
	return created, nil
}

// ────────────────────────────────────────────────────────────────────────────
// main
// ────────────────────────────────────────────────────────────────────────────

func main() {
	client := request.NewRestClient(&http.Client{Timeout: 10 * time.Second})
	svc := NewOrderService(client, "secret")
	ctx := context.Background()

	order, err := svc.GetOrder(ctx, 42)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("Order: %+v\n", order)
}

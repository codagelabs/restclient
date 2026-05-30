# restclient

A lightweight, fluent HTTP client for Go that wraps `net/http` with a clean builder-style API. Supports JSON/XML payloads, all auth schemes, automatic retries with configurable backoff, cookies, headers, and more.

## Install

```bash
go get github.com/codagelabs/restclient
```

## Quick Start

```go
package main

import (
    "fmt"
    "net/http"

    "github.com/codagelabs/restclient/request"
)

func main() {
    type Response struct {
        ID   int    `json:"id"`
        Name string `json:"name"`
    }

    var resp Response
    var status int

    err := request.NewRestClient(&http.Client{}).
        NewRequest().
        GetResponseAs(&resp).
        GetResponseStatusCodeAs(&status).
        GET("https://api.example.com/users/1")

    if err != nil {
        fmt.Println("error:", err)
        return
    }

    fmt.Println("status:", status)
    fmt.Println("response:", resp)
}
```

---

## Usage

### Creating a client

```go
client := request.NewRestClient(&http.Client{})
```

You can pass any `*http.Client` — with custom timeouts, transport, etc.

```go
httpClient := &http.Client{Timeout: 10 * time.Second}
client := request.NewRestClient(httpClient)
```

---

## HTTP Methods

### GET

```go
var resp MyResponse
var status int

err := client.NewRequest().
    GetResponseAs(&resp).
    GetResponseStatusCodeAs(&status).
    GET("https://api.example.com/resource")
```

### POST with JSON body

```go
type CreateRequest struct {
    Name string `json:"name"`
}

type CreateResponse struct {
    ID   int    `json:"id"`
    Name string `json:"name"`
}

var resp CreateResponse
var status int

err := client.NewRequest().
    WithJson(CreateRequest{Name: "Alice"}).
    GetResponseAs(&resp).
    GetResponseStatusCodeAs(&status).
    POST("https://api.example.com/users")
```

### POST with XML body

```go
type OrderRequest struct {
    XMLName  xml.Name `xml:"order"`
    Product  string   `xml:"product"`
    Quantity int      `xml:"quantity"`
}

var resp OrderResponse

err := client.NewRequest().
    WithXml(OrderRequest{Product: "widget", Quantity: 3}).
    GetResponseAs(&resp).
    POST("https://api.example.com/orders")
```

### POST with Form URL-Encoded body

```go
err := client.NewRequest().
    WithFromURLEncoded(map[string]interface{}{
        "username": "john",
        "password": "secret",
    }).
    GetResponseStatusCodeAs(&status).
    POST("https://api.example.com/login")
```

### PUT

```go
err := client.NewRequest().
    WithJson(UpdateRequest{Name: "Bob"}).
    GetResponseAs(&resp).
    PUT("https://api.example.com/users/1")
```

### PATCH

```go
err := client.NewRequest().
    WithJson(PatchRequest{Name: "Charlie"}).
    GetResponseAs(&resp).
    PATCH("https://api.example.com/users/1")
```

### DELETE

```go
err := client.NewRequest().
    GetResponseStatusCodeAs(&status).
    DELETE("https://api.example.com/users/1")
```

### Custom HTTP Method

```go
err := client.NewRequest().
    Execute("OPTIONS", "https://api.example.com/resource")
```

---

## Authentication

### Basic Auth

```go
err := client.NewRequest().
    WithBasicAuth("username", "password").
    GetResponseAs(&resp).
    GET("https://api.example.com/secure")
```

### JWT / Bearer Token

```go
err := client.NewRequest().
    WithJWTAuth("eyJhbGci...your.token.here").
    GetResponseAs(&resp).
    GET("https://api.example.com/secure")
```

### OAuth 2.0

```go
err := client.NewRequest().
    WithOauth("your-oauth-token").
    GetResponseAs(&resp).
    GET("https://api.example.com/secure")
```

---

## Headers, Cookies & Query Parameters

### Custom Headers

```go
err := client.NewRequest().
    AddHeaders("X-Request-ID", "abc-123").
    AddHeaders("Accept-Language", "en-US").
    GetResponseAs(&resp).
    GET("https://api.example.com/resource")
```

### Query Parameters

```go
err := client.NewRequest().
    WithQueryParameters(map[string]string{
        "page":  "1",
        "limit": "20",
    }).
    GetResponseAs(&resp).
    GET("https://api.example.com/users")
```

### Request Cookies

```go
err := client.NewRequest().
    AddCookies(&http.Cookie{Name: "session", Value: "abc123"}).
    GetResponseAs(&resp).
    GET("https://api.example.com/dashboard")
```

### Reading Response Cookies

```go
var cookies []*http.Cookie

err := client.NewRequest().
    GetResponseCookiesAs(&cookies).
    POST("https://api.example.com/login")

for _, c := range cookies {
    fmt.Println(c.Name, c.Value)
}
```

### Reading Response Headers

```go
var headers map[string][]string

err := client.NewRequest().
    GetResponseHeadersAs(&headers).
    GET("https://api.example.com/resource")

fmt.Println(headers["Content-Type"])
```

---

## Context Support

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

err := client.NewRequest().
    WithContext(ctx).
    GetResponseAs(&resp).
    GET("https://api.example.com/resource")
```

---

## Custom Request Modifier

Intercept and mutate the underlying `*http.Request` before it is sent — useful for signing, tracing, or any request-level customisation.

```go
err := client.NewRequest().
    WithCustomRequestModifier(func(r *http.Request) error {
        r.Header.Set("X-Trace-ID", uuid.New().String())
        r.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
        return nil
    }).
    GetResponseAs(&resp).
    POST("https://api.example.com/resource")
```

---

## Retries

### Simple retry (no delay)

Retry automatically when the server responds with one of the specified status codes.

```go
// Via RestClient constructor
err := client.NewRequestWithRetries(3, []int{500, 502, 503}).
    WithJson(payload).
    GetResponseAs(&resp).
    POST("https://api.example.com/resource")

// Or chainable on any request
err := client.NewRequest().
    WithJson(payload).
    WithRetry(3, []int{500, 502, 503}).
    GetResponseAs(&resp).
    POST("https://api.example.com/resource")
```

### Retry with fixed backoff

Wait a constant duration between each attempt.

```go
// Via RestClient constructor
err := client.NewRequestWithRetryAndBackoff(3, []int{500, 503}, 2*time.Second).
    WithJson(payload).
    GetResponseAs(&resp).
    POST("https://api.example.com/resource")

// Or chainable
err := client.NewRequest().
    WithJson(payload).
    WithRetryAndBackoff(3, []int{500, 503}, 2*time.Second).
    GetResponseAs(&resp).
    POST("https://api.example.com/resource")
```

### Retry with exponential backoff + jitter

Delays grow exponentially (`initialBackoff × 2^attempt`) with random jitter added to avoid thundering-herd problems.

```go
// Via RestClient constructor
err := client.NewRequestWithRetryAndExponentialBackoff(
    5,                      // max retries
    []int{500, 502, 503},   // retry on these status codes
    500*time.Millisecond,   // initial backoff (doubles each attempt)
).
    WithJson(payload).
    GetResponseAs(&resp).
    POST("https://api.example.com/resource")

// Or chainable
err := client.NewRequest().
    WithJson(payload).
    WithRetryAndExponentialBackoff(5, []int{500, 502, 503}, 500*time.Millisecond).
    GetResponseAs(&resp).
    POST("https://api.example.com/resource")
```

| Attempt | Delay (500 ms base, no jitter) |
|---------|-------------------------------|
| 1st retry | ~500 ms |
| 2nd retry | ~1 s |
| 3rd retry | ~2 s |
| 4th retry | ~4 s |

Jitter of up to `initialBackoff` is added to each computed delay.

---

## Combining Features

All builder methods are chainable and composable:

```go
var resp MyResponse
var status int
var headers map[string][]string

err := client.NewRequest().
    WithJson(MyRequest{Name: "Alice"}).
    WithBasicAuth("user", "pass").
    WithContext(ctx).
    AddHeaders("X-Request-ID", "req-001").
    WithQueryParameters(map[string]string{"version": "2"}).
    WithRetryAndExponentialBackoff(3, []int{500, 503}, 200*time.Millisecond).
    GetResponseAs(&resp).
    GetResponseStatusCodeAs(&status).
    GetResponseHeadersAs(&headers).
    POST("https://api.example.com/users")
```

---

## Response Binding

| Target type | Behaviour |
|---|---|
| `*string` | Raw response body as a string |
| `*[]byte` | Raw response body as bytes |
| Any struct with `json` tags | Auto-unmarshalled from `application/json` response |
| Any struct with `xml` tags | Auto-unmarshalled from `application/xml` response |

---

## License

MIT
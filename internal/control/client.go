package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

// Client talks to the daemon. It holds no credential: the kernel tells the
// daemon who is calling.
type Client struct {
	Socket string
}

func (c Client) Do(ctx context.Context, request Request) (Response, error) {
	request.APIVersion = APIVersion
	body, err := json.Marshal(request)
	if err != nil {
		return Response{}, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", c.Socket)
		},
	}
	defer transport.CloseIdleConnections()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://control/v1", bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: transport}).Do(httpRequest)
	if err != nil {
		return Response{}, fmt.Errorf("reach the control daemon at %s: %w", c.Socket, err)
	}
	defer resp.Body.Close()
	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Response{}, fmt.Errorf("decode the daemon's response (HTTP %d): %w", resp.StatusCode, err)
	}
	return response, nil
}

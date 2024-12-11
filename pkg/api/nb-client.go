package netbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// Client is the structure for the NetBox API client.
// It contains the base URL for the API, an authentication token, and an HTTP client for making requests.
type Client struct {
	BaseURL    string
	APIToken   string
	HTTPClient *http.Client
}

// NewClient initializes a new NetBox API client.
// Takes the API base URL and the API token as inputs and returns a Client instance.
func NewClient(baseURL, apiToken string) *Client {
	return &Client{
		BaseURL:    baseURL,
		APIToken:   apiToken,
		HTTPClient: &http.Client{},
	}
}

// ------------------------------------------------------------
// Request sends a generic HTTP request to the NetBox API.
// - method: HTTP method (e.g., "GET", "POST").
// - endpoint: API endpoint (e.g., "/api/dcim/sites/").
// - payload: Data to include in the request body (for methods like POST or PUT).
// Returns the response body as a byte slice or an error if the request fails.
func (c *Client) Request(method, endpoint string, payload T) ([]byte, error) {
	// Construct the full URL by appending the endpoint to the base URL.
	url := fmt.Sprintf("%s%s", c.BaseURL, endpoint)

	var body []byte
	if payload != nil {
		// Marshal the payload into JSON format if provided.
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %w", err)
		}
	}

	// Create a new HTTP request with the specified method, URL, and body.
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set required headers for the API request.
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", c.APIToken))
	req.Header.Set("Content-Type", "application/json")

	// Send the request and receive a response.
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check if the response status code indicates success (2xx).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read the response body to include in the error message.
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read the response body and return it.
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return respBody, nil
}

// Create sends a POST request to create a new object in NetBox.
// - endpoint: The API endpoint for the object type (e.g., "dcim/sites").
// - payload: The object data to send in the request body.
// This is a generic function that can be used to create any type of object in NetBox.
func (c *Client) Create(endpoint string, payload T) error {
	// Construct the full API endpoint for the POST request.
	fullEndpoint := fmt.Sprintf("/api/%s/", endpoint)

	// Use the generic Request method to send the POST request.
	_, err := c.Request("POST", fullEndpoint, payload)
	if err != nil {
		return fmt.Errorf("failed to create object at %s: %w", fullEndpoint, err)
	}

	return nil
}

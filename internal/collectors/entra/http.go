package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func (c *collection) get(ctx context.Context, endpoint, fields string, target any) string {
	requestURL := c.base + endpoint + "?" + url.Values{"$select": {fields}}.Encode()
	return c.getURL(ctx, requestURL, target)
}

func (c *collection) getURL(ctx context.Context, address string, target any) string {
	if c.exhausted {
		return "authentication_failed"
	}
	for attempt := 0; attempt < 3; attempt++ {
		c.requests++
		if c.requests > 1000 {
			return "request_limit"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return "invalid_request"
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.client.Do(req)
		if err != nil {
			return "transport_error"
		}
		if resp.StatusCode == 401 {
			c.exhausted = true
		}
		if resp.StatusCode == 429 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
			resp.Body.Close()
			if attempt == 2 {
				return fmt.Sprintf("HTTP_%d", resp.StatusCode)
			}
			delay := time.Duration(attempt+1) * 100 * time.Millisecond
			if value := resp.Header.Get("Retry-After"); value != "" {
				seconds, e := strconv.Atoi(value)
				if e != nil {
					when, parseErr := http.ParseTime(value)
					if parseErr != nil {
						return "rate_limited"
					}
					delay = time.Until(when)
					if delay < 0 {
						delay = 0
					}
				} else {
					if seconds < 0 || seconds > 2 {
						return "rate_limited"
					}
					delay = time.Duration(seconds) * time.Second
				}
				if delay < 0 || delay > 2*time.Second {
					return "rate_limited"
				}
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "cancelled"
			case <-timer.C:
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Sprintf("HTTP_%d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if err != nil {
			return "response_read_error"
		}
		if len(data) > maxResponseBytes {
			return "response_too_large"
		}
		if json.Unmarshal(data, target) != nil {
			return "invalid_metadata_json"
		}
		return ""
	}
	return "request_failed"
}

func (c *collection) list(ctx context.Context, endpoint, fields string, consume func(json.RawMessage) bool) string {
	next := c.base + endpoint + "?" + url.Values{"$select": {fields}}.Encode()
	seen := map[string]bool{}
	count := 0
	for page := 0; page < maxPages; page++ {
		if seen[next] {
			return "repeated_next_link"
		}
		seen[next] = true
		var response struct {
			Value *[]json.RawMessage `json:"value"`
			Next  string             `json:"@odata.nextLink"`
		}
		if code := c.getURL(ctx, next, &response); code != "" {
			return code
		}
		if response.Value == nil {
			return "missing_collection"
		}
		for _, raw := range *response.Value {
			if len(c.entities) >= 20000 {
				return "entity_limit"
			}
			count++
			if count > maxItems {
				return "collection_limit"
			}
			if !consume(raw) {
				return "invalid_collection_item"
			}
		}
		if response.Next == "" {
			return ""
		}
		var ok bool
		next, ok = pageURL(c.base, endpoint, fields, response.Next)
		if !ok {
			return "unsafe_next_link"
		}
	}
	return "page_limit"
}

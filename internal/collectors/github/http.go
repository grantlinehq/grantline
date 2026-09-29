package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (c *collection) get(ctx context.Context, endpoint string, target any) (http.Header, string) {
	if c.exhausted {
		return nil, "authentication_failed"
	}
	for attempt := 0; attempt < 3; attempt++ {
		c.requests++
		if c.requests > 1000 {
			return nil, "request_limit"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, Address+endpoint, nil)
		if err != nil {
			return nil, "invalid_request"
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", APIVersion)
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, "transport_error"
		}
		if resp.StatusCode == 401 {
			c.exhausted = true
		}
		if resp.StatusCode == 429 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
			resp.Body.Close()
			if attempt == 2 {
				return nil, fmt.Sprintf("HTTP_%d", resp.StatusCode)
			}
			delay := time.Duration(attempt+1) * 100 * time.Millisecond
			if s := resp.Header.Get("Retry-After"); s != "" {
				n, e := strconv.Atoi(s)
				if e != nil || n < 0 || n > 2 {
					return nil, "rate_limited"
				}
				delay = time.Duration(n) * time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, "cancelled"
			case <-timer.C:
			}
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Sprintf("HTTP_%d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		resp.Body.Close()
		if err != nil {
			return nil, "response_read_error"
		}
		if len(data) > maxResponseBytes {
			return nil, "response_too_large"
		}
		if json.Unmarshal(data, target) != nil {
			return nil, "invalid_metadata_json"
		}
		return resp.Header, ""
	}
	return nil, "request_failed"
}

// Page numbers are generated locally. Even an otherwise valid Link header
// cannot broaden the request path, query, origin, credentials, or page budget.
func nextPage(header http.Header, endpoint string, page int) (bool, bool) {
	values := header.Values("Link")
	if len(values) == 0 {
		return false, true
	}
	next := false
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			pieces := strings.Split(strings.TrimSpace(part), ";")
			if len(pieces) != 2 || !strings.HasPrefix(pieces[0], "<") || !strings.HasSuffix(pieces[0], ">") {
				return false, false
			}
			rel := strings.TrimSpace(pieces[1])
			if rel != `rel="next"` && rel != `rel="last"` && rel != `rel="prev"` && rel != `rel="first"` {
				return false, false
			}
			u, e := url.Parse(strings.TrimSuffix(strings.TrimPrefix(pieces[0], "<"), ">"))
			if e != nil || u.Scheme != "https" || u.Host != "api.github.com" || u.User != nil || u.Fragment != "" || u.Path != endpoint || u.RawPath != "" {
				return false, false
			}
			q, e := url.ParseQuery(u.RawQuery)
			if e != nil || len(q) != 2 || len(q["page"]) != 1 || len(q["per_page"]) != 1 || q.Get("per_page") != "100" {
				return false, false
			}
			n, e := strconv.Atoi(q.Get("page"))
			if e != nil || n < 1 || n > 10 {
				return false, false
			}
			if rel == `rel="next"` {
				if next || n != page+1 {
					return false, false
				}
				next = true
			}
		}
	}
	return next, true
}

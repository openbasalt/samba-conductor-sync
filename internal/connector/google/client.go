package google

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/samba-conductor/conductor-sync/internal/connector"
)

// apiError is a Directory API error response.
type apiError struct {
	Status  int
	Reason  string
	Message string
}

func (e *apiError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("HTTP %d %s: %s", e.Status, e.Reason, e.Message)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
}

// rateLimitReasons are 403 reasons that mean "slow down", not "forbidden".
var rateLimitReasons = map[string]bool{
	"rateLimitExceeded": true, "userRateLimitExceeded": true, "quotaExceeded": true, "dailyLimitExceeded": false,
}

func (e *apiError) retryable() bool {
	switch {
	case e.Status == http.StatusTooManyRequests:
		return true
	case e.Status == http.StatusForbidden && rateLimitReasons[e.Reason]:
		return true
	case e.Status >= 500:
		return true
	}
	return false
}

func (e *apiError) rateLimited() bool {
	return e.Status == http.StatusTooManyRequests || (e.Status == http.StatusForbidden && rateLimitReasons[e.Reason])
}

// classify wraps an API error with the connector's sentinel errors.
func classify(e *apiError) error {
	switch {
	case e.Status == http.StatusNotFound:
		return fmt.Errorf("%w: %w", connector.ErrNotFound, e)
	case e.Status == http.StatusConflict:
		return fmt.Errorf("%w: %w", connector.ErrConflict, e)
	case e.rateLimited():
		return fmt.Errorf("%w: %w", connector.ErrRateLimited, e)
	case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden:
		return fmt.Errorf("%w: %w", connector.ErrAuth, e)
	case e.Status == http.StatusBadRequest || e.Status == http.StatusPreconditionFailed:
		return fmt.Errorf("%w: %w", connector.ErrInvalid, e)
	}
	return e
}

// limiter spaces requests evenly (a simple, dependency-free pacer).
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func (l *limiter) wait(ctx context.Context, now func() time.Time, sleep func(context.Context, time.Duration) error) error {
	if l.interval <= 0 {
		return nil
	}
	l.mu.Lock()
	t := now()
	at := l.next
	if at.Before(t) {
		at = t
	}
	l.next = at.Add(l.interval)
	l.mu.Unlock()
	if d := at.Sub(t); d > 0 {
		return sleep(ctx, d)
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// client calls the Directory API with retries, backoff and pacing.
type client struct {
	base       *url.URL
	hc         *http.Client
	tokens     *tokenSource
	lim        *limiter
	maxRetries int
	backoff    time.Duration
	maxBackoff time.Duration
	now        func() time.Time
	sleep      func(context.Context, time.Duration) error
	// requests counts HTTP requests (metrics).
	mu       sync.Mutex
	requests int
	retries  int
}

// callInfo tells a caller whether an earlier attempt of the same call may
// have reached the server (a create retried after a timeout may have
// succeeded; its 409 then means "done", not "taken").
type callInfo struct {
	attempts  int
	ambiguous bool
}

func (c *client) stats() (requests, retries int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests, c.retries
}

func (c *client) do(ctx context.Context, method, path string, query url.Values, body, out any) (callInfo, error) {
	var info callInfo
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawPath = ""
	if query != nil {
		u.RawQuery = query.Encode()
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return info, err
		}
	}
	authRetried := false
	for attempt := 0; ; attempt++ {
		info.attempts = attempt + 1
		if err := c.lim.wait(ctx, c.now, c.sleep); err != nil {
			return info, err
		}
		token, err := c.tokens.get(ctx)
		if err != nil {
			return info, err
		}
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
		if err != nil {
			return info, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		c.mu.Lock()
		c.requests++
		c.mu.Unlock()
		resp, err := c.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return info, ctx.Err()
			}
			// The request may or may not have reached the server.
			info.ambiguous = info.ambiguous || method != http.MethodGet
			if attempt >= c.maxRetries {
				return info, fmt.Errorf("google: %s %s: %w", method, path, err)
			}
			if err := c.pause(ctx, attempt, 0); err != nil {
				return info, err
			}
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		_ = resp.Body.Close()
		if rerr != nil {
			info.ambiguous = info.ambiguous || method != http.MethodGet
			if attempt >= c.maxRetries {
				return info, fmt.Errorf("google: %s %s: read: %w", method, path, rerr)
			}
			if err := c.pause(ctx, attempt, 0); err != nil {
				return info, err
			}
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(data) > 0 {
				if err := json.Unmarshal(data, out); err != nil {
					return info, fmt.Errorf("google: %s %s: decode: %w", method, path, err)
				}
			}
			return info, nil
		}
		ae := decodeError(resp.StatusCode, data)
		if resp.StatusCode == http.StatusUnauthorized && !authRetried {
			// Expired or revoked token: fetch a new one once.
			authRetried = true
			c.tokens.invalidate()
			continue
		}
		if ae.retryable() && attempt < c.maxRetries {
			if resp.StatusCode >= 500 {
				info.ambiguous = info.ambiguous || method != http.MethodGet
			}
			if err := c.pause(ctx, attempt, retryAfter(resp.Header.Get("Retry-After"))); err != nil {
				return info, err
			}
			continue
		}
		return info, classify(ae)
	}
}

// pause waits before a retry: exponential backoff with full jitter,
// at least what Retry-After asks for.
func (c *client) pause(ctx context.Context, attempt int, after time.Duration) error {
	c.mu.Lock()
	c.retries++
	c.mu.Unlock()
	d := c.backoff << attempt
	if d <= 0 || d > c.maxBackoff {
		d = c.maxBackoff
	}
	d = d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
	if after > d {
		d = after
	}
	return c.sleep(ctx, d)
}

func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s >= 0 {
		if s > 300 {
			s = 300
		}
		return time.Duration(s) * time.Second
	}
	return 0
}

func decodeError(status int, data []byte) *apiError {
	var env struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Errors  []struct {
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"errors"`
			Status string `json:"status"`
		} `json:"error"`
	}
	ae := &apiError{Status: status}
	if json.Unmarshal(data, &env) == nil {
		ae.Message = clip(env.Error.Message, 300)
		if len(env.Error.Errors) > 0 {
			ae.Reason = clip(env.Error.Errors[0].Reason, 64)
		}
	}
	if ae.Message == "" {
		ae.Message = http.StatusText(status)
	}
	return ae
}

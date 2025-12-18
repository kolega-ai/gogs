// Copyright 2025 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package v1

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"gopkg.in/macaron.v1"

	"gogs.io/gogs/internal/context"
)

const (
	// Rate limits per minute
	rateLimitIP    = 100 // Per IP for unauthenticated requests
	rateLimitToken = 500 // Per token for authenticated requests

	rateLimitWindow = 60 // seconds
)

// rateLimiter implements rate limiting middleware for API endpoints.
// It enforces per-IP limits for unauthenticated requests and per-token
// limits for authenticated requests to prevent abuse and DoS attacks.
func rateLimiter() macaron.Handler {
	return func(c *context.APIContext) {
		var key string
		var limit int

		// Determine rate limit key and limit based on authentication
		if c.IsTokenAuth {
			// Authenticated requests: limit per user token
			key = fmt.Sprintf("ratelimit:token:%d", c.User.ID)
			limit = rateLimitToken
		} else {
			// Unauthenticated requests: limit per IP address
			key = fmt.Sprintf("ratelimit:ip:%s", c.RemoteAddr())
			limit = rateLimitIP
		}

		// Get current request count from cache
		count := 0
		if val := c.Cache.Get(key); val != nil {
			if v, ok := val.(int); ok {
				count = v
			}
		}

		// Calculate remaining requests
		remaining := limit - count - 1
		if remaining < 0 {
			remaining = 0
		}

		// Set rate limit headers
		c.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
		c.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Unix()+rateLimitWindow, 10))

		// Check if rate limit exceeded
		if count >= limit {
			c.Header().Set("Retry-After", strconv.Itoa(rateLimitWindow))
			c.JSON(http.StatusTooManyRequests, map[string]string{
				"message": "API rate limit exceeded. Please retry after some time.",
				"url":     context.DocURL,
			})
			return
		}

		// Increment counter
		c.Cache.Put(key, count+1, rateLimitWindow)

		c.Next()
	}
}

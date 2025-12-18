// Copyright 2020 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package app

import (
	"io"
	"net/http"

	"github.com/microcosm-cc/bluemonday"
	"gopkg.in/macaron.v1"
)

// Maximum size for notebook rendering request (10MB)
// This prevents DoS attacks from excessively large notebook files
const maxNotebookSize = 10 * 1024 * 1024

// ipynbSanitizer returns a bluemonday policy configured for Jupyter notebooks.
// This policy allows safe rendering of notebook content while preventing XSS attacks.
func ipynbSanitizer() *bluemonday.Policy {
	p := bluemonday.UGCPolicy()
	// Allow notebook-specific classes and attributes for proper rendering
	p.AllowAttrs("class", "data-prompt-number").OnElements("div")
	p.AllowAttrs("class").OnElements("img")
	p.AllowAttrs("class").OnElements("pre", "code")
	// Allow data URLs for base64-encoded images in notebook outputs
	p.AllowURLSchemes("data")
	return p
}

// SanitizeIpynb returns a handler that sanitizes Jupyter notebook HTML.
// Security flow:
// 1. Client-side validation of notebook structure
// 2. Client-side rendering using notebookjs
// 3. Server-side sanitization using bluemonday (this handler)
// 4. Return sanitized HTML to client for safe DOM insertion
func SanitizeIpynb() macaron.Handler {
	p := ipynbSanitizer()

	return func(c *macaron.Context) {
		// Limit request size to prevent DoS attacks
		limitedReader := io.LimitReader(c.Req.Body().ReadCloser(), maxNotebookSize+1)
		html, err := io.ReadAll(limitedReader)
		if err != nil {
			c.Error(http.StatusInternalServerError, "read body")
			return
		}

		// Check if request exceeded size limit
		if len(html) > maxNotebookSize {
			c.Error(http.StatusRequestEntityTooLarge, "notebook too large")
			return
		}

		// Check for empty content
		if len(html) == 0 {
			c.Error(http.StatusBadRequest, "empty content")
			return
		}

		// Sanitize HTML to prevent XSS attacks
		sanitized := p.Sanitize(string(html))
		c.PlainText(http.StatusOK, []byte(sanitized))
	}
}

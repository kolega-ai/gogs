// Copyright 2017 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package markup

import (
	"sync"

	"github.com/microcosm-cc/bluemonday"

	"gogs.io/gogs/internal/conf"
	"gogs.io/gogs/internal/lazyregexp"
)

// Sanitizer is a protection wrapper of *bluemonday.Policy which does not allow
// any modification to the underlying policies once it's been created.
type Sanitizer struct {
	policy *bluemonday.Policy
	init   sync.Once
}

var sanitizer = &Sanitizer{
	policy: bluemonday.UGCPolicy(),
}

// NewSanitizer initializes sanitizer with allowed attributes based on settings.
// Multiple calls to this function will only create one instance of Sanitizer during
// entire application lifecycle.
func NewSanitizer() {
	sanitizer.init.Do(func() {
		// We only want to allow HighlightJS specific classes for code blocks
		sanitizer.policy.AllowAttrs("class").Matching(lazyregexp.New(`^language-\w+$`).Regexp()).OnElements("code")

		// Checkboxes
		sanitizer.policy.AllowAttrs("type").Matching(lazyregexp.New(`^checkbox$`).Regexp()).OnElements("input")
		sanitizer.policy.AllowAttrs("checked", "disabled").OnElements("input")

		// Data URLs
		sanitizer.policy.AllowURLSchemes("data")

		// Custom URL-Schemes
		sanitizer.policy.AllowURLSchemes(conf.Markdown.CustomURLSchemes...)
	})
}

// Sanitize takes a string that contains a HTML fragment or document and applies policy whitelist.
func Sanitize(s string) string {
	return sanitizer.policy.Sanitize(s)
}

// SanitizeBytes takes a []byte slice that contains a HTML fragment or document and applies policy whitelist.
func SanitizeBytes(b []byte) []byte {
	return sanitizer.policy.SanitizeBytes(b)
}

var emailSanitizer = &Sanitizer{
	policy: bluemonday.NewPolicy(),
}

// NewEmailSanitizer initializes email sanitizer with a stricter policy that prevents
// email tracking by removing image tags and other external resource loads.
// Multiple calls to this function will only create one instance of Sanitizer during
// entire application lifecycle.
func NewEmailSanitizer() {
	emailSanitizer.init.Do(func() {
		// Build from scratch - explicitly do not include img tags to prevent tracking
		emailSanitizer.policy.AllowElements("a", "abbr", "acronym", "b", "blockquote", "br", "caption", "cite", "code", "dd", "del", "details", "div", "dl", "dt", "em", "figcaption", "figure", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "ins", "kbd", "li", "mark", "ol", "p", "pre", "q", "s", "samp", "small", "span", "strike", "strong", "sub", "summary", "sup", "table", "tbody", "td", "tfoot", "th", "thead", "time", "tr", "u", "ul", "var")

		// Allow code highlighting class
		emailSanitizer.policy.AllowAttrs("class").Matching(lazyregexp.New(`^language-\w+$`).Regexp()).OnElements("code")

		// Allow links but ensure they're safe
		emailSanitizer.policy.AllowStandardURLs()
		emailSanitizer.policy.AllowAttrs("href").OnElements("a")
		emailSanitizer.policy.RequireNoFollowOnLinks(true)

		// Checkboxes for task lists
		emailSanitizer.policy.AllowAttrs("type").Matching(lazyregexp.New(`^checkbox$`).Regexp()).OnElements("input")
		emailSanitizer.policy.AllowAttrs("checked", "disabled").OnElements("input")

		// Data URLs
		emailSanitizer.policy.AllowURLSchemes("data")

		// Custom URL schemes
		emailSanitizer.policy.AllowURLSchemes(conf.Markdown.CustomURLSchemes...)
	})
}

// SanitizeEmail takes a string that contains HTML and applies a stricter email-specific
// policy that removes img tags to prevent tracking.
func SanitizeEmail(s string) string {
	return emailSanitizer.policy.Sanitize(s)
}

// SanitizeEmailBytes takes a []byte slice that contains HTML and applies a stricter
// email-specific policy that removes img tags to prevent tracking.
func SanitizeEmailBytes(b []byte) []byte {
	return emailSanitizer.policy.SanitizeBytes(b)
}

// Copyright 2017 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package markup_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "gogs.io/gogs/internal/markup"
)

func Test_Sanitizer(t *testing.T) {
	NewSanitizer()
	tests := []struct {
		input  string
		expVal string
	}{
		// Regular
		{input: `<a onblur="alert(secret)" href="http://www.google.com">Google</a>`, expVal: `<a href="http://www.google.com" rel="nofollow">Google</a>`},

		// Code highlighting class
		{input: `<code class="random string"></code>`, expVal: `<code></code>`},
		{input: `<code class="language-random ui tab active menu attached animating sidebar following bar center"></code>`, expVal: `<code></code>`},
		{input: `<code class="language-go"></code>`, expVal: `<code class="language-go"></code>`},

		// Input checkbox
		{input: `<input type="hidden">`, expVal: ``},
		{input: `<input type="checkbox">`, expVal: `<input type="checkbox">`},
		{input: `<input checked disabled autofocus>`, expVal: `<input checked="" disabled="">`},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			assert.Equal(t, test.expVal, Sanitize(test.input))
			assert.Equal(t, test.expVal, string(SanitizeBytes([]byte(test.input))))
		})
	}
}

func Test_EmailSanitizer(t *testing.T) {
	NewEmailSanitizer()
	tests := []struct {
		name   string
		input  string
		expVal string
	}{
		// Image tags should be stripped to prevent tracking
		{
			name:   "external image removed",
			input:  `<p>Hello <img src="http://attacker.com/track.png" alt="tracker"/> world</p>`,
			expVal: `<p>Hello  world</p>`,
		},
		{
			name:   "markdown image syntax removed",
			input:  `<p><img src="https://example.com/image.png" alt="image"/></p>`,
			expVal: `<p></p>`,
		},

		// Regular HTML should still be allowed
		{
			name:   "links allowed",
			input:  `<a href="http://www.google.com">Google</a>`,
			expVal: `<a href="http://www.google.com" rel="nofollow">Google</a>`,
		},
		{
			name:   "basic formatting allowed",
			input:  `<p>Hello <strong>world</strong> with <em>emphasis</em></p>`,
			expVal: `<p>Hello <strong>world</strong> with <em>emphasis</em></p>`,
		},

		// Code highlighting class
		{
			name:   "code class stripped if invalid",
			input:  `<code class="random string"></code>`,
			expVal: `<code></code>`,
		},
		{
			name:   "code language class allowed",
			input:  `<code class="language-go"></code>`,
			expVal: `<code class="language-go"></code>`,
		},

		// Input checkbox for task lists
		{
			name:   "checkbox allowed",
			input:  `<input type="checkbox">`,
			expVal: `<input type="checkbox">`,
		},
		{
			name:   "checkbox with checked disabled",
			input:  `<input type="checkbox" checked disabled>`,
			expVal: `<input type="checkbox" checked="" disabled="">`,
		},

		// XSS attempts should be blocked
		{
			name:   "script tags removed",
			input:  `<script>alert('xss')</script>`,
			expVal: ``,
		},
		{
			name:   "javascript href blocked",
			input:  `<a href="javascript:alert('xss')">click</a>`,
			expVal: `click`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expVal, SanitizeEmail(test.input))
			assert.Equal(t, test.expVal, string(SanitizeEmailBytes([]byte(test.input))))
		})
	}
}

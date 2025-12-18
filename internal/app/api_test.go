// Copyright 2020 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ipynbSanitizer(t *testing.T) {
	p := ipynbSanitizer()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name: "allow 'class' and 'data-prompt-number' attributes",
			input: `
<div class="nb-notebook">
    <div class="nb-worksheet">
        <div class="nb-cell nb-markdown-cell">Hello world</div>
        <div class="nb-cell nb-code-cell">
            <div class="nb-input" data-prompt-number="4">
            </div>
        </div>
    </div>
</div>
`,
			want: `
<div class="nb-notebook">
    <div class="nb-worksheet">
        <div class="nb-cell nb-markdown-cell">Hello world</div>
        <div class="nb-cell nb-code-cell">
            <div class="nb-input" data-prompt-number="4">
            </div>
        </div>
    </div>
</div>
`,
		},
		{
			name: "allow base64 encoded images",
			input: `
<div class="nb-output" data-prompt-number="4">
    <img class="nb-image-output" src="data:image/png;base64,iVBORw0KGgoA"/>
</div>
`,
			want: `
<div class="nb-output" data-prompt-number="4">
    <img class="nb-image-output" src="data:image/png;base64,iVBORw0KGgoA"/>
</div>
`,
		},
		{
			name: "allow code blocks with classes",
			input: `
<div class="nb-cell">
    <pre class="nb-code"><code class="python">print("hello")</code></pre>
</div>
`,
			want: `
<div class="nb-cell">
    <pre class="nb-code"><code class="python">print(&#34;hello&#34;)</code></pre>
</div>
`,
		},
		{
			name: "prevent XSS with script tags",
			input: `
<div class="nb-output" data-prompt-number="10">
<div class="nb-html-output">
<style>
.output {
align-items: center;
background: #00ff00;
}
</style>
<script>
function test() {
alert("test");
}

$(document).ready(test);
</script>
</div>
</div>
`,
			want: `
<div class="nb-output" data-prompt-number="10">
<div class="nb-html-output">


</div>
</div>
`,
		},
		{
			name: "prevent XSS with inline event handlers",
			input: `
<div class="nb-output">
    <img src="x" onerror="alert('XSS')" />
    <div onclick="alert('XSS')">Click me</div>
</div>
`,
			want: `
<div class="nb-output">
    <img src="x"/>
    <div>Click me</div>
</div>
`,
		},
		{
			name: "prevent XSS with javascript: protocol",
			input: `
<div class="nb-output">
    <a href="javascript:alert('XSS')">Click</a>
</div>
`,
			want: `
<div class="nb-output">
    Click
</div>
`,
		},
		{
			name: "prevent iframe injection",
			input: `
<div class="nb-output">
    <iframe src="https://malicious.com"></iframe>
</div>
`,
			want: `
<div class="nb-output">
    
</div>
`,
		},
		{
			name: "prevent object and embed tags",
			input: `
<div class="nb-output">
    <object data="malicious.swf"></object>
    <embed src="malicious.swf">
</div>
`,
			want: `
<div class="nb-output">
    
    
</div>
`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, p.Sanitize(test.input))
		})
	}
}

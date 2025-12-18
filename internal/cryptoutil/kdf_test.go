// Copyright 2025 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cryptoutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveKey(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "simple password",
			password: "my-secret-key",
		},
		{
			name:     "complex password",
			password: "C0mpl3x!P@ssw0rd#2025",
		},
		{
			name:     "empty password",
			password: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := DeriveKey(tt.password)

			// Key should be exactly PBKDF2KeyLength bytes
			assert.Equal(t, PBKDF2KeyLength, len(key))

			// Same password should produce same key (deterministic)
			key2 := DeriveKey(tt.password)
			assert.Equal(t, key, key2)
		})
	}
}

func TestDeriveKey_DifferentPasswords(t *testing.T) {
	key1 := DeriveKey("password1")
	key2 := DeriveKey("password2")

	// Different passwords should produce different keys
	assert.NotEqual(t, key1, key2)
}

func TestDeriveKey_Integration(t *testing.T) {
	// Test that the derived key works with AES-GCM encryption
	password := "test-secret-key"
	key := DeriveKey(password)

	plaintext := []byte("sensitive 2FA secret")

	// Encrypt
	encrypted, err := AESGCMEncrypt(key, plaintext)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted)

	// Decrypt
	decrypted, err := AESGCMDecrypt(key, encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

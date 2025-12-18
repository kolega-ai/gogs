// Copyright 2025 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cryptoutil

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// PBKDF2Iterations is the number of iterations for PBKDF2 key derivation.
	// 100,000 iterations provides a good balance between security and performance.
	PBKDF2Iterations = 100000

	// PBKDF2KeyLength is the derived key length in bytes for AES-128.
	PBKDF2KeyLength = 16
)

// pbkdf2Salt is a fixed application-level salt for PBKDF2 key derivation.
// Using a fixed salt is acceptable here since the input key (SecretKey) is
// already a high-entropy server secret. The primary goal is to use a proper
// KDF instead of the cryptographically weak MD5 hash.
var pbkdf2Salt = []byte("gogs-2fa-encryption-salt-v1")

// DeriveKey derives an AES encryption key from the given password using PBKDF2.
// This replaces the use of MD5 for key derivation, providing proper cryptographic
// key derivation with configurable iteration count.
func DeriveKey(password string) []byte {
	return pbkdf2.Key([]byte(password), pbkdf2Salt, PBKDF2Iterations, PBKDF2KeyLength, sha256.New)
}

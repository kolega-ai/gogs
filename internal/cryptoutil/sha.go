// Copyright 2020 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cryptoutil

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
)

// SHA1 encodes string to hexadecimal of SHA1 checksum.
func SHA1(str string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// SHA256 encodes string to hexadecimal of SHA256 checksum.
func SHA256(str string) string {
	return hex.EncodeToString(SHA256Bytes(str))
}

// SHA256Bytes encodes string to SHA256 checksum.
func SHA256Bytes(str string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(str))
	return h.Sum(nil)
}

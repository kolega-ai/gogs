// Copyright 2020 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cryptoutil

import (
	"crypto/md5"
	"encoding/hex"
)

// MD5 encodes string to hexadecimal of MD5 checksum.
//
// Deprecated: MD5 is cryptographically broken and should not be used for
// security purposes. Use SHA256 for cryptographic hashing. This function
// should only be used for non-cryptographic purposes (e.g., Gravatar).
func MD5(str string) string {
	return hex.EncodeToString(MD5Bytes(str))
}

// MD5Bytes encodes string to MD5 checksum.
//
// Deprecated: MD5 is cryptographically broken and should not be used for
// security purposes. Use SHA256Bytes for cryptographic hashing. This function
// should only be used for non-cryptographic purposes (e.g., Gravatar).
func MD5Bytes(str string) []byte {
	m := md5.New()
	_, _ = m.Write([]byte(str))
	return m.Sum(nil)
}

// https://github.com/huijari/eventgarden
// Copyright (C) 2015 Alexandre Cesar da Silva

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

type Token struct {
	Userid    uint64
	Expires   time.Time
	Signature []byte
}

// Encode a token into a string, format: userid.expires.signature.
func EncodeToken(token Token) string {
	userid := strconv.FormatUint(token.Userid, 10)
	userid = base64.URLEncoding.EncodeToString([]byte(userid))

	expires := token.Expires.Format(time.RFC3339)
	expires = base64.URLEncoding.EncodeToString([]byte(expires))

	signature := base64.URLEncoding.EncodeToString(token.Signature)

	return userid + "." + expires + "." + signature
}

// Decode a string into a token structure.
func DecodeToken(encoded string) (Token, error) {
	var token Token

	sections := strings.Split(encoded, ".")
	if len(sections) != 3 {
		return token, errors.New("Invalid Token Format")
	}

	decoded, err := base64.URLEncoding.DecodeString(sections[0])
	if err != nil {
		return token, err
	}
	userid, err := strconv.ParseUint(string(decoded), 10, 64)
	if err != nil {
		return token, err
	}

	decoded, err = base64.URLEncoding.DecodeString(sections[1])
	if err != nil {
		return token, err
	}
	expires, err := time.Parse(time.RFC3339, string(decoded))
	if err != nil {
		return token, err
	}

	decoded, err = base64.URLEncoding.DecodeString(sections[2])
	if err != nil {
		return token, err
	}
	signature := decoded

	token.Userid = userid
	token.Expires = expires
	token.Signature = signature

	return token, nil
}

// Generate a new token to the userid specified.
func GenerateToken(content uint64) Token {
	var token Token

	duration := Conf.Expiration
	token.Userid = content
	token.Expires = time.Now().Add(duration)

	userid := []byte(strconv.FormatUint(token.Userid, 10))
	expires := []byte(token.Expires.Format(time.RFC3339))

	secret := Conf.Secret
	mac := hmac.New(sha256.New, secret)
	mac.Write(userid)
	mac.Write(expires)
	hash := mac.Sum(nil)
	token.Signature = hash

	return token
}

// Validate a token and returns the userid.
func ValidateToken(token Token) (uint64, error) {
	userid := []byte(strconv.FormatUint(token.Userid, 10))
	expires := []byte(token.Expires.Format(time.RFC3339))
	signature := token.Signature

	secret := Conf.Secret
	mac := hmac.New(sha256.New, secret)
	mac.Write(userid)
	mac.Write(expires)
	hash := mac.Sum(nil)

	if hmac.Equal(hash, signature) {
		if token.Expires.After(time.Now()) {
			return token.Userid, nil
		}
		return 0, errors.New("Expired Token")
	}
	return 0, errors.New("Invalid token")
}

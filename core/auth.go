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
	Signature string
}

func decodeToken(encoded string) (Token, error) {
	var token Token

	sections := strings.Split(encoded, ".")
	if len(sections) != 3 {
		return token, errors.New("Invalid Token Format")
	}

	decoded, err := base64.StdEncoding.DecodeString(sections[0])
	if err != nil {
		return token, err
	}
	userid, err := strconv.ParseUint(string(decoded), 10, 64)
	if err != nil {
		return token, err
	}

	decoded, err = base64.StdEncoding.DecodeString(sections[1])
	if err != nil {
		return token, err
	}
	expires, err := time.Parse(time.RFC3339, string(decoded))
	if err != nil {
		return token, err
	}

	signature := sections[2]

	token.Userid = userid
	token.Expires = expires
	token.Signature = signature

	return token, nil
}

func authToken(token Token) (uint64, error) {
	userid := []byte(strconv.FormatUint(token.Userid, 10))
	expires := []byte(token.Expires.Format(time.RFC3339))
	signature := []byte(token.Signature)

	secret := []byte("secret") // TODO: Get by configuration
	mac := hmac.New(sha256.New, secret)
	mac.Write(userid)
	mac.Write(expires)
	hash := mac.Sum(nil)

	if hmac.Equal(hash, signature) {
		if token.Expires.Before(time.Now()) {
			return token.Userid, nil
		}
		return 0, errors.New("Expired Token")
	}
	return 0, errors.New("Invalid token")
}

func generateToken(content uint64) Token {
	var token Token

	duration, _ := time.ParseDuration("1h") // TODO: Get by configuration
	token.Userid = content
	token.Expires = time.Now().Add(duration)

	userid := []byte(strconv.FormatUint(token.Userid, 10))
	expires := []byte(token.Expires.Format(time.RFC3339))

	secret := []byte("secret") // TODO: Get by configuration
	mac := hmac.New(sha256.New, secret)
	mac.Write(userid)
	mac.Write(expires)
	hash := mac.Sum(nil)

	token.Signature = string(hash)

	return token
}

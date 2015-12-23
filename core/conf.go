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
	"github.com/BurntSushi/toml"
	"time"
)

type Configuration struct {
	Secret     []byte
	Expiration time.Duration
}

var Conf Configuration

// Read the configuration file config.toml and store result in global Conf
func ReadConfiguration() error {
	var read struct {
		Secret     string
		Expiration string
	}

	path := "config.toml"
	_, err := toml.DecodeFile(path, &read)
	if err != nil {
		return err
	}

	Conf.Secret = []byte(read.Secret)
	Conf.Expiration, err = time.ParseDuration(read.Expiration)

	if err != nil {
		return err
	}
	return nil
}

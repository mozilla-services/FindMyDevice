package util
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"bufio"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

/* Craptastic typeless parser to read config values (use until things
   settle and you can use something more efficent like TOML)
*/

type JsMap map[string]interface{}

func MzGetConfig(filename string) JsMap {
	config := make(JsMap)
	// Yay for no equivalent to readln
	file, err := os.Open(filename)

	defer file.Close()

	if err != nil {
		log.Fatal(err)
	}
	reader := bufio.NewReader(file)
	for line, err := reader.ReadString('\n'); err == nil; line, err = reader.ReadString('\n') {
		// skip lines beginning with '#/;'
		if strings.Contains("#/;", string(line[0])) {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) < 2 {
			continue
		}
		config[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	if err != nil && err != io.EOF {
		log.Panic(err)
	}
	return config
}

// get a string value from the Interface Map, defaulting to def if
// not found
func MzGet(ma JsMap, key string, def string) string {
	if val, ok := ma[key].(string); ok {
		return val
	}
	return def
}

// get a boolean from the Interface map, defaulting for "false"
func MzGetFlag(ma JsMap, key string) (flag bool) {
	defer func() {
		if r := recover(); r != nil {
			flag = false
		}
	}()

	flag = false
	if val, ok := ma[key]; ok {
		flag, _ = strconv.ParseBool(val.(string))
	}

	return flag
}

// o4fs
// vim: set tabstab=4 softtabstop=4 shiftwidth=4 noexpandtab

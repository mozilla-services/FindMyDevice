/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package util

import (
	"fmt"
	"log"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

type Log struct {
	conf   *MzConfig
	trace  bool
	filter int64
}

// Message levels
const (
	CRITICAL = iota
	ERROR
	WARNING
	INFO
	DEBUG
)

// The fields to relay. NOTE: object reflection is VERY CPU expensive.
// I specify strings here to reduce that as much as possible. Please do
// not change this to something like map[string]interface{} since that
// can dramatically increase server load.
type Fields map[string]string

type Logger interface {
    Log(level int64, mtype, payload string, field Fields) error
    Info(mtype, payload string, field Fields) error
    Debug(mtype, payload string, field Fields) error
    Warn(mtype, payload string, field Fields) error
    Error(mtype, payload string, field Fields) error
    Critical(mtype, payload string, field Fields) error
}

// Create a new Heka logging interface.
func NewLogger(conf *MzConfig) *Log {
	//Preflight
	var filter int64

	filter, _ = strconv.ParseInt(conf.Get("logger.filter", "10"), 0, 0)

	return &Log{
		conf:   conf,
		trace:  conf.GetFlag("logger.show_caller"),
		filter: filter}
}

// Logging workhorse function. Chances are you're not going to call this
// directly, but via one of the helper methods. of Info() .. Critical()
// level - One of the defined logging CONST values
// mtype - Message type, Short class identifier for the message
// payload - Main error message
// fields - additional optional key/value data associated with the message.
func (r *Log) Log(level int64, mtype, payload string, fields Fields) (err error) {
	if level > r.filter {
		return
	}

	// Only print out the debug message if it's less than the filter.
	dump := fmt.Sprintf("[%d]% 7s: %s", level, mtype, payload)
	if len(fields) > 0 {
		var fld []string
		for key, val := range fields {
			fld = append(fld, key+": "+val)
		}
		dump = fmt.Sprintf("%s {%s}", dump, strings.Join(fld, ", "))
	}
	if r.trace {
		// add in go language tracing. (Also CPU intensive, but REALLY helpful
		// when dev/debugging)

		if pc, file, line, ok := runtime.Caller(2); ok {
			funk := runtime.FuncForPC(pc)
			dump = fmt.Sprintf("%s [%s:%s %s]", dump,
				file, strconv.FormatInt(int64(line), 0), funk.Name())
		}
	}
	log.Printf(dump)

	return nil
}

// record the lowest priority message
func (r *Log) Info(mtype, msg string, fields Fields) (err error) {
	return r.Log(INFO, mtype, msg, fields)
}

func (r *Log) Debug(mtype, msg string, fields Fields) (err error) {
	return r.Log(DEBUG, mtype, msg, fields)
}

func (r *Log) Warn(mtype, msg string, fields Fields) (err error) {
	return r.Log(WARNING, mtype, msg, fields)
}

func (r *Log) Error(mtype, msg string, fields Fields) (err error) {
	return r.Log(ERROR, mtype, msg, fields)
}

// record the Highest priority message, and include a printstack to STDERR
func (r *Log) Critical(mtype, msg string, fields Fields) (err error) {
	debug.PrintStack()
	return r.Log(CRITICAL, mtype, msg, fields)
}

// o4fs
// vim: set tabstab=4 softtabstop=4 shiftwidth=4 noexpandtab

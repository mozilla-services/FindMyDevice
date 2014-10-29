/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package util

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"
)

type Log struct {
	conf    *MzConfig
	filter  int32
	logName string
	logType string
	outfile string
	output  *os.File
}

// The fields to relay. NOTE: object reflection is VERY CPU expensive.
// I specify strings here to reduce that as much as possible. Please do
// not change this to something like map[string]interface{} since that
// can dramatically increase server load.
type Fields map[string]string

// Message levels
const (
	EMERGENCY = iota // Everything is broken and on fire
	ALERT            // We're broken.
	CRITICAL         // Someone else is broken, but it's breaking us
	ERROR            // Something bad happened.
	WARNING          // Huh, that's not supposed to happen, but we can deal with it.
	NOTICE           // That was odd, but not a big deal.
	INFO             // The thing you wanted to happen happened.
	DEBUG            // debugging.
)

var (
	levels = []string{"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING",
		"NOTICE", "INFO", "DEBUG"}
)

func marshalFields(fields Fields) (flist []*Field, err error) {
	flist = make([]*Field, len(fields))
	i := 0
	ty := Field_STRING
	for key, value := range fields {
		k := key
		ff := &Field{
			Name:        &k,
			ValueString: []string{value},
			ValueType:   &ty,
		}
		flist[i] = ff
		i++
	}
	return flist, nil
}

func newMessage(level int32, logName, mtype, payload string, fields Fields) *Message {
	msg := new(Message)

	ts := time.Now().UTC().Unix()
	hn, _ := os.Hostname()
	pid := int32(os.Getpid())
	envVersion := "1"

	msg.Uuid, _ = RawUUID4()
	msg.Timestamp = &ts
	msg.Type = &mtype
	msg.Logger = &logName
	msg.Hostname = &hn
	msg.EnvVersion = &envVersion // hardcoded logging envelope version
	msg.Pid = &pid
	msg.Payload = &payload
	msg.Severity = &level
	msg.Fields, _ = marshalFields(fields)
	return msg
}

// ===
type Logger interface {
	Log(level int32, mtype, payload string, field Fields) error
	Info(mtype, payload string, field Fields) error
	Debug(mtype, payload string, field Fields) error
	Warn(mtype, payload string, field Fields) error
	Error(mtype, payload string, field Fields) error
	Critical(mtype, payload string, field Fields) error
	Alert(mtype, payload string, field Fields) error
}

// Create a new Stdout logging interface.
func NewLogger(conf *MzConfig) *Log {
	//Preflight
	var filter int64
	var output *os.File
	var err error

	filter, _ = strconv.ParseInt(conf.Get("logger.filter", "3"), 0, 0)
	name := conf.Get("logger.loggername",
		fmt.Sprintf("%s %s", conf.Get("SERVER", "unknown"),
			conf.Get("VERSION", "Unknown")))
	outFile := conf.Get("logger.output", "STDOUT")
	switch strings.ToLower(outFile) {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		output, err = os.Create(outFile)
		if err != nil {
			panic(fmt.Sprintf("Could not open logging file %s, %s", outFile, err.Error))
		}
	}

	return &Log{
		conf:    conf,
		logName: name,
		logType: conf.Get("logger.logtype", "protobuf"),
		outfile: outFile,
		output:  output,
		filter:  int32(filter)}
}

// Logging workhorse function. Chances are you're not going to call this
// directly, but via one of the helper methods. of Info() .. Critical()
// level - One of the defined logging CONST values
// mtype - Message type, Short class identifier for the message
// payload - Main error message
// fields - additional optional key/value data associated with the message.
func (r *Log) Log(level int32, mtype, payload string, fields Fields) (err error) {
	// Only print out the debug message if it's less than the filter.
	if level > r.filter {
		return
	}

	var dump []byte
	msg := newMessage(level, r.logName, mtype, payload, fields)
	// switch eventually?
	switch r.logType {
	case "json":
		dump, err = json.Marshal(msg)
	case "human":
		dump, err = r.forHumans(msg)
	default:
		dump, err = msg.Marshal()
	}
	if err != nil {
		log.Printf("Error dumping log object %s", err)
	}
	fmt.Fprintln(r.output, string(dump))

	return nil
}

func (r *Log) Debug(mtype, msg string, fields Fields) (err error) {
	return r.Log(DEBUG, mtype, msg, fields)
}

func (r *Log) Info(mtype, msg string, fields Fields) (err error) {
	return r.Log(INFO, mtype, msg, fields)
}

func (r *Log) Warn(mtype, msg string, fields Fields) (err error) {
	return r.Log(WARNING, mtype, msg, fields)
}

func (r *Log) Error(mtype, msg string, fields Fields) (err error) {
	return r.Log(ERROR, mtype, msg, fields)
}

func (r *Log) Critical(mtype, msg string, fields Fields) (err error) {
	debug.PrintStack()
	return r.Log(CRITICAL, mtype, msg, fields)
}

func (r *Log) Alert(mtype, msg string, fields Fields) (err error) {
	debug.PrintStack()
	return r.Log(CRITICAL, mtype, msg, fields)
}

func (r *Log) Emergency(mtype, msg string, fields Fields) (err error) {
	debug.PrintStack()
	return r.Log(CRITICAL, mtype, msg, fields)
}

func (r *Log) forHumans(msg *Message) ([]byte, error) {
	reply := fmt.Sprintf("%s [% 8s] %s \"%s\" ",
		time.Unix(*msg.Timestamp, 0).Format("2006-01-02 03:04:05"),
		levels[*msg.Severity],
		*msg.Type,
		*msg.Payload)
	if msg.Fields != nil {
		var ff = make([]string, len(msg.Fields))
		for i, f := range msg.Fields {
			ff[i] = fmt.Sprintf("%s:%s", *f.Name, f.ValueString[0])
			i++
		}
		reply = reply + strings.Join(ff, ", ")
	}
	return []byte(reply), nil

}

// ====

type TestLog struct {
	T   *testing.T
	Out string
}

func (r *TestLog) Log(level int32, mtype, payload string, fields Fields) error {
	r.Out = fmt.Sprintf("[% 8s] %s:%s %+v", levels[level], mtype, payload, fields)
	r.T.Log(r.Out)
	return nil
}

func (r *TestLog) Info(mtype, msg string, fields Fields) error {
	return r.Log(INFO, mtype, msg, fields)
}

func (r *TestLog) Debug(mtype, msg string, fields Fields) error {
	return r.Log(DEBUG, mtype, msg, fields)
}

func (r *TestLog) Warn(mtype, msg string, fields Fields) error {
	return r.Log(WARNING, mtype, msg, fields)
}

func (r *TestLog) Error(mtype, msg string, fields Fields) error {
	return r.Log(ERROR, mtype, msg, fields)
}

func (r *TestLog) Critical(mtype, msg string, fields Fields) error {
	return r.Log(CRITICAL, mtype, msg, fields)
}

func (r *TestLog) Alert(mtype, msg string, fields Fields) error {
	return r.Log(ALERT, mtype, msg, fields)
}

func (r *TestLog) Emergency(mtype, msg string, fields Fields) error {
	return r.Log(EMERGENCY, mtype, msg, fields)
}

// o4fs
// vim: set tabstab=4 softtabstop=4 shiftwidth=4 noexpandtab

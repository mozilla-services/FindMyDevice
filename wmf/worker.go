package wmf

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"code.google.com/p/go.net/websocket"
	"github.com/mozilla-services/FindMyDevice/util"
	"github.com/mozilla-services/FindMyDevice/wmf/storage"

	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

var (
	ErrInvalidSocket = errors.New("Invalid socket type specified")
)

type Worker interface {
	Run()
}

// Interface for Socket calls (with limited calls we need)
type Sock interface {
	Close() error
	IsClientConn() bool
	Write([]byte) (int, error)
}

// Mock Websocket Interface (used for testing)
type MockWSConn struct {
	Buff      []byte
	Connected bool
}

func (r *MockWSConn) Receive() []byte { return r.Buff }
func (r *MockWSConn) Write(b []byte) (int, error) {
	r.Buff = b
	return len(b), nil
}
func (*MockWSConn) Close() error         { return nil }
func (r *MockWSConn) IsClientConn() bool { return r.Connected }

// Websocket Handler function.
type WWS interface {
	Run()
	Close() error
	Born() time.Time
	Device() *storage.Device
	Handler() *Handler
	Logger() util.Logger
	Socket() Sock
}

type WWSs struct {
	socket  Sock
	logger  util.Logger
	handler *Handler
	device  *storage.Device
	born    time.Time
	input   chan []byte
	quitter chan struct{}
	output  chan []byte
}

// Snif the incoming socket for data
func (self *WWSs) sniffer() (err error) {
	var (
		raw    = make([]byte, 1024)
		socket = self.Socket()
	)

	defer func() {
		lived := int64(time.Now().Sub(self.Born()).Seconds())
		self.logger.Debug("worker",
			"Closing Sniffer",
			util.Fields{"seconds_lived": strconv.FormatInt(lived, 10)})
		// tell the receiver to close.
		close(self.quitter)
	}()

	for {
		switch socket.(type) {
		case *websocket.Conn:
			err = websocket.Message.Receive(socket.(*websocket.Conn), &raw)
		case *MockWSConn:
			raw = socket.(*MockWSConn).Receive()
		default:
			self.logger.Error("worker",
				"Invalid socket type specified.",
				nil)
			return ErrInvalidSocket
		}
		if err != nil {
			switch {
			case err == io.EOF:
				self.logger.Debug("worker",
					"Closing channel",
					nil)
			default:
				self.logger.Error("worker",
					"Unhandled error in reader",
					util.Fields{"error": err.Error()})
			}
			return err
		}
		if len(raw) <= 0 {
			continue
		}
		self.logger.Debug("worker",
			"#### Recv'd",
			util.Fields{"raw": string(raw)})
		self.input <- raw
	}
}

func (self *WWSs) Close() error {
	close(self.quitter)
	return nil
}

func (r *WWSs) Socket() Sock {
	return r.socket
}

func (r *WWSs) Logger() util.Logger {
	return r.logger
}

func (r *WWSs) Handler() *Handler {
	return r.handler
}

func (r *WWSs) Born() time.Time {
	return r.born
}

func (r *WWSs) Device() *storage.Device {
	return r.device
}

// Workhorse function.
func (self *WWSs) Run() {
	self.input = make(chan []byte)
	self.quitter = make(chan struct{})
	self.output = make(chan []byte)

	defer func(sock WWS) {
		if r := recover(); r != nil {
			err := r.(error)
			switch {
			case err == io.EOF:
				lived := int64(time.Now().Sub(self.Born()).Seconds())
				sock.Logger().Debug("worker", "Closing Socket",
					util.Fields{"seconds_lived": strconv.FormatInt(lived, 10)})
			default:
				sock.Logger().Error("worker",
					"Unhandled error in Run",
					util.Fields{"error": r.(error).Error()})
			}
		}
		sock.Logger().Debug("worker", "#### Cleaning up...", nil)
		if self.quitter != nil {
			close(self.quitter)
		}
		return
	}(self)

	go self.sniffer()

	for {
		select {
		case <-self.quitter:
			self.logger.Debug("worker",
				"Killing client",
				util.Fields{"deviceId": self.device.ID})
			self.socket.Close()
			close(self.input)
			// don't reclose this channel.
			self.quitter = nil
			return
		case input := <-self.input:
			msg := make(replyType)
			if err := json.Unmarshal(input, &msg); err != nil {
				self.logger.Error("worker", "Unparsable cmd",
					util.Fields{"cmd": string(input),
						"error": err.Error()})
				self.socket.Write([]byte("false"))
				continue
			}
			rep := make(replyType)
			for cmd, args := range msg {
				rargs := args.(replyType)
				_, err := self.handler.Queue(self.device, cmd, &rargs, &rep)
				if err != nil {
					self.logger.Error("worker", "Error processing command",
						util.Fields{
							"error": err.Error(),
							"cmd":   cmd,
							"args":  fmt.Sprintf("%+v", args)})
					self.socket.Write([]byte("false"))
					break
				}
			}
			self.socket.Write([]byte("true"))
		case output := <-self.output:
			_, err := self.socket.Write(output)
			if err != nil {
				self.logger.Error("worker",
					"Unhandled error writing to socket",
					util.Fields{"error": err.Error()})
			}
		}
	}
}

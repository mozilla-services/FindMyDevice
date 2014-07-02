package wmf

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"code.google.com/p/go.net/websocket"
	"github.com/mozilla-services/FindMyDevice/util"
	"github.com/mozilla-services/FindMyDevice/wmf/storage"

	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Websocket Handler function.
type WWS struct {
	Socket  *websocket.Conn
	Logger  *util.HekaLogger
	Handler *Handler
	Device  *storage.Device
	Born    time.Time
	Quit    bool
	input   chan string
	quitter chan bool
	output  chan []byte
}

// Snif the incoming socket for data
func (self *WWS) sniffer() {
	var (
		raw    = make([]byte, 1024)
		err    error
		socket = self.Socket
	)

	defer func() {
		lived := int64(time.Now().Sub(self.Born).Seconds())
		self.Logger.Debug("worker",
			"Closing Sniffer",
			util.Fields{"seconds_lived": strconv.FormatInt(lived, 10)})
	}()

	for {
		if self.Quit {
			socket.Close()
			return
		}
		err = websocket.Message.Receive(socket, &raw)
		if err != nil {
			switch {
			case err == io.EOF:
				self.Logger.Debug("worker",
					"Closing channel",
					nil)
			default:
				self.Logger.Error("worker",
					"Unhandled error in reader",
					util.Fields{"error": err.Error()})
			}
			self.quitter <- true
			return
		}
		if len(raw) <= 0 {
			continue
		}
		self.input <- string(raw)
	}
}

// Workhorse function.
func (self *WWS) Run() {
	self.input = make(chan string)
	self.quitter = make(chan bool)
	self.output = make(chan []byte)

	defer func(sock *WWS) {
		if r := recover(); r != nil {
			err := r.(error)
			switch {
			case err == io.EOF:
				lived := int64(time.Now().Sub(self.Born).Seconds())
				sock.Logger.Debug("worker", "Closing Socket",
					util.Fields{"seconds_lived": strconv.FormatInt(lived, 10)})
			default:
				sock.Logger.Error("worker",
					"Unhandled error in Run",
					util.Fields{"error": r.(error).Error()})
			}
		}
		sock.Logger.Debug("worker", "Cleaning up...", nil)
		sock.Socket.Close()
		return
	}(self)

	go self.sniffer()

	for {
		select {
		case <-self.quitter:
			self.Quit = true
			self.Logger.Debug("worker",
				"Killing client",
				util.Fields{"deviceId": self.Device.ID})
			return
		case input := <-self.input:
			msg := make(replyType)
			if err := json.Unmarshal([]byte(input), &msg); err != nil {
				self.Logger.Error("worker", "Unparsable cmd",
					util.Fields{"cmd": input,
						"error": err.Error()})
				self.Socket.Write([]byte("false"))
				continue
			}
			rep := make(replyType)
			for cmd, args := range msg {
				rargs := args.(replyType)
				_, err := self.Handler.Queue(self.Device, cmd, &rargs, &rep)
				if err != nil {
					self.Logger.Error("worker", "Error processing command",
						util.Fields{
							"error": err.Error(),
							"cmd":   cmd,
							"args":  fmt.Sprintf("%+v", args)})
					self.Socket.Write([]byte("false"))
					break
				}
			}
			self.Socket.Write([]byte("true"))
		case output := <-self.output:
			_, err := self.Socket.Write(output)
			if err != nil {
				self.Logger.Error("worker",
					"Unhandled error writing to socket",
					util.Fields{"error": err.Error()})
			}
		}
	}
}

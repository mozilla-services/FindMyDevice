/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package wmf

import (
	"code.google.com/p/go.net/websocket"
	"mozilla.org/util"

	"io"
    "strconv"
	"time"
)

type WWS struct {
	Socket  *websocket.Conn
	Logger  *util.HekaLogger
	Born    time.Time
	Quit    bool
	input   chan string
	quitter chan bool
	output  chan []byte
}

func (self *WWS) sniffer() {
	var (
		raw    []byte = make([]byte, 1024)
		err    error
		socket = self.Socket
	)

	defer func() {
        lived := int64(time.Now().Sub(self.Born).Seconds())
        self.Logger.Debug("worker",
            "Closing go routine",
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

func (self *WWS) Run() {
	self.input = make(chan string)
	self.quitter = make(chan bool)
    self.output = make(chan []byte)

	defer func(sock *WWS) {
		if r := recover(); r != nil {
			err := r.(error)
			switch {
			case err == io.EOF:
				sock.Logger.Debug("worker", "Closing socket", nil)
			default:
				sock.Logger.Error("worker",
					"Unhandled error in Run",
					util.Fields{"error": r.(error).Error()})
			}
			sock.quitter <- true
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
			return
		case input := <-self.input:
            self.Logger.Debug("worker",
                "ignoring input",
                util.Fields{
                    "input": input[:100],
                    "len": strconv.FormatInt(int64(len(input)), 10)})
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

func (self *WWS) Write(out []byte) {
	self.output <- out
}

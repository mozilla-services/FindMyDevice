/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package util

import (
	"strings"
	"sync"
	"sync/atomic"

	//	"github.com/cactus/go-statsd-client/statsd"
)

var metrex sync.Mutex

type Metrics struct {
	dict   map[string]int64
	prefix string
	//  statsdc *statsd.Client
}

func NewMetrics(prefix string) (self *Metrics) {
	self = &Metrics{
		dict:   make(map[string]int64),
		prefix: prefix,
	}
	return self
}

func (self *Metrics) Prefix(newPrefix string) {
	self.prefix = strings.TrimRight(newPrefix, ".")
}

/*
func (self *Metrics) StatsdTarget(target string) (err error) {
	self.statsdc, err = statsd.New(target, self.prefix)
	if err != nil {
		return
	}
	return
}
*/
func (self *Metrics) Snapshot() map[string]int64 {
	defer metrex.Unlock()
	metrex.Lock()
	oldMetrics := make(map[string]int64)
	// copy the old metrics
	for k, v := range self.dict {
		oldMetrics[k] = v
	}
	return oldMetrics
}

func (self *Metrics) IncrementBy(metric string, count int) {
	defer metrex.Unlock()
	metrex.Lock()
	m, ok := self.dict[metric]
	if !ok {
		self.dict[metric] = int64(0)
		m = self.dict[metric]
	}
	atomic.AddInt64(&m, int64(count))
	self.dict[metric] = m
	/*	if statsdc != nil {
			statsdc.Inc(metric, int64(count), 1.0)
		}
	*/
}

func (self *Metrics) Increment(metric string) {
	self.IncrementBy(metric, 1)
}

func (self *Metrics) Decrement(metric string) {
	self.IncrementBy(metric, -1)
}

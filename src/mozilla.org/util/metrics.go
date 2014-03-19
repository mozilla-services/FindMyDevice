package util
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
    "time"

    "github.com/cactus/go-statsd-client/statsd"
)

var metrex sync.Mutex

// Metrics tracker
// This is a statsd like aggregator of run info.
type Metrics struct {
	dict   map[string]int64     // counters
    timer  map[string]float64   // timers
	prefix string               // prefix for
	logger *HekaLogger
	statsd *statsd.Client
    born   time.Time
}


// generate a new Metrics object
func NewMetrics(prefix string, logger *HekaLogger, config JsMap) (self *Metrics) {

    var statsdc *statsd.Client
    if server, ok := config["statsd.server"].(string); ok {
        name := strings.ToLower(MzGet(config, "statsd.name", "undef"))
        client, err := statsd.New(server, name)
        if err != nil {
            logger.Error("metrics", "Could not init statsd connection",
                Fields{"error": err.Error()})
            } else {
                statsdc = client
            }
        }


	self = &Metrics{
		dict:   make(map[string]int64),
        timer:  make(map[string]float64),
		prefix: prefix,
		logger: logger,
        statsd: statsdc,
        born:   time.Now(),
	}
	return self
}

// Set the default prefix for the Metrics
func (self *Metrics) Prefix(newPrefix string) {
	self.prefix = strings.TrimRight(newPrefix, ".")
    if self.statsd != nil {
        self.statsd.SetPrefix(newPrefix);
    }
}

// Return a snapshot of the current metric information.
// This will return a running average of the timers.
func (self *Metrics) Snapshot() map[string]interface{} {
	defer metrex.Unlock()
	metrex.Lock()
    var pfx string
    if len(self.prefix) > 0 {
        pfx = self.prefix + "."
    }
	oldMetrics := make(map[string]interface{})
	// copy the old metrics
	for k, v := range self.dict {
		oldMetrics[pfx + "counter." + k] = v
	}
    for k, v := range self.timer {
        oldMetrics[pfx + "avg_timer." + k] = v
    }
    oldMetrics[pfx + "age.server"] = time.Now().Unix() - self.born.Unix();
	return oldMetrics
}

// Increment a counter and report it to statsd (if defined)
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
	if self.logger != nil {
		self.logger.Info("metrics", "counter."+metric,
			Fields{"value": strconv.FormatInt(m, 10),
                   "type": "counter"})
	}
    if self.statsd != nil {
        if count >= 0 {
            self.statsd.Inc(metric, int64(count), 1.0)
        } else {
            self.statsd.Dec(metric, int64(count), 1.0)
        }
    }
}

// Convenience functions
func (self *Metrics) Increment(metric string) {
	self.IncrementBy(metric, 1)
}

func (self *Metrics) Decrement(metric string) {
	self.IncrementBy(metric, -1)
}

// Record a timer to statsd, and generate a running average for the snapshot
func (self *Metrics) Timer(metric string, value int64) {
	defer metrex.Unlock()
	metrex.Lock()
    if m, ok := self.timer[metric]; !ok {
        self.timer[metric] = float64(value)
    } else {
        // calculate running average
        fv := float64(value)
        dm := (fv - m)/2
        switch {
        case fv < m:
            self.timer[metric] = m - dm
        case fv > m:
            self.timer[metric] = m + dm
        }
    }

	if self.logger != nil {
		self.logger.Info("metrics", "timer."+metric,
			Fields{"value": strconv.FormatInt(value, 10),
				"type": "timer"})
	}
    if self.statsd != nil {
        self.statsd.Timing(metric, value, 1.0)
    }
}

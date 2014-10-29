/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package storage

import (
	"github.com/mozilla-services/FindMyDevice/util"

	"fmt"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type udmap struct {
	DeviceID string
	Name     string
}

type cst struct {
	CType   string
	Command string
}

type memStore struct {
	config       *util.MzConfig
	logger       util.Logger
	metrics      util.Metrics
	users        map[string]udmap
	devices      map[string]*Device
	positions    map[string]*Position
	commands     map[string]map[int64]*cst
	accessTokens map[string]string
	nonces       map[string]string
}

// Open the database.
func OpenInmemory(config *util.MzConfig, logger util.Logger, metrics util.Metrics) (storage Storage, err error) {
	return &memStore{
		config:       config,
		logger:       logger,
		users:        make(map[string]udmap),
		devices:      make(map[string]*Device),
		positions:    make(map[string]*Position),
		commands:     make(map[string]map[int64]*cst),
		accessTokens: make(map[string]string),
		nonces:       make(map[string]string),
	}, nil
}

// Create the tables, indexes and other needed items.
func (r *memStore) Init() (err error) {
	return nil
}

func (r *memStore) RegisterDevice(userid string, dev *Device) (devId string, err error) {

	if dev.ID == "" {
		dev.ID, _ = util.GenUUID4()
	}

	r.devices[dev.ID] = dev
	r.users[userid] = udmap{dev.ID, dev.Name}
	return dev.ID, nil
}

// Return known info about a device.
func (r *memStore) GetDeviceInfo(devId string) (devInfo *Device, err error) {

	devInfo, ok := r.devices[devId]
	if !ok {
		return nil, ErrUnknownDevice
	}
	return devInfo, nil
}

func (r *memStore) GetPositions(devId string) (positions []Position, err error) {
	pos, ok := r.positions[devId]
	if !ok {
		return nil, ErrUnknownDevice
	}
	return append(positions, *pos), nil
}

// Get pending commands.
func (r *memStore) GetPending(devId string) (cmd, ctype string, err error) {

	cmds, ok := r.commands[devId]
	if !ok {
		return "", "", ErrUnknownDevice
	}

	var keys []int
	for k := range cmds {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	cmd = cmds[int64(keys[0])].Command
	ctype = cmds[int64(keys[0])].CType
	delete(cmds, int64(keys[0]))
	r.commands[devId] = cmds
	return
}

func (r *memStore) GetUserFromDevice(deviceId string) (userId, name string, err error) {

	devInfo, ok := r.devices[deviceId]
	if !ok {
		return "", "", ErrUnknownDevice
	}
	return devInfo.User, devInfo.Name, nil
}

// Get all known devices for this user.
func (r *memStore) GetDevicesForUser(userId, oldUserId string) (devices []DeviceList, err error) {

	user, ok := r.users[userId]
	if !ok {
		return nil, ErrUnknownDevice
	}
	devInfo, ok := r.devices[user.DeviceID]
	if !ok {
		return nil, ErrUnknownDevice
	}
	return append(devices, DeviceList{user.DeviceID, devInfo.Name}), nil
}

// Store a command into the list of pending commands for a device.
func (r *memStore) StoreCommand(devId, command, cType string) (err error) {

	if _, ok := r.commands[devId]; !ok {
		r.commands[devId] = make(map[int64]*cst)
	}
	r.commands[devId][time.Now().Unix()] = &cst{Command: command, CType: cType}
	return nil
}

func (r *memStore) SetAccessToken(devId, token string) (err error) {

	r.accessTokens[devId] = token
	return nil
}

// Shorthand function to set the lock state for a device.
func (r *memStore) SetDeviceLock(devId string, state bool) (err error) {

	devInfo, ok := r.devices[devId]
	if !ok {
		return ErrUnknownDevice
	}
	devInfo.HasPasscode = state
	r.devices[devId] = devInfo
	return nil
}

// Add the location information to the known set for a device.
func (r *memStore) SetDeviceLocation(devId string, position *Position) (err error) {
	r.positions[devId] = position
	return nil
}

// Remove old postion information for devices.
// This previously removed "expired" location records. We currently only
// retain the latest record for a user.
func (*memStore) GcDatabase(devId, userId string) (err error) {
	return nil
}

// remove all tracking information for devId.
func (r *memStore) PurgePosition(devId string) (err error) {
	delete(r.positions, devId)
	return nil
}

func (*memStore) Touch(devId string) (err error) {
	return nil
}

func (r *memStore) DeleteDevice(devId string) (err error) {
	delete(r.positions, devId)
	delete(r.devices, devId)
	delete(r.commands, devId)
	delete(r.accessTokens, devId)
	return nil
}

func (r *memStore) PurgeCommands(devId string) (err error) {

	delete(r.commands, devId)
	return nil
}

func (*memStore) Close() {
	return
}

func (r *memStore) GetNonce() (string, error) {
	key, _ := util.GenUUID4()
	val, _ := util.GenUUID4()

	r.nonces[key] = val
	return fmt.Sprintf("%s-%s", key, val), nil
}

// Does the user's nonce match?
func (r *memStore) CheckNonce(nonce string) (bool, error) {

	items := strings.Split(nonce, "-")
	val, ok := r.nonces[items[0]]
	delete(r.nonces, items[0])
	return ok && val == items[1], nil
}

func init() {
	AvailableStores["inmemory"] = OpenInmemory
}

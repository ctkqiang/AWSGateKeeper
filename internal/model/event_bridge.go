// Package model (event_bridge.go) defines the EventBridge event envelope.
package model

import "time"

// EventBridgeEvent is the structured event payload published to a
// custom EventBridge bus for downstream consumption.
type EventBridgeEvent struct {
	Version    string                 `json:"version"`
	ID         string                 `json:"id"`
	DetailType string                 `json:"detail-type"`
	Source     string                 `json:"source"`
	Time       time.Time              `json:"time"`
	Detail     map[string]interface{} `json:"detail"`
}

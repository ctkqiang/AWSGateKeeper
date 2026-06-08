package model

import "time"

type EventBridgeEvent struct {
	Version    string                 `json:"version"`
	ID         string                 `json:"id"`
	DetailType string                 `json:"detail-type"`
	Source     string                 `json:"source"`
	Time       time.Time              `json:"time"`
	Detail     map[string]interface{} `json:"detail"`
}

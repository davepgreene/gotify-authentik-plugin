package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

type AuthentikWebhookPayload struct {
	Body              string `json:"body"`
	EventUserEmail    string `json:"event_user_email"`
	EventUserUsername string `json:"event_user_username"`
	Severity          string `json:"severity"`
	UserEmail         string `json:"user_email"`
	UserUsername      string `json:"user_username"`
}

type LoginFailedData struct {
	ASN         ASN         `json:"asn"`
	Geo         Geo         `json:"geo"`
	Stage       Stage       `json:"stage"`
	Username    string      `json:"username"`
	DeviceClass string      `json:"device_class,omitempty"`
	Password    string      `json:"password,omitempty"`
	HTTPRequest HTTPRequest `json:"http_request"`
}

type LoginData struct {
	ASN            ASN            `json:"asn"`
	Geo            Geo            `json:"geo"`
	AuthMethod     string         `json:"auth_method"`
	HTTPRequest    HTTPRequest    `json:"http_request"`
	AuthMethodArgs AuthMethodArgs `json:"auth_method_args"`
}

type ASN struct {
	ASN     int    `json:"asn"`
	ASOrg   string `json:"as_org"`
	Network string `json:"network"`
}

type Geo struct {
	Lat       float64 `json:"lat"`
	City      string  `json:"city"`
	Long      float64 `json:"long"`
	Country   string  `json:"country"`
	Continent string  `json:"continent"`
}

type Stage struct {
	PK        string `json:"pk"`
	App       string `json:"app"`
	Name      string `json:"name"`
	ModelName string `json:"model_name"`
}

type HTTPRequest struct {
	Args      map[string]string `json:"args"`
	Path      string            `json:"path"`
	Method    string            `json:"method"`
	RequestID string            `json:"request_id"`
	UserAgent string            `json:"user_agent"`
}

type AuthMethodArgs struct {
	MFADevices []MFADevice `json:"mfa_devices"`
}

type MFADevice struct {
	PK        int    `json:"pk"`
	App       string `json:"app"`
	Name      string `json:"name"`
	ModelName string `json:"model_name"`
}

func ReturnGotifyMessageFromAuthentikPayload(payload AuthentikWebhookPayload) (string, string, int) {
	if strings.HasPrefix(payload.Body, "login_failed: ") {
		var data LoginFailedData
		bodyContent := strings.TrimPrefix(payload.Body, "login_failed: ")
		bodyContent = strings.ReplaceAll(bodyContent, "'", "\"")

		if err := json.Unmarshal([]byte(bodyContent), &data); err != nil {
			return "Error parsing login_failed data", err.Error(), 7
		}

		title := fmt.Sprintf("Login failed for %s", payload.EventUserUsername)
		message := fmt.Sprintf("Logging attempt failed for user: %s \n\nFrom: %s, %s, %s \n\nFailed at stage: %s \n\nRequestID: %s", payload.EventUserUsername, data.Geo.City, data.Geo.Country, data.Geo.Continent, data.Stage.Name, data.HTTPRequest.RequestID)

		return title, message, 8

	} else if strings.HasPrefix(payload.Body, "login: ") {
		var data LoginData
		bodyContent := strings.TrimPrefix(payload.Body, "login: ")
		bodyContent = strings.ReplaceAll(bodyContent, "'", "\"")

		if err := json.Unmarshal([]byte(bodyContent), &data); err != nil {
			fmt.Println("Error parsing login data:", err)
			return "Error parsing login_failed data", err.Error(), 7
		}

		title := fmt.Sprintf("%s just logged in", payload.EventUserUsername)
		message := fmt.Sprintf("Successful login from user: %s \n\nFrom: %s, %s, %s \n\nRequestID: %s", payload.EventUserUsername, data.Geo.City, data.Geo.Country, data.Geo.Continent, data.HTTPRequest.RequestID)

		return title, message, 5

	} else {
		title := "Unrecognized Event"
		message := payload.Body
		return title, message, 5
	}
}

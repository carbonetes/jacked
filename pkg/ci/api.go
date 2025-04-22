package ci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	// Convert link to test / prod url
	patURL             = "http://localhost:3001/personal-access-token/is-expired"
	fetchVulnResultURL = "http://localhost:3005/vulnerability/plugin-repo"
)

// Response format
type TokenCheckResponse struct {
	Expired     bool `json:"expired"`
	Permissions []struct {
		Label       string   `json:"label"`
		Permissions []string `json:"permissions"`
	} `json:"permissions"`
	Code string `json:"code"`
}

func PersonalAccessToken(token string) {

	// JSON request payload
	payload := map[string]string{
		"token": token,
	}

	// Marshal into JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	// Perform HTTP POST request
	resp, err := http.Post(patURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read response body (modern way)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// Unmarshal the body into the struct
	var result TokenCheckResponse
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("Failed to parse response:", err)
		os.Exit(1)
	}

	if resp.StatusCode != 200 {
		fmt.Println("Status Code:", resp.StatusCode)
		fmt.Println("Response Body:", string(body))
		os.Exit(1)
	}
}

package ci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
)

const (
	// Convert link to test / prod url
	tokenURL = "http://localhost:3001/personal-access-token/is-expired"
	saveURL  = "http://localhost:3001/integrations/vuln/plugin/save"
)

var tokenId = "0"

func PersonalAccessToken(token string) {

	// Payload
	payload := map[string]string{
		"token": token,
	}

	// Perform HTTP POST request
	resp, body := apiRequest(payload, tokenURL)
	// ---------------

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
	tokenId = result.PersonalAccessTokenId
	if result.PersonalAccessTokenId == "" {
		fmt.Println("Status Code:", resp.StatusCode)
		fmt.Println("Error: Unable to fetch token id.")
		os.Exit(1)
	}
}

func SavePluginRepository(bom *cyclonedx.BOM, repoName string, pluginName string, start time.Time) {

	var componentsJSONString string
	var vulnerabilitiesJSONString string
	if bom == nil || bom.Vulnerabilities == nil || bom.Components == nil {
		// Empty State
		componentsJSONString = ""
		vulnerabilitiesJSONString = ""

	} else {

		// Components
		compBytes, err := json.Marshal(bom.Components)
		if err != nil {
			fmt.Println("Failed to marshal components:", err)
			os.Exit(1)
		}
		componentsJSONString = string(compBytes)

		// Vulnerabilities
		vulnBytes, err := json.Marshal(bom.Vulnerabilities)
		if err != nil {
			fmt.Println("Failed to marshal components:", err)
			os.Exit(1)
		}
		vulnerabilitiesJSONString = string(vulnBytes)

	}

	// Payload
	payload := map[string]interface{}{
		"repoName":              repoName,
		"personalAccessTokenId": tokenId,
		"pluginName":            pluginName,
		"components":            componentsJSONString,
		"vulnerabilities":       vulnerabilitiesJSONString,
		"duration":              fmt.Sprintf("%.2f", time.Since(start).Seconds()),
	}

	// Perform HTTP POST request
	resp, body := apiRequest(payload, saveURL)
	// ---------------

	var result PluginRepo

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

func apiRequest(payload any, url string) (*http.Response, []byte) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	// Perform HTTP POST request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read response body (modern way)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return resp, body

}

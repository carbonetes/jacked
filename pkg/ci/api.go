package ci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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
	resp, body := apiRequest(payload)
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

func SavePluginRepository(bom *cyclonedx.BOM, repoName string, pluginType string, start time.Time) {

	vulnAnalysis := map[string]interface{}{}
	if bom == nil || bom.Vulnerabilities == nil || bom.Components == nil {
		vulnAnalysis = nil
	} else {
		tally := tally(*bom.Vulnerabilities)
		vulnAnalysis = map[string]interface{}{
			"status":     "analyzed",
			"duration":   time.Since(start).Seconds(),
			"critical":   tally.Critical,
			"high":       tally.High,
			"medium":     tally.Medium,
			"low":        tally.Low,
			"negligible": tally.Negligible,
			"unknown":    tally.Negligible,
			"os":         "",
			"app":        "",
		}
	}

	// Payload
	payload := map[string]interface{}{
		"personalAccessTokenId": tokenId,
		"pluginType":            pluginType,
		"repoName":              repoName,
		"latestVulnAnalysis":    vulnAnalysis,
	}
	// Perform HTTP POST request
	resp, body := apiRequest(payload)
	// ---------------

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

func apiRequest(payload any) (*http.Response, []byte) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	// Perform HTTP POST request
	resp, err := http.Post(tokenURL, "application/json", bytes.NewBuffer(jsonData))
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

func tally(vulns []cyclonedx.Vulnerability) Tally {
	var tally Tally
	for _, v := range vulns {
		if v.Ratings == nil {
			tally.Unknown++
			continue
		}
		if len(*v.Ratings) == 0 {
			tally.Unknown++
			continue
		}
		for _, r := range *v.Ratings {

			switch strings.ToLower(string(r.Severity)) {
			case "negligible":
				tally.Negligible++
			case "low":
				tally.Low++
			case "medium":
				tally.Medium++
			case "high":
				tally.High++
			case "critical":
				tally.Critical++
			default:
				tally.Unknown++
			}
		}
	}
	return tally
}

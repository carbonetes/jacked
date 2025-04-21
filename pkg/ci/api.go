package ci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func PersonalAccessToken() {
	// API endpoint
	url := "http://localhost:3001/personal-access-token/is-expired"

	// request body
	data := map[string]string{
		"token": "cn_dlL2EhSRpPkOvQRP8hiD6G4F",
	}

	// Convert map to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	// Make the POST request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read and print the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != 200 {
		fmt.Println("Status Code:", resp.StatusCode)
		fmt.Println("Response Body:", string(body))
		os.Exit(1)
	}
}

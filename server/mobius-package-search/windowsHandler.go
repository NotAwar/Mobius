package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

func windowsHandler(w http.ResponseWriter, r *http.Request) {

	// Original response structs
	type ManifestSearchData struct {
		PackageIdentifier string `json:"PackageIdentifier"`
		PackageName       string `json:"PackageName"`
		Publisher         string `json:"Publisher"`
	}

	type ManifestSearchResponse struct {
		Data []ManifestSearchData `json:"Data"`
	}

	// Simplified output struct
	type SimplifiedApp struct {
		Name              string `json:"name"`
		Publisher         string `json:"publisher"`
		PackageIdentifier string `json:"packageIdentifier"`
	}

	result := SearchResult{}

	w.Header().Set("Content-Type", "application/json")
	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
	}

	type QueryBody struct {
		Query struct {
			KeyWord   string `json:"KeyWord"`
			MatchType string `json:"MatchType"`
		} `json:"Query"`
	}

	requestBody := QueryBody{}
	requestBody.Query.KeyWord = req.Search
	requestBody.Query.MatchType = "Substring"

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		log.Fatalf("Failed to marshal request body: %v", err)
	}

	request, err := http.NewRequest("POST", "https://storeedgefd.dsx.mp.microsoft.com/v9.0/manifestSearch", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	var original ManifestSearchResponse
	if err := json.Unmarshal(body, &original); err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	var simplified []SimplifiedApp
	for _, item := range original.Data {
		if len(req.Exclude) == 0 ||
			!strings.Contains(item.PackageName, req.Exclude) {
			simplified = append(simplified, SimplifiedApp{
				Name:              item.PackageName,
				Publisher:         item.Publisher,
				PackageIdentifier: item.PackageIdentifier,
			})
		}
	}
	result.Output = simplified
	json.NewEncoder(w).Encode(result)

}

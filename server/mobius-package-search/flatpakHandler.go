package main

import (
	"encoding/json"
	"net/http"
)

func flatpakHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	output, err := runScript("./flatpak-search.sh", req.Search, req.Exclude, "")
	var res interface{}
	err = json.Unmarshal([]byte(output), &res)
	result := SearchResult{Output: res}
	if err != nil {
		result.Error = err.Error()
	}

	json.NewEncoder(w).Encode(result)
}

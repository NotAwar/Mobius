package main

import (
	"encoding/json"
	"net/http"
)

func aptHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	output, err := runScript("./apt-search.sh", req.Search, req.Exclude, req.Section)
	var res interface{}
	err = json.Unmarshal([]byte(output), &res)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
	}
	result := SearchResult{Output: res}
	if err != nil {
		result.Error = err.Error()
	}

	json.NewEncoder(w).Encode(result)
}

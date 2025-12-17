package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"

	"github.com/gorilla/mux"
)

func aptHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		printLog("Invalid request", LogLevelError, req)
		return
	}

	printLog("Apt request received", LogLevelInfo, req)

	output, _ := runScript("./apt-search.sh", req.Search, req.Exclude, req.Section)
	var res interface{}
	err := json.Unmarshal([]byte(output), &res)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
	}
	result := SearchResult{Output: res}
	if err != nil {
		result.Error = err.Error()
	}

	json.NewEncoder(w).Encode(result)
}

func aptAddRepo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	repo := mux.Vars(r)["repo"]

	cmd := exec.Command(fmt.Sprintf("apt update && apt install software-properties-common -y && add-apt-repository %s", repo))
	output, _ := cmd.CombinedOutput()

	result := SearchResult{Output: string(output)}
	json.NewEncoder(w).Encode(result)
}

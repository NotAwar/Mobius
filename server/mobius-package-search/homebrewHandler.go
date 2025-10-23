package main

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
)

func homebrewHandler(w http.ResponseWriter, r *http.Request) {
	type Formula struct {
		Name     string   `json:"name"`
		Desc     string   `json:"desc"`
		Homepage string   `json:"homepage"`
		_        struct{} `json:"-"` // ignore extra fields
		Versions struct {
			Stable string `json:"stable"`
		} `json:"versions"`
		Bottle struct {
			Stable struct {
				Files map[string]interface{} `json:"files"`
			} `json:"stable"`
		} `json:"bottle"`
	}

	type Result struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Version     string `json:"version"`
		Homepage    string `json:"homepage"`
	}

	w.Header().Set("Content-Type", "application/json")
	result := SearchResult{}

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Compile regexps for search/exclude (case-insensitive)
	searchRe, err := regexp.Compile("(?i)" + regexp.QuoteMeta(req.Search))
	if err != nil {
		log.Printf("Invalid search regexp: %v", err)
		result.Error = err.Error()
		json.NewEncoder(w).Encode(result)
	}
	var excludeRe *regexp.Regexp
	if req.Exclude != "" {
		excludeRe, err = regexp.Compile("(?i)" + regexp.QuoteMeta(req.Exclude))
		if err != nil {
			log.Printf("Invalid exclude regexp: %v", err)
			result.Error = err.Error()
			json.NewEncoder(w).Encode(result)
		}
	}

	// Download formula index
	resp, err := http.Get("https://formulae.brew.sh/api/formula.json")
	if err != nil {
		log.Printf("Failed to download formula index: %v", err)
		result.Error = err.Error()
		json.NewEncoder(w).Encode(result)
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	var formulas []Formula
	if err := dec.Decode(&formulas); err != nil {
		log.Printf("Failed to decode JSON: %v", err)
		result.Error = err.Error()
		json.NewEncoder(w).Encode(result)
	}

	var results []Result
	for _, f := range formulas {
		if !searchRe.MatchString(f.Name) {
			continue
		}
		if excludeRe != nil && excludeRe.MatchString(f.Name) {
			continue
		}

		// Check for a macOS bottle (approx method: look for 'macos' key in files)
		foundMacBottle := false
		for k := range f.Bottle.Stable.Files {
			if strings.Contains(k, "mojave") || strings.Contains(k, "catalina") || strings.Contains(k, "big_sur") || strings.Contains(k, "ventura") || k == "all" {
				foundMacBottle = true
				break
			}
			if k == "macos" {
				foundMacBottle = true
				break
			}
		}
		if !foundMacBottle {
			continue
		}

		results = append(results, Result{
			Name:        f.Name,
			Description: f.Desc,
			Version:     f.Versions.Stable,
			Homepage:    f.Homepage,
		})
	}

	result.Output = results
	json.NewEncoder(w).Encode(result)
}

package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
)

func runScript(script string, search, exclude string, section string) (string, error) {
	args := []string{
		fmt.Sprintf("--search=%s", search),
		fmt.Sprintf("--exclude=%s", exclude),
	}
	if strings.Contains(script, "apt") {
		args = append(args, "--arch=amd64")
	}
	if len(section) > 0 {
		args = append(args, fmt.Sprintf("--section=%s", section))
	}
	cmd := exec.Command(filepath.Join("internal/", script), args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func updateHandler(w http.ResponseWriter, r *http.Request) {
	printLog("Update request received", LogLevelInfo, nil)
	cmd := exec.Command("bash", "-c", "apt update && flatpak update")
	output, err := cmd.CombinedOutput()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(err.Error()))
	}
	_, _ = w.Write(output)
}

func main() {
	http.HandleFunc("/search/apt", aptHandler)
	http.HandleFunc("/search/flatpak", flatpakHandler)
	http.HandleFunc("/update", updateHandler)
	http.HandleFunc("/search/windows", windowsHandler)
	http.HandleFunc("/search/homebrew", homebrewHandler)

	http.HandleFunc("/apt/addrepo", aptAddRepo)

	port := "8080"
	printLog("Starting server on port "+port, LogLevelInfo, nil)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

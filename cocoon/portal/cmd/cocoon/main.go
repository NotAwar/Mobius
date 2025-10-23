package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	fmt.Println("🥥 Mobius Cocoon - Storefront (Development)")
	fmt.Println("This is a placeholder for the future storefront functionality")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Mobius Cocoon - Storefront</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; }
        .container { max-width: 800px; margin: 0 auto; text-align: center; }
        .logo { font-size: 48px; margin-bottom: 20px; }
        .message { font-size: 18px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🥥 Mobius Cocoon</div>
        <h1>Mobius Storefront</h1>
        <p class="message">Future home of the Mobius application marketplace</p>
        <p class="message">Coming soon...</p>
    </div>
</body>
</html>
		`)
	})

	fmt.Printf("🚀 Mobius Cocoon starting on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

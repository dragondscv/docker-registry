package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

const (
	registryRoot = "./registry-data" // Directory to store image layers and manifests
)

func main() {
	// Ensure the registry root directory exists
	if err := os.MkdirAll(registryRoot, 0755); err != nil {
		fmt.Println("Error creating registry root directory:", err)
		return
	}

	// Health check endpoint
	http.HandleFunc("/v2/", handleHealthCheck)

	// Manifest API endpoints
	http.HandleFunc("/v2/{name}/manifests/{reference}", handleManifest)

	// Blob API endpoints
	http.HandleFunc("/v2/{name}/blobs/{digest}", handleBlob)
	http.HandleFunc("/v2/{name}/blobs/uploads/", handleBlobUpload)
	http.HandleFunc("/v2/{name}/blobs/uploads/{uuid}", handleBlobUploadProgress)

	fmt.Println("Docker Registry server listening on port 8000...")
	if err := http.ListenAndServe(":8000", nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}

func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleManifest(w http.ResponseWriter, r *http.Request) {
	// For simplicity, we'll just acknowledge the request.
	// A real implementation would involve storing and retrieving manifests.
	w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	fmt.Fprintln(w, `{"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json", "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 0, "digest": "sha256:dummy_config_digest"}, "layers": []}`)
}

func handleBlob(w http.ResponseWriter, r *http.Request) {
	// For simplicity, we'll just acknowledge the request.
	// A real implementation would involve serving the requested blob.
	w.WriteHeader(http.StatusOK)
}

func handleBlobUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Initiate a blob upload
		uuid := "some-unique-uuid" // In a real scenario, generate a UUID
		w.Header().Set("Location", r.URL.Path+"/"+uuid)
		w.WriteHeader(http.StatusAccepted)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleBlobUploadProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut {
		// Receive and store the blob data
		// In a real scenario, you'd read the request body and save the blob.
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Docker-Content-Digest", "sha256:some_digest_of_uploaded_blob")
	} else if r.Method == http.MethodGet {
		// Report upload progress (not implemented in this basic example)
		w.WriteHeader(http.StatusNoContent)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

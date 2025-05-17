package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// Configuration for the registry
type Config struct {
	StorageDir string
	Addr       string
	BasicAuth  bool
	Username   string
	Password   string
	CertFile   string
	KeyFile    string
}

// Registry represents the Docker registry server
type Registry struct {
	config       Config
	blobs        map[string]string            // Map of digests to file paths
	manifests    map[string]map[string]string // Map of repository -> tag -> digest
	mutex        sync.RWMutex
}

// BlobInfo represents information about a blob
type BlobInfo struct {
	Length int64
	Digest string
}

// ManifestInfo represents information about a manifest
type ManifestInfo struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType,omitempty"`
	Config        ManifestConfig  `json:"config"`
	Layers        []ManifestLayer `json:"layers"`
}

// ManifestConfig represents the config part of a manifest
type ManifestConfig struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// ManifestLayer represents a layer in a manifest
type ManifestLayer struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	Digest    string `json:"digest"`
}

// NewRegistry creates a new registry instance
func NewRegistry(config Config) *Registry {
	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(config.StorageDir, 0755); err != nil {
		log.Fatalf("Failed to create storage directory: %v", err)
	}

	// Create subdirectories for blobs and manifests
	if err := os.MkdirAll(filepath.Join(config.StorageDir, "blobs"), 0755); err != nil {
		log.Fatalf("Failed to create blobs directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(config.StorageDir, "manifests"), 0755); err != nil {
		log.Fatalf("Failed to create manifests directory: %v", err)
	}

	return &Registry{
		config:       config,
		blobs:        make(map[string]string),
		manifests:    make(map[string]map[string]string),
		mutex:        sync.RWMutex{},
	}
}

// Start starts the registry server
func (r *Registry) Start() error {
	router := mux.NewRouter()

	// API v2 endpoint
	router.HandleFunc("/v2/", r.basicAuthMiddleware).Methods("GET")

	// Blob endpoints
	router.HandleFunc("/v2/{name}/blobs/uploads/", r.handleStartBlobUpload).Methods("POST")
	router.HandleFunc("/v2/{name}/blobs/uploads/{uuid}", r.handlePutBlobUpload).Methods("PUT")
	router.HandleFunc("/v2/{name}/blobs/uploads/{uuid}", r.handlePatchBlobUpload).Methods("PATCH")
	router.HandleFunc("/v2/{name}/blobs/{digest}", r.handleGetBlob).Methods("GET", "HEAD")

	// Manifest endpoints
	router.HandleFunc("/v2/{name}/manifests/{reference}", r.handleGetManifest).Methods("GET", "HEAD")
	router.HandleFunc("/v2/{name}/manifests/{reference}", r.handlePutManifest).Methods("PUT")

	// Catalog endpoint
	router.HandleFunc("/v2/_catalog", r.handleCatalog).Methods("GET")
	router.HandleFunc("/v2/{name}/tags/list", r.handleListTags).Methods("GET")

	// Apply middleware
	var handler http.Handler = router
	log.Printf("config: %+v\n", r.config)
	handler = r.loggingMiddleware(handler)

	log.Printf("Starting Docker Registry server on %s", r.config.Addr)

	// Start server with HTTPS if certificates provided
	if r.config.CertFile != "" && r.config.KeyFile != "" {
		return http.ListenAndServeTLS(r.config.Addr, r.config.CertFile, r.config.KeyFile, handler)
	}

	// Start server with HTTP
	return http.ListenAndServe(r.config.Addr, handler)
}

// Middleware for basic authentication
func (r *Registry) basicAuthMiddleware(w http.ResponseWriter, req *http.Request) {
	username, password, ok := req.BasicAuth()
	log.Printf("username:%s, password: %s: \n", username, password)
	if !ok || username != r.config.Username || password != r.config.Password {
		log.Printf("unauthorized")
		w.Header().Set("WWW-Authenticate", `Basic realm="Docker Registry"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
}

// Middleware for logging requests
func (r *Registry) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()

		// Create a response recorder to capture the status code
		recorder := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(recorder, req)

		duration := time.Since(start)
		log.Printf("%s %s %s %d %v", req.RemoteAddr, req.Method, req.URL.Path, recorder.statusCode, duration)
	})
}

// Response recorder for logging
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Start blob upload
func (r *Registry) handleStartBlobUpload(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	name := vars["name"]

	// Generate a UUID for this upload
	uuid := fmt.Sprintf("%d", time.Now().UnixNano())
	uploadPath := filepath.Join(r.config.StorageDir, "uploads", uuid)

	// Create uploads directory if it doesn't exist
	if err := os.MkdirAll(filepath.Join(r.config.StorageDir, "uploads"), 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create the upload file
	if _, err := os.Create(uploadPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the Location header for the upload
	location := fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, uuid)
	w.Header().Set("Location", location)
	w.Header().Set("Docker-Upload-UUID", uuid)
	w.WriteHeader(http.StatusAccepted)
}

// Patch blob upload (chunked upload)
func (r *Registry) handlePatchBlobUpload(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	name := vars["name"]
	uuid := vars["uuid"]

	uploadPath := filepath.Join(r.config.StorageDir, "uploads", uuid)

	// Check if the upload exists
	if _, err := os.Stat(uploadPath); os.IsNotExist(err) {
		http.Error(w, "Upload not found", http.StatusNotFound)
		return
	}

	// Open the upload file for appending
	file, err := os.OpenFile(uploadPath, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Get the current size
	info, err := file.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	currentSize := info.Size()

	// Copy the request body to the upload file
	written, err := io.Copy(file, req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set headers for the response
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, uuid))
	w.Header().Set("Range", fmt.Sprintf("0-%d", currentSize+written-1))
	w.Header().Set("Docker-Upload-UUID", uuid)
	w.WriteHeader(http.StatusAccepted)
}

// Put blob upload (complete upload)
func (r *Registry) handlePutBlobUpload(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	name := vars["name"]
	uuid := vars["uuid"]

	// Get the digest from the query parameters
	digest := req.URL.Query().Get("digest")
	if digest == "" {
		http.Error(w, "Digest parameter required", http.StatusBadRequest)
		return
	}

	uploadPath := filepath.Join(r.config.StorageDir, "uploads", uuid)
	blobPath := filepath.Join(r.config.StorageDir, "blobs", strings.Replace(digest, ":", "_", 1))

	// Check if the upload exists
	if _, err := os.Stat(uploadPath); os.IsNotExist(err) {
		http.Error(w, "Upload not found", http.StatusNotFound)
		return
	}

	// If this is a monolithic upload (PUT with content)
	if req.ContentLength > 0 {
		file, err := os.OpenFile(uploadPath, os.O_WRONLY, 0644)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = io.Copy(file, req.Body)
		file.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Verify the digest
	uploadFile, err := os.Open(uploadPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h := sha256.New()
	if _, err := io.Copy(h, uploadFile); err != nil {
		uploadFile.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	uploadFile.Close()

	computedDigest := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if digest != computedDigest {
		http.Error(w, "Digest mismatch", http.StatusBadRequest)
		return
	}

	// Move the upload to the blob storage
	if err := os.Rename(uploadPath, blobPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Record the blob in our registry
	r.mutex.Lock()
	r.blobs[digest] = blobPath
	r.mutex.Unlock()

	// Set the response headers
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
	w.WriteHeader(http.StatusCreated)
}

// Get blob
func (r *Registry) handleGetBlob(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	digest := vars["digest"]

	r.mutex.RLock()
	blobPath, exists := r.blobs[digest]
	r.mutex.RUnlock()

	if !exists {
		// Try to find the blob by path if it's not in our map
		blobPath = filepath.Join(r.config.StorageDir, "blobs", strings.Replace(digest, ":", "_", 1))
		if _, err := os.Stat(blobPath); os.IsNotExist(err) {
			http.Error(w, "Blob not found", http.StatusNotFound)
			return
		}
	}

	// Get file info for size
	info, err := os.Stat(blobPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set content headers
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Docker-Content-Digest", digest)

	// For HEAD requests, don't send the body
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Open and serve the file
	file, err := os.Open(blobPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	io.Copy(w, file)
}

// Put manifest
func (r *Registry) handlePutManifest(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	name := vars["name"]
	reference := vars["reference"]

	// Read the manifest data
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Calculate the digest
	h := sha256.New()
	h.Write(body)
	digest := "sha256:" + hex.EncodeToString(h.Sum(nil))

	// Store the manifest
	manifestDir := filepath.Join(r.config.StorageDir, "manifests", name)
	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	manifestPath := filepath.Join(manifestDir, reference)
	if err := os.WriteFile(manifestPath, body, 0644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update the manifest map
	r.mutex.Lock()
	if _, exists := r.manifests[name]; !exists {
		r.manifests[name] = make(map[string]string)
	}
	r.manifests[name][reference] = digest
	r.mutex.Unlock()

	// Set response headers
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", name, digest))
	w.WriteHeader(http.StatusCreated)
}

// Get manifest
func (r *Registry) handleGetManifest(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	name := vars["name"]
	reference := vars["reference"]

	manifestPath := filepath.Join(r.config.StorageDir, "manifests", name, reference)

	// Check if the manifest exists
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		http.Error(w, "Manifest not found", http.StatusNotFound)
		return
	}

	// Read the manifest
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the digest
	h := sha256.New()
	h.Write(manifest)
	digest := "sha256:" + hex.EncodeToString(h.Sum(nil))

	// Try to determine the media type
	mediaType := "application/vnd.docker.distribution.manifest.v2+json"
	var manifestInfo ManifestInfo
	if err := json.Unmarshal(manifest, &manifestInfo); err == nil {
		if manifestInfo.MediaType != "" {
			mediaType = manifestInfo.MediaType
		} else if manifestInfo.SchemaVersion == 1 {
			mediaType = "application/vnd.docker.distribution.manifest.v1+json"
		}
	}

	// Set content headers
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(manifest)))

	// For HEAD requests, don't send the body
	if req.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(manifest)
}

// Catalog endpoint
func (r *Registry) handleCatalog(w http.ResponseWriter, req *http.Request) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	repositories := make([]string, 0, len(r.manifests))
	for repo := range r.manifests {
		repositories = append(repositories, repo)
	}

	response := struct {
		Repositories []string `json:"repositories"`
	}{
		Repositories: repositories,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// List tags endpoint
func (r *Registry) handleListTags(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	name := vars["name"]

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	repoTags, exists := r.manifests[name]
	if !exists {
		// If no tags found, return an empty list
		response := struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}{
			Name: name,
			Tags: []string{},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	tags := make([]string, 0, len(repoTags))
	for tag := range repoTags {
		// Only include string tags, not digests
		if !strings.HasPrefix(tag, "sha256:") {
			tags = append(tags, tag)
		}
	}

	response := struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}{
		Name: name,
		Tags: tags,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Default configuration
	config := Config{
		StorageDir: "./registry-data",
		Addr:       ":9050",
		BasicAuth:  false,
	}

	// Override with environment variables if present
	if dir := os.Getenv("REGISTRY_STORAGE_DIR"); dir != "" {
		config.StorageDir = dir
	}
	if addr := os.Getenv("REGISTRY_ADDR"); addr != "" {
		config.Addr = addr
	}
	if os.Getenv("REGISTRY_AUTH_ENABLED") == "true" {
		config.BasicAuth = true
		config.Username = os.Getenv("REGISTRY_AUTH_USERNAME")
		config.Password = os.Getenv("REGISTRY_AUTH_PASSWORD")
	}
	config.CertFile = os.Getenv("REGISTRY_TLS_CERT")
	config.KeyFile = os.Getenv("REGISTRY_TLS_KEY")

	registry := NewRegistry(config)

	log.Fatal(registry.Start())
}

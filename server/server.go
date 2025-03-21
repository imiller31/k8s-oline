package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/imiller31/k8s-auth-webhook/auth"
	"github.com/imiller31/k8s-auth-webhook/config"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WebhookServer handles HTTP requests for the authorization webhook
type WebhookServer struct {
	server     *http.Server
	config     *config.Config
	authorizer *auth.Authorizer
}

// NewWebhookServer creates a new webhook server with the given configuration and authorizer
func NewWebhookServer(config *config.Config, authorizer *auth.Authorizer) *WebhookServer {
	return &WebhookServer{
		config:     config,
		authorizer: authorizer,
	}
}

// handleAuthorize processes authorization requests
func (s *WebhookServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: Method=%s, URL=%s, Headers=%v", r.Method, r.URL.String(), r.Header)

	if r.Method != http.MethodPost {
		log.Printf("Invalid method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Error reading request", http.StatusBadRequest)
		return
	}
	log.Printf("Raw request body: %s", string(body))

	var sar authorizationv1.SubjectAccessReview
	if err := json.NewDecoder(strings.NewReader(string(body))).Decode(&sar); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received authorization request: %+v", sar)

	// Process the authorization request
	allowed, reason := s.authorizer.ProcessRequest(&sar)

	// Create response
	response := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Status: authorizationv1.SubjectAccessReviewStatus{
			Allowed: allowed,
			Denied:  !allowed,
			Reason:  reason,
		},
	}

	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling response: %v", err)
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
	log.Printf("Sending response: %s", string(responseBody))

	w.Header().Set("Content-Type", "application/json")
	w.Write(responseBody)
}

// Start starts the webhook server with TLS
func (s *WebhookServer) Start() error {
	// Create mux and register handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", s.handleAuthorize)

	// Create and start server with TLS
	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%s", s.config.Port),
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Starting authorization webhook server on port %s with TLS", s.config.Port)
	return s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
}

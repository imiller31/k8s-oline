package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Config struct {
	Port            string
	TLSCertFile     string
	TLSKeyFile      string
	ProtectedPrefix string
	PrivilegedUser  string
}

type WebhookServer struct {
	server *http.Server
	config *Config
}

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
	allowed, reason := s.processAuthRequest(&sar)

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

func (s *WebhookServer) processAuthRequest(sar *authorizationv1.SubjectAccessReview) (bool, string) {
	// Extract relevant information from the request
	user := sar.Spec.User
	groups := sar.Spec.Groups
	resourceAttributes := sar.Spec.ResourceAttributes
	nonResourceAttributes := sar.Spec.NonResourceAttributes

	// Log the request details
	log.Printf("Processing request for user: %s, groups: %v", user, groups)
	if resourceAttributes != nil {
		log.Printf("Resource attributes: Group=%s, Version=%s, Resource=%s, Name=%s, Namespace=%s, Verb=%s",
			resourceAttributes.Group,
			resourceAttributes.Version,
			resourceAttributes.Resource,
			resourceAttributes.Name,
			resourceAttributes.Namespace,
			resourceAttributes.Verb)
	}

	// Check for impersonation attempts
	if resourceAttributes != nil &&
		resourceAttributes.Resource == "users" &&
		(resourceAttributes.Verb == "impersonate" || resourceAttributes.Verb == "create") {
		// Block attempts to impersonate system:masters group
		if resourceAttributes.Group == "authentication.k8s.io" &&
			resourceAttributes.Resource == "userextras" &&
			resourceAttributes.Subresource == "groups" &&
			strings.Contains(resourceAttributes.Name, "system:masters") {
			return false, "Impersonation of system:masters group is not allowed"
		}
	}

	// Check for direct group impersonation
	if nonResourceAttributes != nil &&
		nonResourceAttributes.Verb == "impersonate" &&
		nonResourceAttributes.Path == "/api/v1/users/~/groups/system:masters" {
		return false, "Direct impersonation of system:masters group is not allowed"
	}

	// Allow all requests by default
	allowed := true
	reason := "Request allowed by authorization webhook"

	// Check if this is a delete operation
	if resourceAttributes != nil && resourceAttributes.Verb == "delete" {
		// Check if the resource name starts with the protected prefix
		if strings.HasPrefix(resourceAttributes.Name, s.config.ProtectedPrefix) {
			// Allow if user is in system:masters or system:node groups
			for _, group := range groups {
				if group == "system:masters" || group == "system:nodes" {
					log.Printf("Allowing delete operation for user %s in privileged group %s", user, group)
					return true, fmt.Sprintf("User '%s' is authorized to delete protected resources as a member of %s group", user, group)
				}
			}

			// Block delete operations on protected resources unless the user is privileged
			if user != s.config.PrivilegedUser {
				allowed = false
				reason = fmt.Sprintf("User '%s' is not authorized to delete resources with prefix '%s'. Only '%s' users or members of system:masters/system:nodes groups can perform this operation.",
					user, s.config.ProtectedPrefix, s.config.PrivilegedUser)
				log.Printf("Blocking delete operation on protected resource for user: %s", user)
			} else {
				log.Printf("Allowing delete operation for privileged user on resource: %s", resourceAttributes.Name)
			}
		}
	}

	// Log the decision
	log.Printf("Authorization decision for user %s: %v, reason: %s", user, allowed, reason)

	return allowed, reason
}

func loadConfig() *Config {
	config := &Config{
		Port:            getEnvWithDefault("PORT", "8080"),
		TLSCertFile:     os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:      os.Getenv("TLS_KEY_FILE"),
		ProtectedPrefix: getEnvWithDefault("PROTECTED_PREFIX", "aks-automatic-"),
		PrivilegedUser:  getEnvWithDefault("PRIVILEGED_USER", "support"),
	}

	if config.TLSCertFile == "" || config.TLSKeyFile == "" {
		log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE environment variables must be set")
	}

	log.Printf("Loaded configuration: Port=%s, ProtectedPrefix=%s, PrivilegedUser=%s",
		config.Port, config.ProtectedPrefix, config.PrivilegedUser)

	return config
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	config := loadConfig()

	server := &WebhookServer{
		config: config,
	}

	// Create mux and register handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", server.handleAuthorize)

	// Create and start server with TLS
	server.server = &http.Server{
		Addr:    fmt.Sprintf(":%s", config.Port),
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Starting authorization webhook server on port %s with TLS", config.Port)
	if err := server.server.ListenAndServeTLS(config.TLSCertFile, config.TLSKeyFile); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

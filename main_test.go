package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
)

func TestWebhookServer_HandleAuthorize(t *testing.T) {
	config := &Config{
		Port:            "8443",
		TLSCertFile:     "test-cert.pem",
		TLSKeyFile:      "test-key.pem",
		ProtectedPrefix: "test-prefix-",
		PrivilegedUser:  "admin",
	}

	server := &WebhookServer{
		config: config,
	}

	tests := []struct {
		name           string
		request        *authorizationv1.SubjectAccessReview
		expectedStatus int
		expectedResult bool
		expectedReason string
	}{
		{
			name: "allow non-delete operation on protected resource",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "get",
						Name:     "test-prefix-resource",
						Resource: "pods",
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
		{
			name: "block delete on protected resource for regular user",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "delete",
						Name:     "test-prefix-resource",
						Resource: "pods",
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: false,
			expectedReason: "User 'regular-user' is not authorized to delete resources with prefix 'test-prefix-'. Only 'admin' users can perform this operation.",
		},
		{
			name: "allow delete on protected resource for privileged user",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "admin",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "delete",
						Name:     "test-prefix-resource",
						Resource: "pods",
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
		{
			name: "allow delete on non-protected resource for regular user",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "delete",
						Name:     "regular-resource",
						Resource: "pods",
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
		{
			name: "allow request without resource attributes",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
		{
			name: "handle empty resource name",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "delete",
						Resource: "pods",
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First verify the direct authorization logic
			allowed, reason := server.processAuthRequest(tt.request)
			if allowed != tt.expectedResult {
				t.Errorf("processAuthRequest() returned wrong result: got %v want %v", allowed, tt.expectedResult)
			}
			if reason != tt.expectedReason {
				t.Errorf("processAuthRequest() returned wrong reason: got %q want %q", reason, tt.expectedReason)
			}

			// Then test the HTTP handler
			body, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			server.handleAuthorize(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					rr.Code, tt.expectedStatus)
			}

			var response authorizationv1.SubjectAccessReview
			if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if response.Status.Allowed != tt.expectedResult {
				t.Errorf("handler returned wrong result: got %v want %v",
					response.Status.Allowed, tt.expectedResult)
			}

			if response.Status.Reason != tt.expectedReason {
				t.Errorf("handler returned wrong reason: got %q want %q",
					response.Status.Reason, tt.expectedReason)
			}

			if response.APIVersion != "authorization.k8s.io/v1" {
				t.Errorf("handler returned wrong API version: got %v want %v",
					response.APIVersion, "authorization.k8s.io/v1")
			}
			if response.Kind != "SubjectAccessReview" {
				t.Errorf("handler returned wrong kind: got %v want %v",
					response.Kind, "SubjectAccessReview")
			}
		})
	}
}

func TestWebhookServer_ProcessAuthRequest(t *testing.T) {
	config := &Config{
		Port:            "8443",
		TLSCertFile:     "test-cert.pem",
		TLSKeyFile:      "test-key.pem",
		ProtectedPrefix: "test-prefix-",
		PrivilegedUser:  "admin",
	}

	server := &WebhookServer{
		config: config,
	}

	tests := []struct {
		name           string
		request        *authorizationv1.SubjectAccessReview
		expectedResult bool
		expectedReason string
	}{
		{
			name: "allow non-delete operation on protected resource",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "get",
						Name:     "test-prefix-resource",
						Resource: "pods",
					},
				},
			},
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
		{
			name: "block delete on protected resource for regular user",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "delete",
						Name:     "test-prefix-resource",
						Resource: "pods",
					},
				},
			},
			expectedResult: false,
			expectedReason: "User 'regular-user' is not authorized to delete resources with prefix 'test-prefix-'. Only 'admin' users can perform this operation.",
		},
		{
			name: "allow delete on protected resource for privileged user",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "admin",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "delete",
						Name:     "test-prefix-resource",
						Resource: "pods",
					},
				},
			},
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
		{
			name: "allow delete on non-protected resource for regular user",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "delete",
						Name:     "regular-resource",
						Resource: "pods",
					},
				},
			},
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
		{
			name: "allow request without resource attributes",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
				},
			},
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
		{
			name: "handle empty resource name",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "regular-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "delete",
						Resource: "pods",
					},
				},
			},
			expectedResult: true,
			expectedReason: "Request allowed by authorization webhook",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := server.processAuthRequest(tt.request)

			if allowed != tt.expectedResult {
				t.Errorf("processAuthRequest() allowed = %v, want %v", allowed, tt.expectedResult)
			}

			if reason != tt.expectedReason {
				t.Errorf("processAuthRequest() reason = %q, want %q", reason, tt.expectedReason)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Save original environment
	origPort := os.Getenv("PORT")
	origCertFile := os.Getenv("TLS_CERT_FILE")
	origKeyFile := os.Getenv("TLS_KEY_FILE")
	origPrefix := os.Getenv("PROTECTED_PREFIX")
	origUser := os.Getenv("PRIVILEGED_USER")

	// Restore environment after test
	defer func() {
		os.Setenv("PORT", origPort)
		os.Setenv("TLS_CERT_FILE", origCertFile)
		os.Setenv("TLS_KEY_FILE", origKeyFile)
		os.Setenv("PROTECTED_PREFIX", origPrefix)
		os.Setenv("PRIVILEGED_USER", origUser)
	}()

	tests := []struct {
		name           string
		envVars        map[string]string
		expectError    bool
		expectedPort   string
		expectedPrefix string
		expectedUser   string
	}{
		{
			name: "default values",
			envVars: map[string]string{
				"TLS_CERT_FILE": "cert.pem",
				"TLS_KEY_FILE":  "key.pem",
			},
			expectError:    false,
			expectedPort:   "8080",
			expectedPrefix: "aks-automatic-",
			expectedUser:   "support",
		},
		{
			name: "custom values",
			envVars: map[string]string{
				"PORT":             "9443",
				"TLS_CERT_FILE":    "custom-cert.pem",
				"TLS_KEY_FILE":     "custom-key.pem",
				"PROTECTED_PREFIX": "custom-prefix-",
				"PRIVILEGED_USER":  "admin",
			},
			expectError:    false,
			expectedPort:   "9443",
			expectedPrefix: "custom-prefix-",
			expectedUser:   "admin",
		},
		{
			name: "missing TLS cert file",
			envVars: map[string]string{
				"TLS_KEY_FILE": "key.pem",
			},
			expectError: true,
		},
		{
			name: "missing TLS key file",
			envVars: map[string]string{
				"TLS_CERT_FILE": "cert.pem",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set environment variables for test
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			if tt.expectError {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("loadConfig() should have panicked")
					}
				}()
			}

			config := loadConfig()

			if !tt.expectError {
				if config.Port != tt.expectedPort {
					t.Errorf("wrong port: got %v want %v", config.Port, tt.expectedPort)
				}
				if config.ProtectedPrefix != tt.expectedPrefix {
					t.Errorf("wrong prefix: got %v want %v", config.ProtectedPrefix, tt.expectedPrefix)
				}
				if config.PrivilegedUser != tt.expectedUser {
					t.Errorf("wrong user: got %v want %v", config.PrivilegedUser, tt.expectedUser)
				}
			}
		})
	}
}

func TestGetEnvWithDefault(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		defaultVal string
		envVal     string
		expected   string
	}{
		{
			name:       "use default value",
			key:        "TEST_KEY",
			defaultVal: "default",
			envVal:     "",
			expected:   "default",
		},
		{
			name:       "use environment value",
			key:        "TEST_KEY",
			defaultVal: "default",
			envVal:     "custom",
			expected:   "custom",
		},
		{
			name:       "empty default and no env",
			key:        "TEST_KEY",
			defaultVal: "",
			envVal:     "",
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				os.Setenv(tt.key, tt.envVal)
				defer os.Unsetenv(tt.key)
			} else {
				os.Unsetenv(tt.key)
			}

			result := getEnvWithDefault(tt.key, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("getEnvWithDefault() = %v, want %v", result, tt.expected)
			}
		})
	}
}

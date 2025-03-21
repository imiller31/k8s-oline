package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/imiller31/k8s-auth-webhook/auth"
	"github.com/imiller31/k8s-auth-webhook/cel"
	"github.com/imiller31/k8s-auth-webhook/config"
	authorizationv1 "k8s.io/api/authorization/v1"
)

type mockAuthorizer struct {
	allow  bool
	reason string
}

func (m *mockAuthorizer) ProcessRequest(sar *authorizationv1.SubjectAccessReview) (bool, string) {
	return m.allow, m.reason
}

func TestNewWebhookServer(t *testing.T) {
	cfg := &config.Config{
		Port:            "8080",
		TLSCertFile:     "test-cert.pem",
		TLSKeyFile:      "test-key.pem",
		ProtectedPrefix: "test-",
		PrivilegedUser:  "admin",
	}

	celEval, err := cel.NewEvaluator([]string{})
	if err != nil {
		t.Fatalf("Failed to create CEL evaluator: %v", err)
	}

	authorizer := auth.NewAuthorizer(cfg, celEval)
	server := NewWebhookServer(cfg, authorizer)

	if server == nil {
		t.Error("Expected server to be created")
	}
}

func TestHandleAuthorize(t *testing.T) {
	cfg := &config.Config{
		Port:            "8080",
		TLSCertFile:     "test-cert.pem",
		TLSKeyFile:      "test-key.pem",
		ProtectedPrefix: "test-",
		PrivilegedUser:  "admin",
	}

	celEval, err := cel.NewEvaluator([]string{})
	if err != nil {
		t.Fatalf("Failed to create CEL evaluator: %v", err)
	}

	authorizer := auth.NewAuthorizer(cfg, celEval)
	server := NewWebhookServer(cfg, authorizer)

	tests := []struct {
		name           string
		request        *authorizationv1.SubjectAccessReview
		expectedStatus int
		expectedReason string
	}{
		{
			name: "allow request",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
				},
			},
			expectedStatus: http.StatusOK,
			expectedReason: "Request allowed by authorization webhook",
		},
		{
			name: "deny request",
			request: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb: "delete",
						Name: "test-resource",
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedReason: "User 'test-user' is not authorized to delete resources with prefix 'test-'. Only 'admin' users or members of system:masters/system:nodes groups can perform this operation.",
		},
		{
			name:           "invalid request body",
			request:        nil,
			expectedStatus: http.StatusBadRequest,
			expectedReason: "EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			var err error

			if tt.request != nil {
				body, err = json.Marshal(tt.request)
				if err != nil {
					t.Fatalf("Failed to marshal request: %v", err)
				}
			}

			req := httptest.NewRequest("POST", "/authorize", bytes.NewBuffer(body))
			w := httptest.NewRecorder()

			server.handleAuthorize(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("handleAuthorize() status = %v, want %v", w.Code, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusOK {
				var response authorizationv1.SubjectAccessReview
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}

				if response.Status.Reason != tt.expectedReason {
					t.Errorf("handleAuthorize() reason = %v, want %v", response.Status.Reason, tt.expectedReason)
				}
			}
		})
	}
}

func TestStart(t *testing.T) {
	cfg := &config.Config{
		Port:            "8080",
		TLSCertFile:     "test-cert.pem",
		TLSKeyFile:      "test-key.pem",
		ProtectedPrefix: "test-",
		PrivilegedUser:  "admin",
	}

	celEval, err := cel.NewEvaluator([]string{})
	if err != nil {
		t.Fatalf("Failed to create CEL evaluator: %v", err)
	}

	authorizer := auth.NewAuthorizer(cfg, celEval)
	server := NewWebhookServer(cfg, authorizer)

	// Start server in a goroutine
	go func() {
		if err := server.Start(); err != nil {
			t.Errorf("Failed to start server: %v", err)
		}
	}()

	// TODO: Add test for server shutdown
}

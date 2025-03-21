package auth

import (
	"testing"

	"github.com/imiller31/k8s-auth-webhook/cel"
	"github.com/imiller31/k8s-auth-webhook/config"
	authorizationv1 "k8s.io/api/authorization/v1"
)

func TestNewAuthorizer(t *testing.T) {
	cfg := &config.Config{
		ProtectedPrefix: "test-",
		PrivilegedUser:  "admin",
	}
	celEval, _ := cel.NewEvaluator([]string{})

	authorizer := NewAuthorizer(cfg, celEval)
	if authorizer == nil {
		t.Error("NewAuthorizer() returned nil")
	}
	if authorizer.config != cfg {
		t.Error("NewAuthorizer() config mismatch")
	}
	if authorizer.celEval != celEval {
		t.Error("NewAuthorizer() celEval mismatch")
	}
}

func TestProcessRequest(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		celRules []string
		sar      *authorizationv1.SubjectAccessReview
		want     bool
		validate func(*testing.T, string)
	}{
		{
			name: "allow by CEL rule",
			cfg: &config.Config{
				ProtectedPrefix: "test-",
				PrivilegedUser:  "admin",
			},
			celRules: []string{
				"'system:masters' in groups",
			},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:   "test-user",
					Groups: []string{"system:masters"},
				},
			},
			want: true,
			validate: func(t *testing.T, reason string) {
				if reason != "Request allowed by authorization webhook" {
					t.Errorf("expected reason 'Request allowed by authorization webhook', got %s", reason)
				}
			},
		},
		{
			name: "deny by CEL rule",
			cfg: &config.Config{
				ProtectedPrefix: "test-",
				PrivilegedUser:  "admin",
			},
			celRules: []string{
				"'system:masters' in groups",
			},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:   "test-user",
					Groups: []string{"test-group"},
				},
			},
			want: false,
			validate: func(t *testing.T, reason string) {
				if reason != "Request denied by CEL rule 0" {
					t.Errorf("expected reason 'Request denied by CEL rule 0', got %s", reason)
				}
			},
		},
		{
			name: "block system:masters impersonation",
			cfg: &config.Config{
				ProtectedPrefix: "test-",
				PrivilegedUser:  "admin",
			},
			celRules: []string{},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Group:       "authentication.k8s.io",
						Resource:    "userextras",
						Subresource: "groups",
						Name:        "system:masters",
					},
				},
			},
			want: false,
			validate: func(t *testing.T, reason string) {
				if reason != "Impersonation of system:masters group is not allowed" {
					t.Errorf("expected reason 'Impersonation of system:masters group is not allowed', got %s", reason)
				}
			},
		},
		{
			name: "block direct system:masters group impersonation",
			cfg: &config.Config{
				ProtectedPrefix: "test-",
				PrivilegedUser:  "admin",
			},
			celRules: []string{},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					NonResourceAttributes: &authorizationv1.NonResourceAttributes{
						Path: "/api/v1/users/~/groups/system:masters",
					},
				},
			},
			want: false,
			validate: func(t *testing.T, reason string) {
				if reason != "Direct impersonation of system:masters group is not allowed" {
					t.Errorf("expected reason 'Direct impersonation of system:masters group is not allowed', got %s", reason)
				}
			},
		},
		{
			name: "allow delete by privileged user",
			cfg: &config.Config{
				ProtectedPrefix: "test-",
				PrivilegedUser:  "admin",
			},
			celRules: []string{},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "admin",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb: "delete",
						Name: "test-resource",
					},
				},
			},
			want: true,
			validate: func(t *testing.T, reason string) {
				if reason != "User 'admin' is authorized to delete protected resources as a privileged user" {
					t.Errorf("expected reason 'User 'admin' is authorized to delete protected resources as a privileged user', got %s", reason)
				}
			},
		},
		{
			name: "allow delete by system:masters group",
			cfg: &config.Config{
				ProtectedPrefix: "test-",
				PrivilegedUser:  "admin",
			},
			celRules: []string{},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:   "test-user",
					Groups: []string{"system:masters"},
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb: "delete",
						Name: "test-resource",
					},
				},
			},
			want: true,
			validate: func(t *testing.T, reason string) {
				if reason != "User 'test-user' is authorized to delete protected resources as a member of system:masters group" {
					t.Errorf("expected reason 'User 'test-user' is authorized to delete protected resources as a member of system:masters group', got %s", reason)
				}
			},
		},
		{
			name: "deny delete by non-privileged user",
			cfg: &config.Config{
				ProtectedPrefix: "test-",
				PrivilegedUser:  "admin",
			},
			celRules: []string{},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb: "delete",
						Name: "test-resource",
					},
				},
			},
			want: false,
			validate: func(t *testing.T, reason string) {
				if reason != "User 'test-user' is not authorized to delete resources with prefix 'test-'. Only 'admin' users or members of system:masters/system:nodes groups can perform this operation." {
					t.Errorf("expected reason 'User 'test-user' is not authorized to delete resources with prefix 'test-'. Only 'admin' users or members of system:masters/system:nodes groups can perform this operation.', got %s", reason)
				}
			},
		},
		{
			name: "allow non-delete operation",
			cfg: &config.Config{
				ProtectedPrefix: "test-",
				PrivilegedUser:  "admin",
			},
			celRules: []string{},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb: "get",
						Name: "test-resource",
					},
				},
			},
			want: true,
			validate: func(t *testing.T, reason string) {
				if reason != "Request allowed by authorization webhook" {
					t.Errorf("expected reason 'Request allowed by authorization webhook', got %s", reason)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			celEval, err := cel.NewEvaluator(tt.celRules)
			if err != nil {
				t.Fatalf("Failed to create CEL evaluator: %v", err)
			}

			authorizer := NewAuthorizer(tt.cfg, celEval)
			got, reason := authorizer.ProcessRequest(tt.sar)

			if got != tt.want {
				t.Errorf("ProcessRequest() = %v, want %v", got, tt.want)
			}
			if tt.validate != nil {
				tt.validate(t, reason)
			}
		})
	}
}

package cel

import (
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
)

func TestNewEvaluator(t *testing.T) {
	tests := []struct {
		name    string
		rules   []string
		wantErr bool
	}{
		{
			name:    "empty rules",
			rules:   []string{},
			wantErr: false,
		},
		{
			name: "valid rules",
			rules: []string{
				"'system:masters' in groups",
				"user == 'admin'",
			},
			wantErr: false,
		},
		{
			name: "invalid rule",
			rules: []string{
				"invalid syntax",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval, err := NewEvaluator(tt.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEvaluator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && eval == nil {
				t.Error("NewEvaluator() returned nil evaluator without error")
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		rules    []string
		sar      *authorizationv1.SubjectAccessReview
		want     bool
		validate func(*testing.T, string)
	}{
		{
			name:  "no rules",
			rules: []string{},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:   "test-user",
					Groups: []string{"test-group"},
				},
			},
			want: true,
			validate: func(t *testing.T, reason string) {
				if reason != "No CEL rules configured" {
					t.Errorf("expected reason 'No CEL rules configured', got %s", reason)
				}
			},
		},
		{
			name: "allow system:masters group",
			rules: []string{
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
				if reason != "Request allowed by CEL rules" {
					t.Errorf("expected reason 'Request allowed by CEL rules', got %s", reason)
				}
			},
		},
		{
			name: "deny non-system:masters group",
			rules: []string{
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
			name: "allow specific user",
			rules: []string{
				"user == 'admin'",
			},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "admin",
				},
			},
			want: true,
			validate: func(t *testing.T, reason string) {
				if reason != "Request allowed by CEL rules" {
					t.Errorf("expected reason 'Request allowed by CEL rules', got %s", reason)
				}
			},
		},
		{
			name: "deny specific user",
			rules: []string{
				"user == 'admin'",
			},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "other-user",
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
			name: "allow based on resource attributes",
			rules: []string{
				"has(resourceAttributes.namespace) && resourceAttributes.namespace == 'prod'",
			},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "prod",
					},
				},
			},
			want: true,
			validate: func(t *testing.T, reason string) {
				if reason != "Request allowed by CEL rules" {
					t.Errorf("expected reason 'Request allowed by CEL rules', got %s", reason)
				}
			},
		},
		{
			name: "deny based on resource attributes",
			rules: []string{
				"has(resourceAttributes.namespace) && resourceAttributes.namespace == 'prod'",
			},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "dev",
					},
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
			name: "multiple rules - all must pass",
			rules: []string{
				"'system:masters' in groups",
				"has(resourceAttributes.namespace) && resourceAttributes.namespace == 'prod'",
			},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:   "test-user",
					Groups: []string{"system:masters"},
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "prod",
					},
				},
			},
			want: true,
			validate: func(t *testing.T, reason string) {
				if reason != "Request allowed by CEL rules" {
					t.Errorf("expected reason 'Request allowed by CEL rules', got %s", reason)
				}
			},
		},
		{
			name: "multiple rules - one fails",
			rules: []string{
				"'system:masters' in groups",
				"has(resourceAttributes.namespace) && resourceAttributes.namespace == 'prod'",
			},
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:   "test-user",
					Groups: []string{"system:masters"},
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "dev",
					},
				},
			},
			want: false,
			validate: func(t *testing.T, reason string) {
				if reason != "Request denied by CEL rule 1" {
					t.Errorf("expected reason 'Request denied by CEL rule 1', got %s", reason)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval, err := NewEvaluator(tt.rules)
			if err != nil {
				t.Fatalf("Failed to create evaluator: %v", err)
			}

			got, reason := eval.Evaluate(tt.sar)
			if got != tt.want {
				t.Errorf("Evaluate() = %v, want %v", got, tt.want)
			}
			if tt.validate != nil {
				tt.validate(t, reason)
			}
		})
	}
}

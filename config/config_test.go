package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		yamlFile string
		wantErr  bool
		validate func(*testing.T, *Config)
	}{
		{
			name:    "default values",
			wantErr: true, // Should error because TLS files are required
		},
		{
			name: "basic config",
			yamlFile: `port: "8443"
tlsCertFile: "test-cert.pem"
tlsKeyFile: "test-key.pem"`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Port != "8443" {
					t.Errorf("expected Port=8443, got %s", cfg.Port)
				}
				if cfg.ProtectedPrefix != "aks-automatic-" {
					t.Errorf("expected ProtectedPrefix=aks-automatic-, got %s", cfg.ProtectedPrefix)
				}
				if cfg.PrivilegedUser != "support" {
					t.Errorf("expected PrivilegedUser=support, got %s", cfg.PrivilegedUser)
				}
				if !strings.HasSuffix(cfg.TLSCertFile, "test-cert.pem") {
					t.Errorf("expected TLSCertFile to end with test-cert.pem, got %s", cfg.TLSCertFile)
				}
				if !strings.HasSuffix(cfg.TLSKeyFile, "test-key.pem") {
					t.Errorf("expected TLSKeyFile to end with test-key.pem, got %s", cfg.TLSKeyFile)
				}
				if len(cfg.CELRules) != 0 {
					t.Errorf("expected empty CELRules, got %v", cfg.CELRules)
				}
			},
		},
		{
			name: "full config",
			yamlFile: `port: "8443"
tlsCertFile: "custom-cert.pem"
tlsKeyFile: "custom-key.pem"
protectedPrefix: "custom-"
privilegedUser: "admin"
celRules:
  - "rule1"
  - "rule2"`,
			wantErr: false,
			validate: func(t *testing.T, cfg *Config) {
				if cfg.Port != "8443" {
					t.Errorf("expected Port=8443, got %s", cfg.Port)
				}
				if cfg.ProtectedPrefix != "custom-" {
					t.Errorf("expected ProtectedPrefix=custom-, got %s", cfg.ProtectedPrefix)
				}
				if cfg.PrivilegedUser != "admin" {
					t.Errorf("expected PrivilegedUser=admin, got %s", cfg.PrivilegedUser)
				}
				if !strings.HasSuffix(cfg.TLSCertFile, "custom-cert.pem") {
					t.Errorf("expected TLSCertFile to end with custom-cert.pem, got %s", cfg.TLSCertFile)
				}
				if !strings.HasSuffix(cfg.TLSKeyFile, "custom-key.pem") {
					t.Errorf("expected TLSKeyFile to end with custom-key.pem, got %s", cfg.TLSKeyFile)
				}
				if len(cfg.CELRules) != 2 {
					t.Errorf("expected 2 CELRules, got %d", len(cfg.CELRules))
				}
				if cfg.CELRules[0] != "rule1" || cfg.CELRules[1] != "rule2" {
					t.Errorf("expected CELRules=[rule1 rule2], got %v", cfg.CELRules)
				}
			},
		},
		{
			name: "missing TLS cert file",
			yamlFile: `port: "8443"
tlsKeyFile: "test-key.pem"`,
			wantErr: true,
		},
		{
			name: "missing TLS key file",
			yamlFile: `port: "8443"
tlsCertFile: "test-cert.pem"`,
			wantErr: true,
		},
		{
			name:     "invalid YAML file",
			yamlFile: "invalid yaml content",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test files
			tmpDir := t.TempDir()

			var configPath string
			if tt.yamlFile != "" {
				configPath = filepath.Join(tmpDir, "config.yaml")
				if err := os.WriteFile(configPath, []byte(tt.yamlFile), 0644); err != nil {
					t.Fatalf("Failed to write config file: %v", err)
				}

				// Create TLS files if specified in the YAML
				if strings.Contains(tt.yamlFile, "test-cert.pem") {
					certPath := filepath.Join(tmpDir, "test-cert.pem")
					if err := os.WriteFile(certPath, []byte("test-cert"), 0644); err != nil {
						t.Fatalf("Failed to write TLS cert file: %v", err)
					}
					// Update the YAML content with the full path
					tt.yamlFile = strings.ReplaceAll(tt.yamlFile, "test-cert.pem", certPath)
					if err := os.WriteFile(configPath, []byte(tt.yamlFile), 0644); err != nil {
						t.Fatalf("Failed to update config file: %v", err)
					}
				}
				if strings.Contains(tt.yamlFile, "test-key.pem") {
					keyPath := filepath.Join(tmpDir, "test-key.pem")
					if err := os.WriteFile(keyPath, []byte("test-key"), 0644); err != nil {
						t.Fatalf("Failed to write TLS key file: %v", err)
					}
					// Update the YAML content with the full path
					tt.yamlFile = strings.ReplaceAll(tt.yamlFile, "test-key.pem", keyPath)
					if err := os.WriteFile(configPath, []byte(tt.yamlFile), 0644); err != nil {
						t.Fatalf("Failed to update config file: %v", err)
					}
				}
				if strings.Contains(tt.yamlFile, "custom-cert.pem") {
					certPath := filepath.Join(tmpDir, "custom-cert.pem")
					if err := os.WriteFile(certPath, []byte("test-cert"), 0644); err != nil {
						t.Fatalf("Failed to write TLS cert file: %v", err)
					}
					// Update the YAML content with the full path
					tt.yamlFile = strings.ReplaceAll(tt.yamlFile, "custom-cert.pem", certPath)
					if err := os.WriteFile(configPath, []byte(tt.yamlFile), 0644); err != nil {
						t.Fatalf("Failed to update config file: %v", err)
					}
				}
				if strings.Contains(tt.yamlFile, "custom-key.pem") {
					keyPath := filepath.Join(tmpDir, "custom-key.pem")
					if err := os.WriteFile(keyPath, []byte("test-key"), 0644); err != nil {
						t.Fatalf("Failed to write TLS key file: %v", err)
					}
					// Update the YAML content with the full path
					tt.yamlFile = strings.ReplaceAll(tt.yamlFile, "custom-key.pem", keyPath)
					if err := os.WriteFile(configPath, []byte(tt.yamlFile), 0644); err != nil {
						t.Fatalf("Failed to update config file: %v", err)
					}
				}
			}

			// Run the test
			cfg, err := Load(configPath)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != "8080" {
		t.Errorf("expected Port=8080, got %s", cfg.Port)
	}
	if cfg.ProtectedPrefix != "aks-automatic-" {
		t.Errorf("expected ProtectedPrefix=aks-automatic-, got %s", cfg.ProtectedPrefix)
	}
	if cfg.PrivilegedUser != "support" {
		t.Errorf("expected PrivilegedUser=support, got %s", cfg.PrivilegedUser)
	}
	if len(cfg.CELRules) != 0 {
		t.Errorf("expected empty CELRules, got %v", cfg.CELRules)
	}
}

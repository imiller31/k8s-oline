package config

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the webhook server
type Config struct {
	Port            string   `yaml:"port"`
	TLSCertFile     string   `yaml:"tlsCertFile"`
	TLSKeyFile      string   `yaml:"tlsKeyFile"`
	ProtectedPrefix string   `yaml:"protectedPrefix"`
	PrivilegedUser  string   `yaml:"privilegedUser"`
	SupportUser     string   `yaml:"supportUser"`
	CELRules        []string `yaml:"celRules"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Port:            "8080",
		ProtectedPrefix: "aks-automatic-",
		PrivilegedUser:  "support",
		SupportUser:     "support",
		CELRules:        []string{},
	}
}

// Load creates a new Config from a YAML file
func Load(configFile string) (*Config, error) {
	// Start with default configuration
	cfg := DefaultConfig()

	// Load configuration from YAML file
	if configFile != "" {
		if err := cfg.loadFromYAML(configFile); err != nil {
			return nil, fmt.Errorf("failed to load config from YAML file: %v", err)
		}
	}

	// Validate required fields
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, fmt.Errorf("tlsCertFile and tlsKeyFile are required in configuration")
	}

	// Check if TLS files exist
	if _, err := os.Stat(cfg.TLSCertFile); err != nil {
		return nil, fmt.Errorf("TLS certificate file not found: %s", cfg.TLSCertFile)
	}
	if _, err := os.Stat(cfg.TLSKeyFile); err != nil {
		return nil, fmt.Errorf("TLS key file not found: %s", cfg.TLSKeyFile)
	}

	log.Printf("Loaded configuration: Port=%s, ProtectedPrefix=%s, PrivilegedUser=%s, CELRules=%v",
		cfg.Port, cfg.ProtectedPrefix, cfg.PrivilegedUser, cfg.CELRules)

	return cfg, nil
}

// loadFromYAML loads configuration from a YAML file
func (c *Config) loadFromYAML(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var yamlConfig Config
	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return err
	}

	// Update fields that are set in the YAML file
	if yamlConfig.Port != "" {
		c.Port = yamlConfig.Port
	}
	if yamlConfig.TLSCertFile != "" {
		c.TLSCertFile = yamlConfig.TLSCertFile
	}
	if yamlConfig.TLSKeyFile != "" {
		c.TLSKeyFile = yamlConfig.TLSKeyFile
	}
	if yamlConfig.ProtectedPrefix != "" {
		c.ProtectedPrefix = yamlConfig.ProtectedPrefix
	}
	if yamlConfig.PrivilegedUser != "" {
		c.PrivilegedUser = yamlConfig.PrivilegedUser
	}
	if len(yamlConfig.CELRules) > 0 {
		c.CELRules = yamlConfig.CELRules
	}

	return nil
}

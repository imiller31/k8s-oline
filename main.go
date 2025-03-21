package main

import (
	"flag"
	"log"

	"github.com/imiller31/k8s-auth-webhook/auth"
	"github.com/imiller31/k8s-auth-webhook/cel"
	"github.com/imiller31/k8s-auth-webhook/config"
	"github.com/imiller31/k8s-auth-webhook/server"
)

// main is the entry point for the webhook server
func main() {
	configFile := flag.String("config", "config.yaml", "Path to the configuration file")
	flag.Parse()

	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create CEL evaluator
	celEval, err := cel.NewEvaluator(cfg.CELRules)
	if err != nil {
		log.Fatalf("Failed to create CEL evaluator: %v", err)
	}

	// Create authorizer
	authorizer := auth.NewAuthorizer(cfg, celEval)

	// Create and start webhook server
	webhookServer := server.NewWebhookServer(cfg, authorizer)
	if err := webhookServer.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

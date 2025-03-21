package auth

import (
	"log"
	"strings"

	"github.com/imiller31/k8s-auth-webhook/cel"
	"github.com/imiller31/k8s-auth-webhook/config"
	authorizationv1 "k8s.io/api/authorization/v1"
)

type Authorizer struct {
	config  *config.Config
	celEval *cel.Evaluator
}

func NewAuthorizer(config *config.Config, celEval *cel.Evaluator) *Authorizer {
	return &Authorizer{
		config:  config,
		celEval: celEval,
	}
}

func (a *Authorizer) ProcessRequest(sar *authorizationv1.SubjectAccessReview) (bool, string) {
	log.Printf("Processing request for user: %s, groups: %v", sar.Spec.User, sar.Spec.Groups)

	// Check CEL rules first
	if allowed, reason := a.celEval.Evaluate(sar); !allowed {
		return false, reason
	}

	// Check for system:masters impersonation attempts
	if sar.Spec.ResourceAttributes != nil {
		log.Printf("Resource attributes: Group=%s, Version=%s, Resource=%s, Name=%s, Namespace=%s, Verb=%s",
			sar.Spec.ResourceAttributes.Group,
			sar.Spec.ResourceAttributes.Version,
			sar.Spec.ResourceAttributes.Resource,
			sar.Spec.ResourceAttributes.Name,
			sar.Spec.ResourceAttributes.Namespace,
			sar.Spec.ResourceAttributes.Verb)

		if sar.Spec.ResourceAttributes.Group == "authentication.k8s.io" &&
			sar.Spec.ResourceAttributes.Resource == "userextras" &&
			sar.Spec.ResourceAttributes.Subresource == "groups" &&
			sar.Spec.ResourceAttributes.Name == "system:masters" {
			return false, "Impersonation of system:masters group is not allowed"
		}
	}

	// Check for direct system:masters group impersonation
	if sar.Spec.NonResourceAttributes != nil &&
		strings.Contains(sar.Spec.NonResourceAttributes.Path, "/groups/system:masters") {
		return false, "Direct impersonation of system:masters group is not allowed"
	}

	// Check for protected resource deletion
	if sar.Spec.ResourceAttributes != nil &&
		sar.Spec.ResourceAttributes.Verb == "delete" &&
		strings.HasPrefix(sar.Spec.ResourceAttributes.Name, a.config.ProtectedPrefix) {

		// Allow privileged user
		if sar.Spec.User == a.config.PrivilegedUser {
			log.Printf("Allowing delete operation for privileged user on resource: %s", sar.Spec.ResourceAttributes.Name)
			return true, "User '" + sar.Spec.User + "' is authorized to delete protected resources as a privileged user"
		}

		// Allow system:masters group
		for _, group := range sar.Spec.Groups {
			if group == "system:masters" {
				log.Printf("Allowing delete operation for user %s in privileged group system:masters", sar.Spec.User)
				return true, "User '" + sar.Spec.User + "' is authorized to delete protected resources as a member of system:masters group"
			}
		}

		log.Printf("Blocking delete operation on protected resource for user: %s", sar.Spec.User)
		return false, "User '" + sar.Spec.User + "' is not authorized to delete resources with prefix '" + a.config.ProtectedPrefix + "'. Only '" + a.config.PrivilegedUser + "' users or members of system:masters/system:nodes groups can perform this operation."
	}

	log.Printf("Authorization decision for user %s: true, reason: Request allowed by authorization webhook", sar.Spec.User)
	return true, "Request allowed by authorization webhook"
}

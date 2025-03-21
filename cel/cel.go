package cel

import (
	"fmt"
	"log"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	authorizationv1 "k8s.io/api/authorization/v1"
)

// Evaluator handles CEL rule compilation and evaluation
type Evaluator struct {
	env      *cel.Env
	programs []cel.Program
}

// NewEvaluator creates a new CEL evaluator with the provided rules
func NewEvaluator(rules []string) (*Evaluator, error) {
	env, err := createEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %v", err)
	}

	programs, err := compileRules(env, rules)
	if err != nil {
		return nil, fmt.Errorf("failed to compile CEL rules: %v", err)
	}

	return &Evaluator{
		env:      env,
		programs: programs,
	}, nil
}

// createEnvironment sets up the CEL environment with necessary declarations
func createEnvironment() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Declarations(
			decls.NewVar("user", decls.String),
			decls.NewVar("groups", decls.NewListType(decls.String)),
			decls.NewVar("resourceAttributes", decls.NewMapType(decls.String, decls.String)),
			decls.NewVar("nonResourceAttributes", decls.NewMapType(decls.String, decls.String)),
		),
	)
}

// compileRules compiles CEL rules into programs
func compileRules(env *cel.Env, rules []string) ([]cel.Program, error) {
	var programs []cel.Program

	for _, rule := range rules {
		if rule == "" {
			continue
		}

		ast, issues := env.Compile(rule)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("failed to compile CEL rule '%s': %v", rule, issues.Err())
		}

		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("failed to create program for rule '%s': %v", rule, err)
		}

		programs = append(programs, prg)
	}

	return programs, nil
}

// Evaluate evaluates a SubjectAccessReview against the compiled rules
func (e *Evaluator) Evaluate(sar *authorizationv1.SubjectAccessReview) (bool, string) {
	if len(e.programs) == 0 {
		return true, "No CEL rules configured"
	}

	// Prepare variables for evaluation
	vars := map[string]interface{}{
		"user":   sar.Spec.User,
		"groups": sar.Spec.Groups,
	}

	// Add resource attributes if present
	if sar.Spec.ResourceAttributes != nil {
		attrs := map[string]string{
			"group":       sar.Spec.ResourceAttributes.Group,
			"version":     sar.Spec.ResourceAttributes.Version,
			"resource":    sar.Spec.ResourceAttributes.Resource,
			"name":        sar.Spec.ResourceAttributes.Name,
			"namespace":   sar.Spec.ResourceAttributes.Namespace,
			"verb":        sar.Spec.ResourceAttributes.Verb,
			"subresource": sar.Spec.ResourceAttributes.Subresource,
		}
		vars["resourceAttributes"] = attrs
	}

	// Add non-resource attributes if present
	if sar.Spec.NonResourceAttributes != nil {
		attrs := map[string]string{
			"path": sar.Spec.NonResourceAttributes.Path,
			"verb": sar.Spec.NonResourceAttributes.Verb,
		}
		vars["nonResourceAttributes"] = attrs
	}

	// Evaluate each rule
	for i, program := range e.programs {
		result, _, err := program.Eval(vars)
		if err != nil {
			log.Printf("Error evaluating rule %d: %v", i, err)
			return false, fmt.Sprintf("Error evaluating CEL rule %d", i)
		}

		allowed, ok := result.Value().(bool)
		if !ok {
			log.Printf("Rule %d did not return a boolean", i)
			return false, fmt.Sprintf("Invalid result from CEL rule %d", i)
		}

		if !allowed {
			return false, fmt.Sprintf("Request denied by CEL rule %d", i)
		}
	}

	return true, "Request allowed by CEL rules"
}

package rules

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/titus"
	"github.com/praetorian-inc/titus/pkg/rule"
	"github.com/praetorian-inc/titus/pkg/types"
	"gopkg.in/yaml.v3"
)

// RuleDefinition represents a single rule as defined in a custom YAML rules file.
type RuleDefinition struct {
	Name             string   `yaml:"name"`
	ID               string   `yaml:"id"`
	Pattern          string   `yaml:"pattern"`
	References       []string `yaml:"references,omitempty"`
	Examples         []string `yaml:"examples,omitempty"`
	NegativeExamples []string `yaml:"negative_examples,omitempty"`
	Categories       []string `yaml:"categories,omitempty"`
	Description      string   `yaml:"description,omitempty"`
}

// RulesFile represents the top-level structure of a rules YAML file.
type RulesFile struct {
	Rules []RuleDefinition `yaml:"rules"`
}

// LoadAllRules loads the Titus builtin rules (459+) and merges them with any
// custom rules found in the given directory. Returns a fully configured
// titus.Scanner ready to scan content.
func LoadAllRules(customRulesDir string) (*titus.Scanner, int, error) {
	// Load builtin rules from the Titus library
	loader := rule.NewLoader()
	builtinRules, err := loader.LoadBuiltinRules()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to load Titus builtin rules: %w", err)
	}
	slog.Info("Loaded Titus builtin rules", "count", len(builtinRules))

	// Load custom rules from directory
	customRules := loadCustomRulesFromDirectory(customRulesDir)
	if len(customRules) > 0 {
		slog.Info("Loaded custom rules", "count", len(customRules), "dir", customRulesDir)
	}

	// Merge: builtin + custom
	allRules := make([]*types.Rule, 0, len(builtinRules)+len(customRules))
	allRules = append(allRules, builtinRules...)
	allRules = append(allRules, customRules...)

	totalCount := len(allRules)
	slog.Info("Total rules loaded", "builtin", len(builtinRules), "custom", len(customRules), "total", totalCount)

	// Create a Titus scanner with all rules
	scanner, err := titus.NewScanner(titus.WithRules(allRules))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create Titus scanner: %w", err)
	}

	return scanner, totalCount, nil
}

// loadCustomRulesFromDirectory walks the given directory for .yaml and .yml files,
// parses them as rule definition files, and converts them to Titus Rule objects.
func loadCustomRulesFromDirectory(dir string) []*types.Rule {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("Custom rules directory does not exist, using builtin rules only", "dir", dir)
		} else {
			slog.Warn("Failed to stat custom rules directory", "dir", dir, "error", err)
		}
		return nil
	}

	if !info.IsDir() {
		slog.Warn("Custom rules path is not a directory", "dir", dir)
		return nil
	}

	var allRules []*types.Rule

	err = filepath.Walk(dir, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			slog.Warn("Error walking custom rules directory", "path", path, "error", walkErr)
			return nil
		}

		if fi.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		rules, parseErr := parseCustomRulesFile(path)
		if parseErr != nil {
			slog.Warn("Failed to load custom rules from file", "path", path, "error", parseErr)
			return nil
		}

		allRules = append(allRules, rules...)
		return nil
	})

	if err != nil {
		slog.Warn("Error walking custom rules directory", "dir", dir, "error", err)
	}

	return allRules
}

// parseCustomRulesFile reads a single YAML file and converts its rule definitions
// to Titus Rule objects.
func parseCustomRulesFile(path string) ([]*types.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var rulesFile RulesFile
	if err := yaml.Unmarshal(data, &rulesFile); err != nil {
		return nil, fmt.Errorf("failed to parse YAML in %s: %w", path, err)
	}

	var rules []*types.Rule

	for _, def := range rulesFile.Rules {
		if def.Pattern == "" {
			slog.Warn("Skipping custom rule with empty pattern",
				"name", def.Name,
				"id", def.ID,
				"file", path,
			)
			continue
		}

		r := &types.Rule{
			ID:               def.ID,
			Name:             def.Name,
			Pattern:          strings.TrimSpace(def.Pattern),
			Description:      def.Description,
			Examples:         def.Examples,
			NegativeExamples: def.NegativeExamples,
			References:       def.References,
			Categories:       def.Categories,
		}
		r.StructuralID = r.ComputeStructuralID()

		rules = append(rules, r)

		slog.Debug("Loaded custom rule",
			"name", def.Name,
			"id", def.ID,
			"file", path,
		)
	}

	slog.Info("Loaded custom rules from file",
		"path", path,
		"rules_loaded", len(rules),
		"rules_in_file", len(rulesFile.Rules),
	)

	return rules, nil
}

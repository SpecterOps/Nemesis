package rules

import (
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

func TestFilterDisabledRules(t *testing.T) {
	// Helper to create test rules
	makeRules := func(ids ...string) []*types.Rule {
		rules := make([]*types.Rule, len(ids))
		for i, id := range ids {
			rules[i] = &types.Rule{ID: id, Name: "Rule " + id}
		}
		return rules
	}

	t.Run("no disabled rules", func(t *testing.T) {
		allRules := makeRules("np.aws.1", "np.github.2", "np.linkedin.3")
		disabledRules := []string{}

		// Simulate the filtering logic from LoadAllRules
		filtered := filterRules(allRules, disabledRules)

		if len(filtered) != 3 {
			t.Errorf("expected 3 rules, got %d", len(filtered))
		}
	})

	t.Run("one disabled rule", func(t *testing.T) {
		allRules := makeRules("np.aws.1", "np.github.2", "np.linkedin.3")
		disabledRules := []string{"np.linkedin.3"}

		filtered := filterRules(allRules, disabledRules)

		if len(filtered) != 2 {
			t.Errorf("expected 2 rules, got %d", len(filtered))
		}
		for _, r := range filtered {
			if r.ID == "np.linkedin.3" {
				t.Error("disabled rule np.linkedin.3 should have been filtered out")
			}
		}
	})

	t.Run("multiple disabled rules", func(t *testing.T) {
		allRules := makeRules("np.aws.1", "np.github.2", "np.linkedin.3")
		disabledRules := []string{"np.aws.1", "np.linkedin.3"}

		filtered := filterRules(allRules, disabledRules)

		if len(filtered) != 1 {
			t.Errorf("expected 1 rule, got %d", len(filtered))
		}
		if filtered[0].ID != "np.github.2" {
			t.Errorf("expected remaining rule np.github.2, got %s", filtered[0].ID)
		}
	})

	t.Run("disabled rule not in list", func(t *testing.T) {
		allRules := makeRules("np.aws.1", "np.github.2")
		disabledRules := []string{"np.nonexistent.99"}

		filtered := filterRules(allRules, disabledRules)

		if len(filtered) != 2 {
			t.Errorf("expected 2 rules, got %d", len(filtered))
		}
	})

	t.Run("nil disabled rules", func(t *testing.T) {
		allRules := makeRules("np.aws.1", "np.github.2")

		filtered := filterRules(allRules, nil)

		if len(filtered) != 2 {
			t.Errorf("expected 2 rules, got %d", len(filtered))
		}
	})
}

// filterRules applies the same filtering logic used in LoadAllRules.
// Extracted here for testability without needing Titus builtin rules.
func filterRules(allRules []*types.Rule, disabledRules []string) []*types.Rule {
	if len(disabledRules) == 0 {
		return allRules
	}
	disabled := make(map[string]bool, len(disabledRules))
	for _, id := range disabledRules {
		disabled[id] = true
	}
	filtered := make([]*types.Rule, 0, len(allRules))
	for _, r := range allRules {
		if !disabled[r.ID] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

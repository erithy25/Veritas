use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};
use uuid::Uuid;
use veritas_shared::types::{ReasonCategory, ReasonCodeEntry, VerdictDecision};

use crate::scoring::ScoringOutput;

// ---------------------------------------------------------------------------
// Tenant policy types
// ---------------------------------------------------------------------------

/// Per-tenant policy configuration that overrides default scoring thresholds
/// and adds custom rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPolicy {
    pub tenant_id: Uuid,
    /// Custom thresholds for verdict mapping (override defaults).
    pub thresholds: VerdictThresholds,
    /// Ordered list of custom rules evaluated top-down.  First matching rule
    /// wins (short-circuit).
    pub rules: Vec<PolicyRule>,
    /// Whether to auto-block on known-hash match regardless of score.
    pub auto_block_known_hash: bool,
    /// Minimum L3 model agreement ratio required to trust the ensemble score.
    pub min_model_agreement: f32,
}

impl Default for TenantPolicy {
    fn default() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            thresholds: VerdictThresholds::default(),
            rules: Vec::new(),
            auto_block_known_hash: true,
            min_model_agreement: 0.5,
        }
    }
}

/// Configurable thresholds for mapping a risk score to a verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VerdictThresholds {
    /// Scores below this value result in ALLOW.
    pub allow_max: f32,
    /// Scores in [allow_max, flag_max) result in FLAG.
    pub flag_max: f32,
    /// Scores in [flag_max, flag_urgent_max) result in FLAG_URGENT.
    /// Scores >= flag_urgent_max result in BLOCK.
    pub flag_urgent_max: f32,
}

impl Default for VerdictThresholds {
    fn default() -> Self {
        Self {
            allow_max: 0.30,
            flag_max: 0.60,
            flag_urgent_max: 0.85,
        }
    }
}

/// A custom policy rule that can override the default verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable rule identifier.
    pub rule_id: String,
    /// Description shown in audit logs.
    pub description: String,
    /// The condition that triggers this rule.
    pub condition: RuleCondition,
    /// The verdict to apply when the condition matches.
    pub action: RuleAction,
}

/// Conditions that can trigger a policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    /// Matches if *any* of the given reason codes are present.
    ReasonCodePresent { codes: Vec<String> },
    /// Matches if the final score exceeds the given value.
    ScoreAbove { threshold: f32 },
    /// Matches if the final score is below the given value.
    ScoreBelow { threshold: f32 },
    /// Matches if the context multiplier exceeds the given value.
    ContextMultiplierAbove { threshold: f32 },
    /// Matches if a specific reason category is present.
    CategoryPresent { category: ReasonCategory },
    /// Boolean AND of multiple sub-conditions.
    AllOf { conditions: Vec<RuleCondition> },
    /// Boolean OR of multiple sub-conditions.
    AnyOf { conditions: Vec<RuleCondition> },
}

/// Action taken when a rule matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAction {
    /// Override the verdict to this value.
    pub verdict: VerdictDecision,
    /// Additional reason code appended to the output.
    pub reason_code: String,
    /// Explanation for the override.
    pub explanation: String,
}

// ---------------------------------------------------------------------------
// Policy engine
// ---------------------------------------------------------------------------

/// The final output after policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOutput {
    /// The verdict after policy overrides.
    pub verdict: VerdictDecision,
    /// The final risk score (unchanged by policy, but included for convenience).
    pub risk_score: f32,
    /// Merged reason codes (scoring reasons + any policy-triggered reasons).
    pub reason_codes: Vec<ReasonCodeEntry>,
    /// If a policy rule overrode the verdict, its rule_id.
    pub override_rule_id: Option<String>,
}

/// In-memory policy store.  In production this would be backed by a database
/// or config service with hot-reload.
#[derive(Debug, Clone, Default)]
pub struct PolicyStore {
    policies: HashMap<Uuid, TenantPolicy>,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    /// Register or replace a tenant policy.
    pub fn upsert(&mut self, policy: TenantPolicy) {
        self.policies.insert(policy.tenant_id, policy);
    }

    /// Retrieve the policy for a tenant, falling back to defaults.
    pub fn get(&self, tenant_id: &Uuid) -> TenantPolicy {
        self.policies
            .get(tenant_id)
            .cloned()
            .unwrap_or_else(|| {
                debug!(%tenant_id, "No tenant-specific policy found; using defaults");
                TenantPolicy {
                    tenant_id: *tenant_id,
                    ..Default::default()
                }
            })
    }
}

/// Evaluate a scoring output against the tenant's policy.
///
/// Returns a `PolicyOutput` that may override the verdict produced by
/// the scoring layer.
#[instrument(skip_all, fields(tenant_id = %tenant_id, original_verdict, final_verdict))]
pub fn evaluate_policy(
    tenant_id: &Uuid,
    scoring: &ScoringOutput,
    policy: &TenantPolicy,
) -> PolicyOutput {
    let mut reason_codes = scoring.reason_codes.clone();

    // Step 1: Re-map verdict using tenant-specific thresholds.
    let threshold_verdict = map_with_thresholds(scoring.final_score, &policy.thresholds);

    tracing::Span::current().record("original_verdict", scoring.verdict.as_str());

    if threshold_verdict != scoring.verdict {
        debug!(
            original = scoring.verdict.as_str(),
            remapped = threshold_verdict.as_str(),
            "Verdict remapped by tenant thresholds"
        );
    }

    let mut final_verdict = threshold_verdict;
    let mut override_rule_id: Option<String> = None;

    // Step 2: Evaluate custom rules (first match wins).
    for rule in &policy.rules {
        if evaluate_condition(&rule.condition, scoring, &reason_codes) {
            debug!(
                rule_id = %rule.rule_id,
                action_verdict = rule.action.verdict.as_str(),
                "Policy rule matched"
            );

            final_verdict = rule.action.verdict;
            override_rule_id = Some(rule.rule_id.clone());

            reason_codes.push(ReasonCodeEntry {
                code: rule.action.reason_code.clone(),
                category: ReasonCategory::Context,
                explanation: rule.action.explanation.clone(),
                confidence: 1.0,
            });

            break; // First-match semantics.
        }
    }

    // Step 3: Auto-block on known-hash match if policy says so.
    if policy.auto_block_known_hash
        && reason_codes.iter().any(|r| r.code == "L1_HASH_MATCH")
        && final_verdict != VerdictDecision::Block
    {
        warn!(
            %tenant_id,
            "Auto-blocking due to known-hash match per tenant policy"
        );
        final_verdict = VerdictDecision::Block;
        override_rule_id = Some("AUTO_BLOCK_KNOWN_HASH".to_string());
        reason_codes.push(ReasonCodeEntry {
            code: "POLICY_AUTO_BLOCK_HASH".to_string(),
            category: ReasonCategory::Context,
            explanation: "Tenant policy auto-blocks media matching known deepfake hashes"
                .to_string(),
            confidence: 1.0,
        });
    }

    tracing::Span::current().record("final_verdict", final_verdict.as_str());

    PolicyOutput {
        verdict: final_verdict,
        risk_score: scoring.final_score,
        reason_codes,
        override_rule_id,
    }
}

/// Map a score to a verdict using the given thresholds.
fn map_with_thresholds(score: f32, thresholds: &VerdictThresholds) -> VerdictDecision {
    if score < thresholds.allow_max {
        VerdictDecision::Allow
    } else if score < thresholds.flag_max {
        VerdictDecision::Flag
    } else if score < thresholds.flag_urgent_max {
        VerdictDecision::FlagUrgent
    } else {
        VerdictDecision::Block
    }
}

/// Recursively evaluate a rule condition against the current scoring output.
fn evaluate_condition(
    condition: &RuleCondition,
    scoring: &ScoringOutput,
    reason_codes: &[ReasonCodeEntry],
) -> bool {
    match condition {
        RuleCondition::ReasonCodePresent { codes } => {
            codes.iter().any(|c| reason_codes.iter().any(|r| &r.code == c))
        }
        RuleCondition::ScoreAbove { threshold } => scoring.final_score > *threshold,
        RuleCondition::ScoreBelow { threshold } => scoring.final_score < *threshold,
        RuleCondition::ContextMultiplierAbove { threshold } => {
            scoring.context_multiplier > *threshold
        }
        RuleCondition::CategoryPresent { category } => {
            reason_codes.iter().any(|r| r.category == *category)
        }
        RuleCondition::AllOf { conditions } => conditions
            .iter()
            .all(|c| evaluate_condition(c, scoring, reason_codes)),
        RuleCondition::AnyOf { conditions } => conditions
            .iter()
            .any(|c| evaluate_condition(c, scoring, reason_codes)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scoring_output(score: f32, verdict: VerdictDecision) -> ScoringOutput {
        ScoringOutput {
            base_score: score,
            context_multiplier: 1.0,
            final_score: score,
            verdict,
            reason_codes: vec![],
        }
    }

    #[test]
    fn default_policy_preserves_verdict() {
        let tenant_id = Uuid::new_v4();
        let scoring = make_scoring_output(0.20, VerdictDecision::Allow);
        let policy = TenantPolicy::default();

        let output = evaluate_policy(&tenant_id, &scoring, &policy);
        assert_eq!(output.verdict, VerdictDecision::Allow);
        assert!(output.override_rule_id.is_none());
    }

    #[test]
    fn custom_thresholds_change_verdict() {
        let tenant_id = Uuid::new_v4();
        let scoring = make_scoring_output(0.25, VerdictDecision::Allow);

        // Tenant with stricter thresholds.
        let policy = TenantPolicy {
            tenant_id,
            thresholds: VerdictThresholds {
                allow_max: 0.20,
                flag_max: 0.50,
                flag_urgent_max: 0.75,
            },
            ..Default::default()
        };

        let output = evaluate_policy(&tenant_id, &scoring, &policy);
        assert_eq!(output.verdict, VerdictDecision::Flag);
    }

    #[test]
    fn custom_rule_overrides_verdict() {
        let tenant_id = Uuid::new_v4();
        let mut scoring = make_scoring_output(0.40, VerdictDecision::Flag);
        scoring.reason_codes.push(ReasonCodeEntry {
            code: "L3_GAN_DETECTION".to_string(),
            category: ReasonCategory::L3Neural,
            explanation: "test".to_string(),
            confidence: 0.9,
        });

        let policy = TenantPolicy {
            tenant_id,
            rules: vec![PolicyRule {
                rule_id: "ESCALATE_GAN".to_string(),
                description: "Escalate GAN detections to FLAG_URGENT".to_string(),
                condition: RuleCondition::ReasonCodePresent {
                    codes: vec!["L3_GAN_DETECTION".to_string()],
                },
                action: RuleAction {
                    verdict: VerdictDecision::FlagUrgent,
                    reason_code: "POLICY_ESCALATE_GAN".to_string(),
                    explanation: "Tenant policy escalates GAN detections".to_string(),
                },
            }],
            ..Default::default()
        };

        let output = evaluate_policy(&tenant_id, &scoring, &policy);
        assert_eq!(output.verdict, VerdictDecision::FlagUrgent);
        assert_eq!(output.override_rule_id, Some("ESCALATE_GAN".to_string()));
    }

    #[test]
    fn auto_block_known_hash() {
        let tenant_id = Uuid::new_v4();
        let mut scoring = make_scoring_output(0.35, VerdictDecision::Flag);
        scoring.reason_codes.push(ReasonCodeEntry {
            code: "L1_HASH_MATCH".to_string(),
            category: ReasonCategory::L1Hash,
            explanation: "known hash".to_string(),
            confidence: 0.99,
        });

        let policy = TenantPolicy {
            tenant_id,
            auto_block_known_hash: true,
            ..Default::default()
        };

        let output = evaluate_policy(&tenant_id, &scoring, &policy);
        assert_eq!(output.verdict, VerdictDecision::Block);
        assert!(output
            .reason_codes
            .iter()
            .any(|r| r.code == "POLICY_AUTO_BLOCK_HASH"));
    }

    #[test]
    fn composite_rule_condition() {
        let tenant_id = Uuid::new_v4();
        let mut scoring = make_scoring_output(0.70, VerdictDecision::FlagUrgent);
        scoring.context_multiplier = 1.45;
        scoring.reason_codes.push(ReasonCodeEntry {
            code: "CTX_PUBLIC_FIGURE".to_string(),
            category: ReasonCategory::Context,
            explanation: "test".to_string(),
            confidence: 0.9,
        });

        let policy = TenantPolicy {
            tenant_id,
            rules: vec![PolicyRule {
                rule_id: "BLOCK_HIGH_CONTEXT".to_string(),
                description: "Block when score > 0.60 AND public figure".to_string(),
                condition: RuleCondition::AllOf {
                    conditions: vec![
                        RuleCondition::ScoreAbove { threshold: 0.60 },
                        RuleCondition::ReasonCodePresent {
                            codes: vec!["CTX_PUBLIC_FIGURE".to_string()],
                        },
                    ],
                },
                action: RuleAction {
                    verdict: VerdictDecision::Block,
                    reason_code: "POLICY_BLOCK_PUBLIC_FIGURE_HIGH".to_string(),
                    explanation: "Public figure content with high risk score auto-blocked"
                        .to_string(),
                },
            }],
            ..Default::default()
        };

        let output = evaluate_policy(&tenant_id, &scoring, &policy);
        assert_eq!(output.verdict, VerdictDecision::Block);
        assert_eq!(
            output.override_rule_id,
            Some("BLOCK_HIGH_CONTEXT".to_string())
        );
    }

    #[test]
    fn policy_store_fallback() {
        let store = PolicyStore::new();
        let tenant_id = Uuid::new_v4();
        let policy = store.get(&tenant_id);
        assert_eq!(policy.thresholds.allow_max, 0.30);
    }
}

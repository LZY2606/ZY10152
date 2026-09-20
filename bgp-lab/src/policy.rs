//! Ordered policy evaluation with explicit semantics:
//! - a rule that does not match: evaluation continues to the next rule
//!   (`miss` / "没有命中继续");
//! - a matching rule with `on_match = continue`: its actions apply and evaluation
//!   continues (`hit-continue` / "命中并继续"); later conditions see the NEW values;
//! - a matching rule with `on_match = accept|reject`: evaluation terminates
//!   (`hit-accept` / `hit-reject` / "终止接受/拒绝");
//! - falling off the end applies the policy default decision.

use crate::model::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleOutcome {
    Miss,
    HitContinue,
    HitAccept,
    HitReject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTraceEntry {
    pub index: usize,
    pub rule: String,
    pub outcome: RuleOutcome,
    /// Human-readable explanation of why the rule matched or missed.
    pub detail: String,
    /// Snapshot of the route *after* this rule's actions were applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<Route>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVerdict {
    pub decision: Verdict,
    /// Stable machine-readable reason code.
    pub reason: String,
    /// `default-accept` / `default-reject` when no terminating rule matched.
    pub defaulted: bool,
    pub trace: Vec<RuleTraceEntry>,
}

fn prefix_matches(pattern: &str, prefix: &str, cmp: Cmp) -> bool {
    match cmp {
        Cmp::Eq => pattern == prefix,
        Cmp::Ne => pattern != prefix,
        Cmp::Matches => glob_match(pattern, prefix),
        Cmp::In => glob_match(pattern, prefix),
        Cmp::NotIn => !glob_match(pattern, prefix),
        _ => pattern == prefix,
    }
}

/// Tiny glob: `*` matches any run, `?` one character; also supports `10.0.0.0/8`-style
/// prefix-set patterns passed verbatim (exact). Sufficient for fixtures.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn helper(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => {
                helper(&p[1..], t) || t.first().map_or(false, |_| helper(p, &t[1..]))
            }
            (Some(b'?'), Some(_)) => helper(&p[1..], &t[1..]),
            (Some(pc), Some(tc)) if pc == tc => helper(&p[1..], &t[1..]),
            _ => false,
        }
    }
    helper(pattern.as_bytes(), text.as_bytes())
}

fn num_cmp(want: i64, have: i64, cmp: Cmp) -> bool {
    match cmp {
        Cmp::Eq => have == want,
        Cmp::Ne => have != want,
        Cmp::Gte => have >= want,
        Cmp::Lte => have <= want,
        _ => have == want,
    }
}

fn community_present(wanted: &[String], have: &[String], cmp: Cmp) -> bool {
    let any = wanted.iter().any(|w| have.iter().any(|h| h == w));
    match cmp {
        Cmp::NotIn => !any,
        _ => any,
    }
}

/// Evaluate one match block against the CURRENT route (post previous rewrites).
/// Returns true + a list of human-readable match facts on match.
fn evaluate_match(m: &Match, route: &Route, peer: &str) -> (bool, Vec<String>) {
    let mut facts = Vec::new();

    if let Some(want) = &m.peer {
        if want != peer {
            return (false, vec![format!("peer {peer} != {want}")]);
        }
        facts.push(format!("peer {peer}"));
    }

    if let Some(want) = &m.prefix {
        let cmp = m.prefix_cmp.unwrap_or(Cmp::Eq);
        if !prefix_matches(want, &route.prefix, cmp) {
            return (
                false,
                vec![format!("prefix {} failed {:?} {want}", route.prefix, cmp)],
            );
        }
        facts.push(format!("prefix {} {:?} {want}", route.prefix, cmp));
    }

    if let Some(want) = m.as_path_len {
        let cmp = m.as_path_len_cmp.unwrap_or(Cmp::Eq);
        let have = route.as_path.len() as i64;
        if !num_cmp(want as i64, have, cmp) {
            return (
                false,
                vec![format!("as_path_len {have} failed {:?} {want}", cmp)],
            );
        }
        facts.push(format!("as_path_len {have} {:?} {want}", cmp));
    }

    if !m.as_path_contains.is_empty() {
        let missing: Vec<u32> = m
            .as_path_contains
            .iter()
            .copied()
            .filter(|asn| !route.as_path.contains(asn))
            .collect();
        if !missing.is_empty() {
            return (false, vec![format!("as_path missing {:?}", missing)]);
        }
        facts.push(format!("as_path contains {:?}", m.as_path_contains));
    }

    if let Some(want) = m.local_pref {
        let cmp = m.local_pref_cmp.unwrap_or(Cmp::Eq);
        if !num_cmp(want, route.local_pref, cmp) {
            return (
                false,
                vec![format!(
                    "local_pref {} failed {:?} {want}",
                    route.local_pref, cmp
                )],
            );
        }
        facts.push(format!("local_pref {} {:?} {want}", route.local_pref, cmp));
    }

    if let Some(want) = m.med {
        let cmp = m.med_cmp.unwrap_or(Cmp::Eq);
        let have = route.med.unwrap_or(0);
        if !num_cmp(want, have, cmp) {
            return (false, vec![format!("med {have} failed {:?} {want}", cmp)]);
        }
        facts.push(format!("med {have} {:?} {want}", cmp));
    }

    if !m.community_any.is_empty() {
        let cmp = m.community_any_cmp.unwrap_or(Cmp::In);
        if !community_present(&m.community_any, &route.communities, cmp) {
            return (
                false,
                vec![format!(
                    "communities {:?} failed {:?} {:?}",
                    route.communities, cmp, m.community_any
                )],
            );
        }
        facts.push(format!(
            "community {:?} {:?} {:?}",
            cmp, m.community_any, route.communities
        ));
    }

    (true, facts)
}

fn apply_action(route: &mut Route, a: &Action) -> Vec<String> {
    let mut changes = Vec::new();
    if let Some(v) = a.set_local_pref {
        changes.push(format!("local_pref {} -> {v}", route.local_pref));
        route.local_pref = v;
    }
    if let Some(v) = a.set_med {
        changes.push(format!("med {:?} -> {v}", route.med));
        route.med = Some(v);
    }
    if let Some(c) = &a.add_community {
        if !route.communities.iter().any(|x| x == c) {
            route.communities.push(c.clone());
        }
        changes.push(format!("add community {c}"));
    }
    if !a.remove_communities.is_empty() {
        let before = route.communities.len();
        route
            .communities
            .retain(|x| !a.remove_communities.contains(x));
        if route.communities.len() != before {
            changes.push(format!("remove communities {:?}", a.remove_communities));
        }
    }
    if let Some(n) = a.as_path_prepend {
        if n > 0 {
            changes.push(format!("as_path_prepend +{n} (applied at send boundary)"));
        }
    }
    changes
}

/// Evaluate an ordered rule list. `prepend_n` for extra prepend actions is returned
/// separately because AS_PATH prepend materializes at the send boundary (export) where
/// the advertising AS is known.
pub fn evaluate(
    rules: &[Rule],
    route_in: &Route,
    peer: &str,
    default: Decision,
) -> (PolicyVerdict, Route, u32) {
    let mut route = route_in.clone();
    let mut trace = Vec::new();
    let mut prepend_n: u32 = 0;

    for (index, rule) in rules.iter().enumerate() {
        let (matched, facts) = evaluate_match(&rule.when, &route, peer);
        if !matched {
            trace.push(RuleTraceEntry {
                index,
                rule: rule.id.clone(),
                outcome: RuleOutcome::Miss,
                detail: facts.join("; "),
                after: None,
            });
            continue;
        }

        let changes = apply_action(&mut route, &rule.do_);
        if let Some(n) = rule.do_.as_path_prepend {
            prepend_n = prepend_n.saturating_add(n);
        }

        let mut detail = facts.join(", ");
        if !changes.is_empty() {
            detail.push_str(" | ");
            detail.push_str(&changes.join(", "));
        }

        match rule.on_match {
            OnMatch::Continue => {
                trace.push(RuleTraceEntry {
                    index,
                    rule: rule.id.clone(),
                    outcome: RuleOutcome::HitContinue,
                    detail,
                    after: Some(route.clone()),
                });
            }
            OnMatch::Accept => {
                trace.push(RuleTraceEntry {
                    index,
                    rule: rule.id.clone(),
                    outcome: RuleOutcome::HitAccept,
                    detail,
                    after: Some(route.clone()),
                });
                return (
                    PolicyVerdict {
                        decision: Verdict::Accept,
                        reason: format!("rule {} terminated accept", rule.id),
                        defaulted: false,
                        trace,
                    },
                    route,
                    prepend_n,
                );
            }
            OnMatch::Reject => {
                trace.push(RuleTraceEntry {
                    index,
                    rule: rule.id.clone(),
                    outcome: RuleOutcome::HitReject,
                    detail,
                    after: Some(route.clone()),
                });
                return (
                    PolicyVerdict {
                        decision: Verdict::Reject,
                        reason: format!("rule {} terminated reject", rule.id),
                        defaulted: false,
                        trace,
                    },
                    route,
                    prepend_n,
                );
            }
        }
    }

    let (decision, reason) = match default {
        Decision::Accept => (
            Verdict::Accept,
            "no terminating rule matched: policy default accept".to_string(),
        ),
        Decision::Reject => (
            Verdict::Reject,
            "no terminating rule matched: policy default reject".to_string(),
        ),
    };
    (
        PolicyVerdict {
            decision,
            reason,
            defaulted: true,
            trace,
        },
        route,
        prepend_n,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_route() -> Route {
        Route {
            prefix: "10.0.0.0/24".into(),
            as_path: vec![64500],
            local_pref: 100,
            med: Some(10),
            communities: vec!["64500:10".into()],
            provenance: Provenance::EBgp,
            ingress_session: Some("s".into()),
            first_as: None,
        }
    }

    #[test]
    fn rewrite_visible_to_later_conditions() {
        let rules = vec![
            Rule {
                id: "set".into(),
                description: "".into(),
                when: Match {
                    prefix: Some("10.0.0.0/24".into()),
                    ..Default::default()
                },
                do_: Action {
                    set_local_pref: Some(300),
                    ..Default::default()
                },
                on_match: OnMatch::Continue,
            },
            Rule {
                id: "see-new".into(),
                description: "".into(),
                when: Match {
                    local_pref: Some(300),
                    local_pref_cmp: Some(Cmp::Eq),
                    ..Default::default()
                },
                do_: Action::default(),
                on_match: OnMatch::Accept,
            },
        ];
        let (v, route, _) = evaluate(&rules, &base_route(), "peer-x", Decision::Reject);
        assert_eq!(v.decision, Verdict::Accept);
        assert_eq!(v.defaulted, false);
        assert_eq!(route.local_pref, 300);
        assert_eq!(v.trace[1].outcome, RuleOutcome::HitAccept);
    }

    #[test]
    fn miss_continues_to_default_reject() {
        let rules = vec![Rule {
            id: "other".into(),
            description: "".into(),
            when: Match {
                prefix: Some("9.9.9.9/32".into()),
                ..Default::default()
            },
            do_: Action::default(),
            on_match: OnMatch::Accept,
        }];
        let (v, _, _) = evaluate(&rules, &base_route(), "peer-x", Decision::Reject);
        assert_eq!(v.decision, Verdict::Reject);
        assert!(v.defaulted);
        assert_eq!(v.trace[0].outcome, RuleOutcome::Miss);
    }

    #[test]
    fn terminate_reject_short_circuits() {
        let rules = vec![
            Rule {
                id: "deny".into(),
                description: "".into(),
                when: Match {
                    community_any: vec!["64500:10".into()],
                    ..Default::default()
                },
                do_: Action {
                    add_community: Some("x".into()),
                    ..Default::default()
                },
                on_match: OnMatch::Reject,
            },
            Rule {
                id: "unreachable".into(),
                description: "".into(),
                when: Match::default(),
                do_: Action::default(),
                on_match: OnMatch::Accept,
            },
        ];
        let (v, route, _) = evaluate(&rules, &base_route(), "peer-x", Decision::Accept);
        assert_eq!(v.decision, Verdict::Reject);
        assert_eq!(v.trace.len(), 1, "later rule must never be evaluated");
        assert!(route.communities.contains(&"x".to_string()));
    }
}

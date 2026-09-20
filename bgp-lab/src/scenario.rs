//! Scenario snapshot branching, edit application and rule-level diffs.

use crate::model::*;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiffOp {
    RuleAdded,
    RuleChanged,
    RuleRemoved,
    RuleReordered,
    AnnouncementWithdrawn,
    RestartInjected,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleDiff {
    pub op: DiffOp,
    pub node: NodeId,
    pub direction: String,
    pub rule: String,
    pub detail: String,
    pub before: Option<Rule>,
    pub after: Option<Rule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EditPreview {
    /// Fully materialized derived scenario (snapshot branch input).
    pub scenario: ScenarioInput,
    pub diffs: Vec<RuleDiff>,
    pub affected_nodes: Vec<NodeId>,
    pub affected_prefixes: Vec<Prefix>,
}

fn rules_of<'a>(input: &'a ScenarioInput, node: &str, dir: Direction) -> Option<&'a Vec<Rule>> {
    let spec = input.nodes.get(node)?;
    Some(match dir {
        Direction::Import => &spec.policy.import,
        Direction::Export => &spec.policy.export,
    })
}

fn rules_of_mut<'a>(
    input: &'a mut ScenarioInput,
    node: &str,
    dir: Direction,
) -> Option<&'a mut Vec<Rule>> {
    let spec = input.nodes.get_mut(node)?;
    Some(match dir {
        Direction::Import => &mut spec.policy.import,
        Direction::Export => &mut spec.policy.export,
    })
}

/// Apply an edit set to a snapshot, returning a NEW scenario (the base is never
/// overwritten — "新场景是基于快照的分支").
pub fn branch(
    base: &ScenarioInput,
    edits: &EditSet,
    branch_name: String,
) -> Result<EditPreview, String> {
    let mut next = base.clone();
    next.name = branch_name;

    let mut diffs: Vec<RuleDiff> = Vec::new();
    let mut affected_nodes: Vec<NodeId> = Vec::new();
    let affected_prefixes_hint: Vec<Prefix> = Vec::new();

    for edit in &edits.rules {
        let node_spec = base
            .nodes
            .get(&edit.node)
            .ok_or_else(|| format!("unknown node {}", edit.node))?;
        let rules = match edit.direction {
            Direction::Import => &node_spec.policy.import,
            Direction::Export => &node_spec.policy.export,
        };
        let existing_pos = rules.iter().position(|r| r.id == edit.rule.id);
        let before = existing_pos.map(|i| rules[i].clone());

        let target = rules_of_mut(&mut next, &edit.node, edit.direction).unwrap();
        match existing_pos {
            Some(pos) => {
                if target[pos] == edit.rule {
                    continue;
                }
                let op = if target[pos].when == edit.rule.when && target[pos].do_ == edit.rule.do_ {
                    DiffOp::RuleReordered
                } else {
                    DiffOp::RuleChanged
                };
                target[pos] = edit.rule.clone();
                diffs.push(RuleDiff {
                    op,
                    node: edit.node.clone(),
                    direction: edit.direction.as_str().to_string(),
                    rule: edit.rule.id.clone(),
                    detail: format!(
                        "rule {} on {} {} replaced",
                        edit.rule.id,
                        edit.node,
                        edit.direction.as_str()
                    ),
                    before,
                    after: Some(edit.rule.clone()),
                });
            }
            None => {
                if !edit.upsert {
                    return Err(format!(
                        "rule {} not found on {} {} and upsert=false",
                        edit.rule.id,
                        edit.node,
                        edit.direction.as_str()
                    ));
                }
                target.push(edit.rule.clone());
                diffs.push(RuleDiff {
                    op: DiffOp::RuleAdded,
                    node: edit.node.clone(),
                    direction: edit.direction.as_str().to_string(),
                    rule: edit.rule.id.clone(),
                    detail: format!(
                        "rule {} appended to {} {}",
                        edit.rule.id,
                        edit.node,
                        edit.direction.as_str()
                    ),
                    before: None,
                    after: Some(edit.rule.clone()),
                });
            }
        }
        if !affected_nodes.contains(&edit.node) {
            affected_nodes.push(edit.node.clone());
        }
    }

    for rm in &edits.removed_rule_ids {
        let rules = rules_of(&base, &rm.node, rm.direction)
            .ok_or_else(|| format!("unknown node {}", rm.node))?;
        let before = rules.iter().find(|r| r.id == rm.rule).cloned();
        let target = rules_of_mut(&mut next, &rm.node, rm.direction).unwrap();
        if let Some(pos) = target.iter().position(|r| r.id == rm.rule) {
            target.remove(pos);
            diffs.push(RuleDiff {
                op: DiffOp::RuleRemoved,
                node: rm.node.clone(),
                direction: rm.direction.as_str().to_string(),
                rule: rm.rule.clone(),
                detail: format!(
                    "rule {} removed from {} {}",
                    rm.rule,
                    rm.node,
                    rm.direction.as_str()
                ),
                before,
                after: None,
            });
            if !affected_nodes.contains(&rm.node) {
                affected_nodes.push(rm.node.clone());
            }
        }
    }

    for ann_id in &edits.withdraw {
        if next
            .events
            .iter()
            .any(|e| e.id() == format!("withdraw-{ann_id}"))
        {
            continue;
        }
        if let Some(ann) = next.announcements.iter().find(|a| &a.id == ann_id) {
            let tick = edits
                .restart_tick
                .unwrap_or_else(|| next.events.iter().map(|e| e.tick()).max().unwrap_or(0) + 1);
            next.events.push(EventSpec::Withdraw {
                id: format!("withdraw-{ann_id}"),
                announcement: ann_id.clone(),
                tick,
            });
            diffs.push(RuleDiff {
                op: DiffOp::AnnouncementWithdrawn,
                node: ann.node.clone(),
                direction: "event".into(),
                rule: ann_id.clone(),
                detail: format!(
                    "announcement {ann_id} ({}) withdrawn at tick {tick}",
                    ann.prefix
                ),
                before: None,
                after: None,
            });
            if !affected_nodes.contains(&ann.node) {
                affected_nodes.push(ann.node.clone());
            }
        }
    }

    for n in &edits.restart {
        if !next.nodes.contains_key(n) {
            return Err(format!("unknown node {n} for restart"));
        }
        let id = format!("restart-{}-{}", n, next.events.len());
        if next.events.iter().any(|e| e.id() == id) {
            continue;
        }
        let tick = edits
            .restart_tick
            .unwrap_or_else(|| next.events.iter().map(|e| e.tick()).max().unwrap_or(0) + 1);
        next.events.push(EventSpec::Restart {
            id,
            node: n.clone(),
            tick,
        });
        diffs.push(RuleDiff {
            op: DiffOp::RestartInjected,
            node: n.clone(),
            direction: "event".into(),
            rule: n.clone(),
            detail: format!("neighbor {n} restart injected at tick {tick}"),
            before: None,
            after: None,
        });
        if !affected_nodes.contains(n) {
            affected_nodes.push(n.clone());
        }
    }

    let _ = affected_prefixes_hint;
    Ok(EditPreview {
        scenario: next,
        diffs,
        affected_nodes,
        affected_prefixes: Vec::new(),
    })
}

/// Compute rule-level differences between two concurrent drafts against a common base.
/// Each rule reports the side(s) that changed it so conflicts are visible per rule.
#[derive(Debug, Clone, Serialize)]
pub struct ConcurrentDiff {
    pub rule: RuleRefKey,
    pub left: Option<Rule>,
    pub right: Option<Rule>,
    pub conflict: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleRefKey {
    pub node: NodeId,
    pub direction: String,
    pub rule: String,
}

fn rule_index(input: &ScenarioInput) -> std::collections::BTreeMap<(String, String, String), Rule> {
    let mut out = std::collections::BTreeMap::new();
    for (id, spec) in &input.nodes {
        for (dir, rules) in [
            ("import", &spec.policy.import),
            ("export", &spec.policy.export),
        ] {
            for r in rules {
                out.insert((id.clone(), dir.to_string(), r.id.clone()), r.clone());
            }
        }
    }
    out
}

pub fn concurrent_diff(
    base: &ScenarioInput,
    left: &ScenarioInput,
    right: &ScenarioInput,
) -> Vec<ConcurrentDiff> {
    let b = rule_index(base);
    let l = rule_index(left);
    let r = rule_index(right);
    let mut keys: std::collections::BTreeSet<(String, String, String)> =
        b.keys().cloned().collect();
    keys.extend(l.keys().cloned());
    keys.extend(r.keys().cloned());

    let mut out = Vec::new();
    for key in keys {
        let before = b.get(&key);
        let lv = l.get(&key);
        let rv = r.get(&key);
        let l_changed = lv != before;
        let r_changed = rv != before;
        if !l_changed && !r_changed {
            continue;
        }
        let conflict = l_changed && r_changed && lv != rv;
        let detail = match (l_changed, r_changed) {
            (true, true) if conflict => "both drafts changed this rule differently".into(),
            (true, true) => "both drafts changed this rule identically".into(),
            (true, false) => "only left draft changed this rule".into(),
            _ => "only right draft changed this rule".into(),
        };
        out.push(ConcurrentDiff {
            rule: RuleRefKey {
                node: key.0.clone(),
                direction: key.1.clone(),
                rule: key.2.clone(),
            },
            left: lv.cloned(),
            right: rv.cloned(),
            conflict,
            detail,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn branch_does_not_overwrite_base() {
        let base = fixtures::basic_preferences();
        let before = base.nodes["R2"].policy.import.len();
        let edits = EditSet {
            rules: vec![RuleEdit {
                node: "R2".into(),
                direction: Direction::Import,
                rule: Rule {
                    id: "extra".into(),
                    description: "".into(),
                    when: Match::default(),
                    do_: Action {
                        set_local_pref: Some(50),
                        ..Default::default()
                    },
                    on_match: OnMatch::Continue,
                },
                upsert: true,
            }],
            removed_rule_ids: vec![],
            withdraw: vec![],
            restart: vec![],
            restart_tick: None,
        };
        let preview = branch(&base, &edits, "child".into()).unwrap();
        assert_eq!(base.nodes["R2"].policy.import.len(), before);
        assert_eq!(preview.scenario.nodes["R2"].policy.import.len(), before + 1);
    }
}

use bgp_lab::fixtures;
use bgp_lab::model::*;
use bgp_lab::scenario::branch;

fn edit_set() -> EditSet {
    EditSet {
        rules: vec![RuleEdit {
            node: "R3".into(),
            direction: Direction::Import,
            rule: Rule {
                id: "prefer-community".into(),
                description: "lowered".into(),
                when: Match {
                    community_any: vec!["65002:exit-A".into()],
                    ..Default::default()
                },
                do_: Action {
                    set_local_pref: Some(120),
                    ..Default::default()
                },
                on_match: OnMatch::Continue,
            },
            upsert: false,
        }],
        removed_rule_ids: vec![],
        withdraw: vec![],
        restart: vec![],
        restart_tick: None,
    }
}

#[test]
fn preview_reports_affected_diffs_without_overwriting() {
    let base = fixtures::basic_preferences();
    let preview = branch(&base, &edit_set(), "trial".into()).unwrap();
    assert!(preview.diffs.iter().any(|d| d.node == "R3"));
    assert_ne!(
        base.nodes["R3"].policy.import[0].do_.set_local_pref,
        Some(120)
    );
    let run = bgp_lab::engine::simulate(&preview.scenario);
    assert_eq!(run.status, bgp_lab::engine::RunStatus::Stable);
}

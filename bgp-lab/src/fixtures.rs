//! Built-in demonstration scenarios ("fixtures with loops, attribute rewrites and
//! equal-cost paths").

use crate::model::*;
use std::collections::BTreeMap;

fn node(id: &str, asn: u32, x: f64, y: f64, policy: Policy) -> (String, NodeSpec) {
    (id.to_string(), NodeSpec { asn, x, y, policy })
}

fn sess(id: &str, local: &str, remote: &str, kind: SessionKind, delay: u64) -> Session {
    Session {
        id: id.into(),
        local: local.into(),
        remote: remote.into(),
        kind,
        delay,
    }
}

/// Simple AS-path / local-pref preference over a four-node chain + peer.
/// Topology:  AS65001 (R1 origin) -- eBGP -- R2 (AS65002) -- R3 (AS65003)
///                                   \-- eBGP -- R4 (AS65004) -- R3
/// R2 prefers the direct path via import local-pref policy rewrite.
pub fn basic_preferences() -> ScenarioInput {
    let r1 = node("R1", 65001, 60.0, 200.0, Policy::default());
    let mut r2_policy = Policy::default();
    r2_policy.import.push(Rule {
        id: "trust-r1".into(),
        description: "raise preference for routes learned from R1".into(),
        when: Match {
            peer: Some("R1".into()),
            ..Default::default()
        },
        do_: Action {
            set_local_pref: Some(300),
            add_community: Some("65002:trusted".into()),
            ..Default::default()
        },
        on_match: OnMatch::Continue,
    });
    r2_policy.export.push(Rule {
        id: "tag-multi-exit".into(),
        description: "tag routes exported to R3".into(),
        when: Match::default(),
        do_: Action {
            add_community: Some("65002:exit-A".into()),
            ..Default::default()
        },
        on_match: OnMatch::Continue,
    });
    let r2 = node("R2", 65002, 260.0, 120.0, r2_policy);

    let mut r3_policy = Policy::default();
    r3_policy.import.push(Rule {
        id: "prefer-community".into(),
        description: "prefer routes carrying the 65002:exit-A community".into(),
        when: Match {
            community_any: vec!["65002:exit-A".into()],
            ..Default::default()
        },
        do_: Action {
            set_local_pref: Some(250),
            ..Default::default()
        },
        on_match: OnMatch::Continue,
    });
    r3_policy.import.push(Rule {
        id: "block-no-community".into(),
        description: "demonstrate miss-continue (never terminates here)".into(),
        when: Match {
            community_any: vec!["65009:nope".into()],
            ..Default::default()
        },
        do_: Action::default(),
        on_match: OnMatch::Reject,
    });
    let r3 = node("R3", 65003, 480.0, 200.0, r3_policy);
    let r4 = node("R4", 65004, 260.0, 320.0, Policy::default());

    let mut nodes = BTreeMap::new();
    nodes.insert(r1.0.clone(), r1.1);
    nodes.insert(r2.0.clone(), r2.1);
    nodes.insert(r3.0.clone(), r3.1);
    nodes.insert(r4.0.clone(), r4.1);

    ScenarioInput {
        name: "basic-preferences".into(),
        description: "Local-pref / MED / community rewrite with miss-continue evidence.".into(),
        nodes,
        sessions: vec![
            sess("R1-R2", "R1", "R2", SessionKind::EBgp, 1),
            sess("R2-R1", "R2", "R1", SessionKind::EBgp, 1),
            sess("R2-R3", "R2", "R3", SessionKind::EBgp, 2),
            sess("R3-R2", "R3", "R2", SessionKind::EBgp, 2),
            sess("R2-R4", "R2", "R4", SessionKind::EBgp, 3),
            sess("R4-R2", "R4", "R2", SessionKind::EBgp, 3),
            sess("R4-R3", "R4", "R3", SessionKind::EBgp, 1),
            sess("R3-R4", "R3", "R4", SessionKind::EBgp, 1),
        ],
        announcements: vec![Announcement {
            id: "ann-prefix-a".into(),
            node: "R1".into(),
            prefix: "10.10.0.0/16".into(),
            local_pref: 100,
            med: Some(0),
            communities: vec!["65001:origin".into()],
        }],
        events: vec![EventSpec::Withdraw {
            id: "manual-withdraw-a".into(),
            announcement: "ann-prefix-a".into(),
            tick: 40,
        }],
        max_iterations: 100_000,
    }
}

/// MED + community rewrite + community-scoped termination.
pub fn med_community_rewrite() -> ScenarioInput {
    let mut nodes = BTreeMap::new();
    nodes.insert(
        "A".to_string(),
        NodeSpec {
            asn: 65101,
            x: 80.0,
            y: 160.0,
            policy: Policy::default(),
        },
    );
    let mut b = NodeSpec {
        asn: 65102,
        x: 280.0,
        y: 120.0,
        policy: Policy::default(),
    };
    b.policy.export.push(Rule {
        id: "set-med-50".into(),
        description: "lower MED toward C".into(),
        when: Match {
            peer: Some("C".into()),
            ..Default::default()
        },
        do_: Action {
            set_med: Some(50),
            add_community: Some("65102:low-med".into()),
            ..Default::default()
        },
        on_match: OnMatch::Continue,
    });
    b.policy.export.push(Rule {
        id: "strip-origin-tag".into(),
        description: "remove origin community on export".into(),
        when: Match::default(),
        do_: Action {
            remove_communities: vec!["65101:internal".into()],
            ..Default::default()
        },
        on_match: OnMatch::Continue,
    });
    nodes.insert("B".to_string(), b);
    nodes.insert(
        "D".to_string(),
        NodeSpec {
            asn: 65104,
            x: 280.0,
            y: 300.0,
            policy: Policy::default(),
        },
    );
    let mut c = NodeSpec {
        asn: 65103,
        x: 500.0,
        y: 210.0,
        policy: Policy::default(),
    };
    c.policy.import.push(Rule {
        id: "reject-high-community".into(),
        description: "terminate-reject on quarantine community".into(),
        when: Match {
            community_any: vec!["65109:quarantine".into()],
            ..Default::default()
        },
        do_: Action::default(),
        on_match: OnMatch::Reject,
    });
    nodes.insert("C".to_string(), c);

    ScenarioInput {
        name: "med-community-rewrite".into(),
        description: "MED set via hit-continue; later rules and conditions see rewritten values; terminate-reject demo.".into(),
        nodes,
        sessions: vec![
            sess("A-B", "A", "B", SessionKind::EBgp, 1),
            sess("B-A", "B", "A", SessionKind::EBgp, 1),
            sess("A-D", "A", "D", SessionKind::EBgp, 1),
            sess("D-A", "D", "A", SessionKind::EBgp, 1),
            sess("B-C", "B", "C", SessionKind::EBgp, 1),
            sess("C-B", "C", "B", SessionKind::EBgp, 1),
            sess("D-C", "D", "C", SessionKind::EBgp, 1),
            sess("C-D", "C", "D", SessionKind::EBgp, 1),
        ],
        announcements: vec![Announcement {
            id: "ann-med".into(),
            node: "A".into(),
            prefix: "172.16.5.0/24".into(),
            local_pref: 100,
            med: Some(200),
            communities: vec!["65101:internal".into()],
        }],
        events: vec![],
        max_iterations: 100_000,
    }
}

/// AS_PATH loop evidence.
///
/// S (AS 65201) originates. X is ANOTHER border router in AS 65201. The route walks
/// S -> Y (AS 65204) -> X (eBGP session back into AS 65201). X's incoming AS_PATH is
/// [65204, 65201] which already contains its own AS: the import-side mandatory loop
/// check refuses it with explicit evidence. Direct S->X is deliberately absent so the
/// export-side guard on Y is what forwards the poison; the export guard is also shown
/// when Z tries to send the route back to peers already on the path.
pub fn as_path_loop() -> ScenarioInput {
    let mut nodes = BTreeMap::new();
    nodes.insert(
        "S".to_string(),
        NodeSpec {
            asn: 65201,
            x: 80.0,
            y: 200.0,
            policy: Policy::default(),
        },
    );
    nodes.insert(
        "Y".to_string(),
        NodeSpec {
            asn: 65204,
            x: 300.0,
            y: 200.0,
            policy: Policy::default(),
        },
    );
    nodes.insert(
        "Z".to_string(),
        NodeSpec {
            asn: 65201,
            x: 520.0,
            y: 300.0,
            policy: Policy::default(),
        },
    );
    nodes.insert(
        "X".to_string(),
        NodeSpec {
            asn: 65205,
            x: 520.0,
            y: 120.0,
            policy: Policy::default(),
        },
    );

    let mut z_policy = Policy::default();
    z_policy.import.push(Rule {
        id: "annotate".into(),
        description:
            "would tag accepted routes; the mandatory AS_PATH loop check runs first and refuses"
                .into(),
        when: Match::default(),
        do_: Action {
            add_community: Some("65201:checked".into()),
            ..Default::default()
        },
        on_match: OnMatch::Continue,
    });
    nodes.get_mut("Z").unwrap().policy = z_policy;
    let mut y_policy = Policy::default();
    y_policy.export.push(Rule {
        id: "prep-toward-x".into(),
        description: "extra own-AS prepend lengthens path to X".into(),
        when: Match {
            peer: Some("X".into()),
            ..Default::default()
        },
        do_: Action {
            as_path_prepend: Some(1),
            ..Default::default()
        },
        on_match: OnMatch::Continue,
    });
    nodes.get_mut("Y").unwrap().policy = y_policy;

    ScenarioInput {
        name: "as-path-loop".into(),
        description: "Import-side AS_PATH loop rejection (X re-enters AS 65201) plus export-side suppression.".into(),
        nodes,
        sessions: vec![
            sess("S-Y", "S", "Y", SessionKind::EBgp, 1),
            sess("Y-S", "Y", "S", SessionKind::EBgp, 1),
            sess("Y-X", "Y", "X", SessionKind::EBgp, 1),
            sess("X-Y", "X", "Y", SessionKind::EBgp, 1),
            sess("Y-Z", "Y", "Z", SessionKind::EBgp, 1),
            sess("Z-Y", "Z", "Y", SessionKind::EBgp, 1),
        ],
        announcements: vec![Announcement {
            id: "ann-loop".into(),
            node: "S".into(),
            prefix: "192.0.2.0/24".into(),
            local_pref: 100,
            med: Some(0),
            communities: vec![],
        }],
        events: vec![],
        max_iterations: 100_000,
    }
}

/// Two providers E and F advertise the SAME prefix with identical attributes to G;
/// final selection must be a stable, explainable tie-break independent of ordering.
pub fn equal_paths() -> ScenarioInput {
    // E and F are two eBGP speakers IN THE SAME upstream AS 65305, so at G both routes
    // carry an identical AS_PATH [65305], identical MED/local-pref/community and only
    // differ by ingress neighbor — exercising the final deterministic tie-break.
    let mut nodes = BTreeMap::new();
    nodes.insert(
        "E".to_string(),
        NodeSpec {
            asn: 65305,
            x: 120.0,
            y: 110.0,
            policy: Policy::default(),
        },
    );
    nodes.insert(
        "F".to_string(),
        NodeSpec {
            asn: 65305,
            x: 120.0,
            y: 310.0,
            policy: Policy::default(),
        },
    );
    nodes.insert(
        "G".to_string(),
        NodeSpec {
            asn: 65307,
            x: 380.0,
            y: 210.0,
            policy: Policy::default(),
        },
    );

    ScenarioInput {
        name: "equal-paths".into(),
        description: "Identical attributes from two eBGP peers; deterministic final tie-break."
            .into(),
        nodes,
        sessions: vec![
            sess("E-G", "E", "G", SessionKind::EBgp, 1),
            sess("G-E", "G", "E", SessionKind::EBgp, 1),
            sess("F-G", "F", "G", SessionKind::EBgp, 1),
            sess("G-F", "G", "F", SessionKind::EBgp, 1),
        ],
        announcements: vec![
            Announcement {
                id: "ann-e".into(),
                node: "E".into(),
                prefix: "203.0.113.0/24".into(),
                local_pref: 100,
                med: Some(10),
                communities: vec!["shared:peer".into()],
            },
            Announcement {
                id: "ann-f".into(),
                node: "F".into(),
                prefix: "203.0.113.0/24".into(),
                local_pref: 100,
                med: Some(10),
                communities: vec!["shared:peer".into()],
            },
        ],
        events: vec![],
        max_iterations: 100_000,
    }
}

/// BAD_GADGET / dispute-wheel oscillation.
///
/// Three customers A, B, C each have a direct eBGP session to provider P (AS 65000)
/// and a full eBGP mesh with each other. Every customer prefers routes learned from a
/// particular peer (lp=200) over its second peer (lp=90) and over its own direct
/// provider route (lp=50). This cyclic preference profile is the classic
/// Griffin–Wilkie–Rexford no-stable-solution gadget. The deterministic engine reaches a
/// recurring global state and reports `oscillation` with a state-signature proof
/// (rather than failing on an iteration cap).
///
/// The delay vector is part of the fingerprint: `A->B` is 3 ticks while the other
/// peer links are 1 tick.
pub fn dispute_wheel() -> ScenarioInput {
    let mut nodes = BTreeMap::new();
    nodes.insert(
        "P".to_string(),
        NodeSpec {
            asn: 65000,
            x: 400.0,
            y: 60.0,
            policy: Policy::default(),
        },
    );

    let mk_policy = |first: &str, second: &str| {
        let mut p = Policy::default();
        p.import.push(Rule {
            id: "prefer-first-peer".into(),
            description: format!("routes learned from {first} are most preferred"),
            when: Match {
                peer: Some(first.into()),
                ..Default::default()
            },
            do_: Action {
                set_local_pref: Some(200),
                ..Default::default()
            },
            on_match: OnMatch::Continue,
        });
        p.import.push(Rule {
            id: "prefer-second-peer".into(),
            description: format!("routes learned from {second} are second choice"),
            when: Match {
                peer: Some(second.into()),
                ..Default::default()
            },
            do_: Action {
                set_local_pref: Some(90),
                ..Default::default()
            },
            on_match: OnMatch::Continue,
        });
        p.import.push(Rule {
            id: "direct-provider".into(),
            description: "direct route to provider P is least preferred".into(),
            when: Match {
                peer: Some("P".into()),
                ..Default::default()
            },
            do_: Action {
                set_local_pref: Some(50),
                ..Default::default()
            },
            on_match: OnMatch::Continue,
        });
        p
    };

    nodes.insert(
        "A".to_string(),
        NodeSpec {
            asn: 65011,
            x: 120.0,
            y: 360.0,
            policy: mk_policy("B", "C"),
        },
    );
    nodes.insert(
        "B".to_string(),
        NodeSpec {
            asn: 65012,
            x: 400.0,
            y: 360.0,
            policy: mk_policy("C", "A"),
        },
    );
    nodes.insert(
        "C".to_string(),
        NodeSpec {
            asn: 65013,
            x: 680.0,
            y: 360.0,
            policy: mk_policy("A", "B"),
        },
    );

    ScenarioInput {
        name: "dispute-wheel".into(),
        description: "BAD_GADGET cyclic preferences: provable recurring-state oscillation, not a cap failure.".into(),
        nodes,
        sessions: vec![
            sess("P-A", "P", "A", SessionKind::EBgp, 1),
            sess("A-P", "A", "P", SessionKind::EBgp, 1),
            sess("P-B", "P", "B", SessionKind::EBgp, 1),
            sess("B-P", "B", "P", SessionKind::EBgp, 1),
            sess("P-C", "P", "C", SessionKind::EBgp, 1),
            sess("C-P", "C", "P", SessionKind::EBgp, 1),
            sess("A-B", "A", "B", SessionKind::EBgp, 3),
            sess("B-A", "B", "A", SessionKind::EBgp, 1),
            sess("B-C", "B", "C", SessionKind::EBgp, 1),
            sess("C-B", "C", "B", SessionKind::EBgp, 1),
            sess("C-A", "C", "A", SessionKind::EBgp, 1),
            sess("A-C", "A", "C", SessionKind::EBgp, 1),
        ],
        announcements: vec![Announcement {
            id: "ann-wheel".into(),
            node: "P".into(),
            prefix: "198.51.100.0/24".into(),
            local_pref: 100,
            med: Some(0),
            communities: vec![],
        }],
        events: vec![],
        max_iterations: 100_000,
    }
}

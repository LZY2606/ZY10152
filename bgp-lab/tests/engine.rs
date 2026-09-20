use bgp_lab::engine::{simulate, RunStatus};
use bgp_lab::fixtures::*;

#[test]
fn basic_reaches_stable_after_withdraw() {
    let r = simulate(&basic_preferences());
    assert_eq!(
        r.status,
        RunStatus::Stable,
        "{}",
        r.inconclusive_reason.unwrap_or_default()
    );
    // withdrawal event leaves no best route for the originated prefix anywhere
    let still: Vec<_> = r
        .best
        .iter()
        .filter(|b| b.prefix == "10.10.0.0/16")
        .collect();
    assert!(
        still.is_empty(),
        "prefix should be withdrawn everywhere, got {} entries",
        still.len()
    );
}

#[test]
fn deterministic_trace_fingerprint_replays_identically() {
    let a = simulate(&med_community_rewrite());
    let b = simulate(&med_community_rewrite());
    assert_eq!(a.trace_fingerprint, b.trace_fingerprint);
    assert_eq!(a.steps.len(), b.steps.len());
}

#[test]
fn loop_rejection_has_explicit_evidence() {
    let r = simulate(&as_path_loop());
    let ev: Vec<_> = r
        .steps
        .iter()
        .filter_map(|s| s.receive.as_ref())
        .filter(|rec| rec.loop_evidence.is_some() && !rec.accepted)
        .collect();
    assert!(
        !ev.is_empty(),
        "expected at least one import-side loop rejection with evidence"
    );
    let export_ev: Vec<_> = r
        .steps
        .iter()
        .flat_map(|s| s.exports.clone())
        .filter(|e| e.loop_evidence.is_some())
        .collect();
    // either import or export side must have explicit evidence in this poisoning setup
    assert!(ev.len() + export_ev.len() > 0);
}

#[test]
fn equal_paths_have_stable_winner_and_equal_peer() {
    let r = simulate(&equal_paths());
    assert_eq!(r.status, RunStatus::Stable);
    let g = r
        .best
        .iter()
        .find(|b| b.node == "G" && b.prefix == "203.0.113.0/24")
        .expect("G selected the prefix");
    let peer = g.equal_peer.as_deref();
    assert!(
        peer == Some("E") || peer == Some("F"),
        "expected equal-best peer E/F, got {peer:?}"
    );
    assert!(peer != Some("G"));
}

#[test]
fn dispute_wheel_has_verifiable_cycle_proof() {
    let r = simulate(&dispute_wheel());
    assert_eq!(r.status, RunStatus::Oscillation);
    let c = r.cycle.as_ref().expect("cycle proof must be present");
    assert!(c.recurred_at_step > c.first_seen_at_step);
    assert!(!c.state_signature.is_empty());
    assert!(c.involved_prefixes.contains(&"198.51.100.0/24".to_string()));
    // recurring-state proof, not a cap failure
    assert!(r.inconclusive_reason.is_none());
    assert!(r.messages_processed < dispute_wheel().max_iterations);
}

#[test]
fn iteration_cap_is_inconclusive_not_oscillation() {
    // Use the genuine oscillating gadget with a tiny cap: the cap must surface as
    // inconclusive rather than a false non-convergence claim.
    let mut sc = dispute_wheel();
    sc.max_iterations = 3;
    let r = simulate(&sc);
    assert_eq!(r.status, RunStatus::Inconclusive);
    assert!(r.cycle.is_none());
    assert!(r.inconclusive_reason.unwrap().contains("safety cap"));
}

#[test]
fn restart_clears_rib_and_reconverges_deterministically() {
    use bgp_lab::model::*;
    let mut sc = basic_preferences();
    // restart R2 before the manual withdrawal; result must be deterministic
    sc.events = vec![EventSpec::Restart {
        id: "restart-r2".into(),
        node: "R2".into(),
        tick: 10,
    }];
    let a = simulate(&sc);
    let b = simulate(&sc);
    assert_eq!(a.status, RunStatus::Stable);
    assert_eq!(a.trace_fingerprint, b.trace_fingerprint);
    let restart_steps: Vec<_> = a
        .steps
        .iter()
        .filter(|s| matches!(s.kind, bgp_lab::engine::StepKind::Restart))
        .collect();
    assert_eq!(restart_steps.len(), 1);
}

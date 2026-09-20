//! Deterministic best-path selection.
//!
//! Stage order (documented in README):
//! 1. highest LOCAL_PREF
//! 2. shortest AS_PATH
//! 3. lowest origin-type (origin < eBGP < iBGP)
//! 4. lowest MED — only compared when the neighboring AS (leftmost AS_PATH) is equal
//! 5. eBGP over iBGP
//! 6. lowest stable ingress neighbor id (router id)
//! 7. final lexicographic tie-break over (BGP attributes, ingress identity)
//!
//! Stages 6–7 can only separate routes that differ by ingress identity while their BGP
//! attributes are identical. Such routes are reported as `equal_peer`: the selection is
//! still unique and independent of hash-map / message-interleaving order, while the UI
//! can show a stable, explainable tie-break ("两个等价最优路径").

use crate::model::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub node: NodeId,
    pub ingress_session: Option<SessionId>,
    pub route: Route,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageReport {
    pub stage: usize,
    pub name: String,
    pub detail: String,
    pub retained: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionReport {
    pub winner: Option<String>,
    /// Another candidate with byte-identical BGP attributes to the winner, separated
    /// only by the stable ingress-identity tie-break.
    pub equal_peer: Option<String>,
    pub stages: Vec<StageReport>,
    pub tie_key_winner: Option<String>,
}

/// BGP-attribute equality key (does NOT include ingress identity).
fn attribute_key(c: &Candidate) -> String {
    let mut comms = c.route.communities.clone();
    comms.sort();
    format!(
        "{}|{}|{}|{}|{}|{}",
        c.route.prefix,
        c.route.local_pref,
        c.route
            .as_path
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(" "),
        c.route.med.unwrap_or(0),
        c.route.provenance.as_str(),
        comms.join(","),
    )
}

/// Final deterministic tie-break key; folds ingress identity.
fn candidate_key(c: &Candidate) -> String {
    format!(
        "{}|{}|{}",
        attribute_key(c),
        c.ingress_session
            .clone()
            .unwrap_or_else(|| format!("origin@{}", c.node)),
        c.node
    )
}

fn retained(candidates: &[&Candidate]) -> Vec<String> {
    candidates.iter().map(|c| c.node.clone()).collect()
}

fn reduce<'a, F>(
    stage_no: usize,
    name: &str,
    detail: &str,
    candidates: &[&'a Candidate],
    key: F,
    stages: &mut Vec<StageReport>,
) -> Vec<&'a Candidate>
where
    F: Fn(&Candidate) -> i64,
{
    let best = candidates.iter().map(|c| key(c)).min().unwrap();
    let kept: Vec<&Candidate> = candidates
        .iter()
        .copied()
        .filter(|c| key(c) == best)
        .collect();
    stages.push(StageReport {
        stage: stage_no,
        name: name.to_string(),
        detail: detail.to_string(),
        retained: retained(&kept),
    });
    kept
}

fn med_comparable(candidates: &[&Candidate]) -> bool {
    let first = candidates[0].route.neighbor_as();
    candidates.iter().all(|c| c.route.neighbor_as() == first)
}

pub fn select(candidates: &[Candidate]) -> SelectionReport {
    let mut stages: Vec<StageReport> = Vec::new();
    if candidates.is_empty() {
        return SelectionReport {
            winner: None,
            equal_peer: None,
            stages,
            tie_key_winner: None,
        };
    }

    let mut pool: Vec<&Candidate> = candidates.iter().collect();
    stages.push(StageReport {
        stage: 0,
        name: "candidates".into(),
        detail: format!("{} eligible route(s) in Adj-RIB-In", pool.len()),
        retained: retained(&pool),
    });

    pool = reduce(
        1,
        "local-pref",
        "highest LOCAL_PREF wins",
        &pool,
        |c| -c.route.local_pref,
        &mut stages,
    );
    if pool.len() == 1 {
        return finish(pool, stages);
    }
    pool = reduce(
        2,
        "as-path-length",
        "shortest AS_PATH wins",
        &pool,
        |c| c.route.as_path.len() as i64,
        &mut stages,
    );
    if pool.len() == 1 {
        return finish(pool, stages);
    }
    pool = reduce(
        3,
        "origin-type",
        "origin < eBGP < iBGP",
        &pool,
        |c| c.route.provenance.rank() as i64,
        &mut stages,
    );
    if pool.len() == 1 {
        return finish(pool, stages);
    }

    if med_comparable(&pool) {
        pool = reduce(
            4,
            "med",
            "same neighboring AS: lowest MED wins (missing MED = 0)",
            &pool,
            |c| c.route.med.unwrap_or(0),
            &mut stages,
        );
        if pool.len() == 1 {
            return finish(pool, stages);
        }
    } else {
        let r = retained(&pool);
        stages.push(StageReport {
            stage: 4,
            name: "med".into(),
            detail: "skipped: routes come from different neighboring ASes".into(),
            retained: r,
        });
    }

    pool = reduce(
        5,
        "ebgp-over-ibgp",
        "eBGP-learned preferred over iBGP-learned",
        &pool,
        |c| {
            if c.route.provenance == Provenance::EBgp {
                0
            } else {
                1
            }
        },
        &mut stages,
    );
    if pool.len() == 1 {
        return finish(pool, stages);
    }

    // Stages 6–7 compare ingress identity. Snapshot attribute equality first.
    let winner_attr_preview: String = {
        let mut sorted: Vec<&Candidate> = pool.to_vec();
        sorted.sort_by(|a, b| candidate_key(a).cmp(&candidate_key(b)));
        attribute_key(sorted[0])
    };
    let equal_peer_preview: Option<String> = pool
        .iter()
        .filter(|c| attribute_key(c) == winner_attr_preview)
        .map(|c| c.node.clone())
        .filter(|n| n != &pool_node_of_lowest_key(&pool))
        .min();

    pool = reduce(
        6,
        "router-id",
        "lowest ingress neighbor id wins",
        &pool,
        |c| {
            let mut h: i64 = 0;
            for b in c.node.bytes() {
                h = h.wrapping_mul(31).wrapping_add(b as i64);
            }
            h
        },
        &mut stages,
    );

    // Stage 7 always records the deterministic key even when unique, so tie evidence is
    // visible for attribute-equal routes that stage 6 already separated.
    let mut sorted: Vec<&Candidate> = pool.to_vec();
    sorted.sort_by(|a, b| candidate_key(a).cmp(&candidate_key(b)));
    let winner = sorted[0];
    stages.push(StageReport {
        stage: 7,
        name: "deterministic-tie-break".into(),
        detail: "stable lexicographic key over (BGP attributes, ingress session, neighbor id)"
            .into(),
        retained: vec![winner.node.clone()],
    });

    let equal_peer = equal_peer_preview;
    SelectionReport {
        winner: Some(winner.node.clone()),
        equal_peer,
        stages,
        tie_key_winner: Some(candidate_key(winner)),
    }
}

fn pool_node_of_lowest_key(pool: &[&Candidate]) -> String {
    pool.iter()
        .min_by(|a, b| candidate_key(a).cmp(&candidate_key(b)))
        .unwrap()
        .node
        .clone()
}

fn finish(pool: Vec<&Candidate>, stages: Vec<StageReport>) -> SelectionReport {
    // Single route left before ingress-identity stages: the remaining candidates were
    // already discarded on real attribute differences, so no equal peer.
    let winner = pool[0];
    SelectionReport {
        winner: Some(winner.node.clone()),
        equal_peer: None,
        stages,
        tie_key_winner: Some(candidate_key(winner)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(
        node: &str,
        sess: &str,
        lp: i64,
        path: Vec<u32>,
        med: Option<i64>,
        prov: Provenance,
    ) -> Candidate {
        Candidate {
            node: node.into(),
            ingress_session: Some(sess.into()),
            route: Route {
                prefix: "10/8".into(),
                as_path: path,
                local_pref: lp,
                med,
                communities: vec![],
                provenance: prov,
                ingress_session: Some(sess.into()),
                first_as: None,
            },
        }
    }

    #[test]
    fn local_pref_beats_as_path() {
        let cs = vec![
            cand("A", "s-a", 200, vec![1, 2, 3], None, Provenance::EBgp),
            cand("B", "s-b", 100, vec![9], None, Provenance::EBgp),
        ];
        assert_eq!(select(&cs).winner.as_deref(), Some("A"));
    }

    #[test]
    fn equal_attributes_report_peer_and_stable_winner() {
        let mk = || {
            vec![
                cand("Z", "s-z", 100, vec![7], Some(5), Provenance::EBgp),
                cand("A", "s-a", 100, vec![7], Some(5), Provenance::EBgp),
                cand("M", "s-m", 100, vec![7], Some(5), Provenance::EBgp),
            ]
        };
        let r1 = select(&mk());
        let mut rev = mk();
        rev.reverse();
        let r2 = select(&rev);
        assert_eq!(r1.winner, r2.winner);
        assert_eq!(r1.winner.as_deref(), Some("A"));
        assert_eq!(r1.equal_peer, r2.equal_peer);
        assert_eq!(r1.tie_key_winner, r2.tie_key_winner);
    }

    #[test]
    fn med_skipped_across_neighbor_as() {
        let cs = vec![
            cand("A", "s-a", 100, vec![100, 9], Some(999), Provenance::EBgp),
            cand("B", "s-b", 100, vec![200, 9], Some(1), Provenance::EBgp),
        ];
        assert!(select(&cs)
            .stages
            .iter()
            .any(|s| s.name == "med" && s.detail.starts_with("skipped")));
    }
}

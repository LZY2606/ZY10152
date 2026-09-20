//! Deterministic virtual BGP event engine.
//!
//! Properties required by the spec and verified in tests:
//! * the virtual event queue is ordered by a fully deterministic comparison key
//!   `(tick, seq, kind, session, prefix)` — replaying the same scenario fingerprint
//!   always yields the same convergence trace fingerprint;
//! * AS_PATH loops and iBGP split-horizon violations are refused with explicit
//!   evidence (they never silently disappear);
//! * non-convergence is only announced when a recurring global-state signature proves
//!   a cycle; hitting the iteration cap produces an `inconclusive` verdict instead;
//! * rule rewrites are applied before later conditions are tested (see `policy.rs`).

use crate::bestpath::{select, Candidate, SelectionReport};
use crate::fingerprint::{fingerprint_hex, ENGINE_VERSION};
use crate::model::*;
use crate::policy::{evaluate as eval_policy, Verdict as PVerdict};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

/// What one dequeued message did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepKind {
    OriginInject,
    OriginWithdraw,
    Receive,
    Withdraw,
    Restart,
    Refresh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopEvidence {
    pub kind: String,
    pub detail: String,
    pub session: String,
    pub as_path: Vec<u32>,
    pub own_as: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionEvidence {
    pub session: String,
    pub reason: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveRecord {
    pub session: String,
    pub from: NodeId,
    pub prefix: Prefix,
    pub accepted: bool,
    pub reason: String,
    pub policy: crate::policy::PolicyVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loop_evidence: Option<LoopEvidence>,
    pub route_after: Option<Route>,
    pub best_changed: bool,
    pub best: Option<Route>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    pub session: String,
    pub to: NodeId,
    pub prefix: Prefix,
    pub published: bool,
    pub reason: String,
    pub policy: Option<crate::policy::PolicyVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loop_evidence: Option<LoopEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suppressed: Vec<SuppressionEvidence>,
    pub route: Option<Route>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub seq: usize,
    pub tick: u64,
    pub kind: StepKind,
    pub node: NodeId,
    pub prefix: Option<Prefix>,
    pub summary: String,
    pub receive: Option<ReceiveRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exports: Vec<ExportRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<SelectionReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvertisedRoute {
    pub session: SessionId,
    pub from: NodeId,
    pub to: NodeId,
    pub prefix: Prefix,
    pub route: Route,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BestEntry {
    pub node: NodeId,
    pub prefix: Prefix,
    pub route: Route,
    pub equal_peer: Option<NodeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node: NodeId,
    pub best: BTreeMap<Prefix, Route>,
    pub equal_peer: BTreeMap<Prefix, NodeId>,
    /// External export decisions, keyed by (session, prefix).
    pub advertised: BTreeMap<String, Route>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    Stable,
    Oscillation,
    Inconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleProof {
    /// Global-state signature that recurred.
    pub state_signature: String,
    pub first_seen_at_step: usize,
    pub recurred_at_step: usize,
    pub first_seen_tick: u64,
    pub recurred_tick: u64,
    pub involved_prefixes: Vec<Prefix>,
    pub involved_nodes: Vec<NodeId>,
    pub cycle_steps: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub status: RunStatus,
    pub steps: Vec<Step>,
    pub states: Vec<NodeState>,
    pub best: Vec<BestEntry>,
    pub advertised: Vec<AdvertisedRoute>,
    pub trace_fingerprint: String,
    pub final_state_signature: String,
    pub messages_processed: usize,
    pub ticks: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycle: Option<CycleProof>,
    pub inconclusive_reason: Option<String>,
}

// ---------- internal events ----------

#[derive(Debug, Clone, PartialEq, Eq)]
enum MsgKind {
    OriginInject,
    OriginWithdraw,
    Receive,
    Withdraw,
    Restart,
}

#[derive(Debug, Clone)]
struct Scheduled {
    tick: u64,
    seq: u64,
    kind: MsgKind,
    node: NodeId,
    session: Option<SessionId>,
    prefix: Option<Prefix>,
    route: Option<Route>,
    #[allow(dead_code)]
    announcement: Option<String>,
}

impl Scheduled {
    fn order_key_kind(&self) -> u8 {
        match self.kind {
            MsgKind::Restart => 0,
            MsgKind::OriginWithdraw => 1,
            MsgKind::OriginInject => 2,
            MsgKind::Withdraw => 3,
            MsgKind::Receive => 4,
        }
    }
}

/// The heap is a max-heap, so `Ord` is implemented in reverse priority order.
impl Ord for Scheduled {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .tick
            .cmp(&self.tick)
            .then_with(|| other.seq.cmp(&self.seq))
            .then_with(|| other.order_key_kind().cmp(&self.order_key_kind()))
            .then_with(|| other.session.cmp(&self.session))
            .then_with(|| other.prefix.cmp(&self.prefix))
            .then_with(|| other.node.cmp(&self.node))
    }
}
impl PartialOrd for Scheduled {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Scheduled {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Scheduled {}

// ---------- runtime node data ----------

struct RtNode {
    spec: NodeSpec,
    /// Best locally originated routes still active: prefix -> route.
    origins: BTreeMap<Prefix, Route>,
    /// Adj-RIB-In: (ingress session, prefix) -> accepted route.
    rib_in: BTreeMap<(SessionId, Prefix), Route>,
    best: BTreeMap<Prefix, Route>,
    equal_peer: BTreeMap<Prefix, NodeId>,
    /// Last advertisement sent per (egress session, prefix); None = withdrawn.
    advertised: BTreeMap<(SessionId, Prefix), Option<Route>>,
    up: bool,
}

pub struct Engine<'a> {
    input: &'a ScenarioInput,
    nodes: BTreeMap<NodeId, RtNode>,
    /// session id -> session spec.
    sessions: BTreeMap<SessionId, Session>,
    /// outgoing session ids per node (deterministic order = input order).
    out_sessions: BTreeMap<NodeId, Vec<SessionId>>,
    in_sessions: BTreeMap<NodeId, Vec<SessionId>>,
    queue: std::collections::BinaryHeap<Scheduled>,
    seq_ctr: u64,
    steps: Vec<Step>,
    messages: usize,
    /// Latest message sequence number per (session,prefix) for supersede dedup.
    latest_msg: HashMap<(SessionId, Prefix), u64>,
    /// Last best-path selection report per (node, prefix), used to attach evidence.
    last_selection: HashMap<(NodeId, Prefix), SelectionReport>,
}

impl<'a> Engine<'a> {
    pub fn new(input: &'a ScenarioInput) -> Self {
        let mut nodes = BTreeMap::new();
        for (id, spec) in input.nodes.iter() {
            nodes.insert(
                id.clone(),
                RtNode {
                    spec: spec.clone(),
                    origins: BTreeMap::new(),
                    rib_in: BTreeMap::new(),
                    best: BTreeMap::new(),
                    equal_peer: BTreeMap::new(),
                    advertised: BTreeMap::new(),
                    up: true,
                },
            );
        }
        let mut sessions = BTreeMap::new();
        let mut out_sessions: BTreeMap<NodeId, Vec<SessionId>> = BTreeMap::new();
        let mut in_sessions: BTreeMap<NodeId, Vec<SessionId>> = BTreeMap::new();
        for s in &input.sessions {
            sessions.insert(s.id.clone(), s.clone());
            out_sessions
                .entry(s.local.clone())
                .or_default()
                .push(s.id.clone());
            in_sessions
                .entry(s.remote.clone())
                .or_default()
                .push(s.id.clone());
        }
        Engine {
            input,
            nodes,
            sessions,
            out_sessions,
            in_sessions,
            queue: std::collections::BinaryHeap::new(),
            seq_ctr: 0,
            steps: Vec::new(),
            messages: 0,
            latest_msg: HashMap::new(),
            last_selection: HashMap::new(),
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq_ctr += 1;
        self.seq_ctr
    }

    fn schedule(&mut self, mut msg: Scheduled) {
        // Supersede older pending messages on the same (session, prefix): a fresher
        // UPDATE replaces a queued one, a queued WITHDRAW replaces an older UPDATE.
        if let (Some(sess), Some(pfx)) = (&msg.session, &msg.prefix) {
            let key = (sess.clone(), pfx.clone());
            let seq = self.next_seq();
            msg.seq = seq;
            self.latest_msg.insert(key, seq);
        } else {
            msg.seq = self.next_seq();
        }
        self.queue.push(msg);
    }

    /// Run to convergence, oscillation proof, or safety cap.
    pub fn run(mut self) -> RunResult {
        // Initial origin injections at tick 0.
        for ann in &self.input.announcements {
            let route = Route {
                prefix: ann.prefix.clone(),
                as_path: vec![],
                local_pref: ann.local_pref,
                med: ann.med,
                communities: ann.communities.clone(),
                provenance: Provenance::Origin,
                ingress_session: None,
                first_as: Some(self.nodes[&ann.node].spec.asn),
            };
            self.schedule(Scheduled {
                tick: 0,
                seq: 0,
                kind: MsgKind::OriginInject,
                node: ann.node.clone(),
                session: None,
                prefix: Some(ann.prefix.clone()),
                route: Some(route),
                announcement: Some(ann.id.clone()),
            });
        }

        // Exogenous events.
        for ev in &self.input.events {
            match ev {
                EventSpec::Withdraw {
                    id,
                    announcement,
                    tick,
                } => {
                    if let Some(ann) = self
                        .input
                        .announcements
                        .iter()
                        .find(|a| &a.id == announcement)
                    {
                        self.schedule(Scheduled {
                            tick: *tick,
                            seq: 0,
                            kind: MsgKind::OriginWithdraw,
                            node: ann.node.clone(),
                            session: None,
                            prefix: Some(ann.prefix.clone()),
                            route: None,
                            announcement: Some(id.clone()),
                        });
                    }
                }
                EventSpec::Restart { id: _, node, tick } => {
                    self.schedule(Scheduled {
                        tick: *tick,
                        seq: 0,
                        kind: MsgKind::Restart,
                        node: node.clone(),
                        session: None,
                        prefix: None,
                        route: None,
                        announcement: None,
                    });
                }
            }
        }

        let mut seen: HashMap<String, (usize, u64)> = HashMap::new();
        let mut cycle_steps: Vec<usize> = Vec::new();

        while let Some(msg) = self.queue.pop() {
            // Stale-message filter: if a fresher message for the same (session,prefix)
            // exists in the queue, drop this superseded one entirely (no state change).
            if let (Some(sess), Some(pfx)) = (&msg.session, &msg.prefix) {
                if let Some(latest) = self.latest_msg.get(&(sess.clone(), pfx.clone())) {
                    if *latest != msg.seq {
                        continue;
                    }
                }
            }

            if self.messages >= self.input.max_iterations {
                let cap = self.input.max_iterations;
                return self.finish(
                    RunStatus::Inconclusive,
                    None,
                    Some(format!(
                        "safety cap of {} messages reached without stability or a recurring-state proof; \
                         this is NOT declared non-convergence",
                        cap
                    )),
                );
            }
            self.messages += 1;
            self.dispatch(msg);

            // Global-state signature at the post-message boundary.
            let sig = self.state_signature();
            cycle_steps.push(self.messages);
            if let Some((prev_step, prev_tick)) = seen.get(&sig).copied() {
                let cur_step = self.messages;
                let cur_tick = self.steps.last().map(|s| s.tick).unwrap_or(0);
                if self.queue.is_empty() {
                    break; // deterministic idling = stable
                }
                let proof = self.cycle_proof(sig.clone(), prev_step, cur_step, prev_tick, cur_tick);
                return self.finish(RunStatus::Oscillation, Some(proof), None);
            }
            seen.insert(
                sig,
                (
                    self.messages,
                    self.steps.last().map(|s| s.tick).unwrap_or(0),
                ),
            );

            if self.queue.is_empty() {
                break;
            }
        }

        self.finish(RunStatus::Stable, None, None)
    }

    fn dispatch(&mut self, msg: Scheduled) {
        match msg.kind {
            MsgKind::OriginInject => self.handle_origin_inject(msg),
            MsgKind::OriginWithdraw => self.handle_origin_withdraw(msg),
            MsgKind::Restart => self.handle_restart(msg),
            MsgKind::Receive => self.handle_receive(msg),
            MsgKind::Withdraw => self.handle_withdraw(msg),
        }
    }

    fn record(
        &mut self,
        mut step: Step,
        exports: Vec<ExportRecord>,
        selection: Option<SelectionReport>,
    ) {
        step.exports = exports;
        step.selection = selection;
        self.steps.push(step);
    }

    fn handle_origin_inject(&mut self, msg: Scheduled) {
        let node = msg.node.clone();
        let prefix = msg.prefix.clone().unwrap();
        let route = msg.route.clone().unwrap();
        self.nodes
            .get_mut(&node)
            .unwrap()
            .origins
            .insert(prefix.clone(), route.clone());

        let (best_changed, best, selection) = self.reevaluate(&node, &prefix);
        let exports = self.export_best(&node, &prefix);
        self.record(
            Step {
                seq: self.messages,
                tick: msg.tick,
                kind: StepKind::OriginInject,
                node: node.clone(),
                prefix: Some(prefix.clone()),
                summary: format!("{node} originates {prefix}"),
                receive: None,
                exports: vec![],
                selection: None,
            },
            exports,
            selection,
        );
        let _ = best_changed;
        let _ = best;
    }

    fn handle_origin_withdraw(&mut self, msg: Scheduled) {
        let node = msg.node.clone();
        let prefix = msg.prefix.clone().unwrap();
        self.nodes.get_mut(&node).unwrap().origins.remove(&prefix);

        let (changed, best, selection) = self.reevaluate(&node, &prefix);
        let exports = self.export_best(&node, &prefix);
        self.record(
            Step {
                seq: self.messages,
                tick: msg.tick,
                kind: StepKind::OriginWithdraw,
                node: node.clone(),
                prefix: Some(prefix.clone()),
                summary: format!("{node} withdraws originated {prefix}"),
                receive: None,
                exports: vec![],
                selection: None,
            },
            exports,
            selection,
        );
        let _ = changed;
        let _ = best;
    }

    fn handle_restart(&mut self, msg: Scheduled) {
        let node = msg.node.clone();
        {
            let rt = self.nodes.get_mut(&node).unwrap();
            rt.up = false;
            // Restart clears all learned state and previous advertisements.
            rt.rib_in.clear();
            rt.advertised.clear();
            rt.best.clear();
            rt.equal_peer.clear();
        }
        // Bring the node back up and re-inject local origins.
        let origins: Vec<Route> = self.nodes[&node].origins.values().cloned().collect();
        let prefixes: Vec<Prefix> = origins.iter().map(|r| r.prefix.clone()).collect();
        let rt = self.nodes.get_mut(&node).unwrap();
        rt.up = true;
        for route in origins {
            rt.best.insert(route.prefix.clone(), route.clone());
        }

        let mut all_exports = Vec::new();
        let mut last_selection = None;
        for prefix in &prefixes {
            let (_, _, sel) = self.reevaluate(&node, prefix);
            if sel.is_some() {
                last_selection = sel;
            }
            all_exports.extend(self.export_best(&node, prefix));
        }

        // Refresh requests to all iBGP peers (and eBGP peers re-send active routes on
        // their own next send event). We schedule explicit refreshes from neighbors.
        if let Some(ins) = self.in_sessions.get(&node).cloned() {
            for sid in ins {
                let sess = self.sessions[&sid].clone();
                // neighbor re-advertises its best for all prefixes it currently holds
                let bests: Vec<(Prefix, Route)> = self.nodes[&sess.local]
                    .best
                    .iter()
                    .map(|(p, r)| (p.clone(), r.clone()))
                    .collect();
                for (pfx, route) in bests {
                    self.schedule_send(&sess, pfx, Some(route));
                }
            }
        }

        self.record(
            Step {
                seq: self.messages,
                tick: msg.tick,
                kind: StepKind::Restart,
                node: node.clone(),
                prefix: None,
                summary: format!("{node} restarts: Adj-RIB-In cleared, local routes re-originated"),
                receive: None,
                exports: vec![],
                selection: None,
            },
            all_exports,
            last_selection,
        );
    }

    fn handle_receive(&mut self, msg: Scheduled) {
        let sid = msg.session.clone().unwrap();
        let sess = self.sessions[&sid].clone();
        let node = sess.remote.clone();
        let from = sess.local.clone();
        let prefix = msg.prefix.clone().unwrap();
        let incoming = msg.route.clone().unwrap();
        let tick = msg.tick;

        let own_as = self.nodes[&node].spec.asn;

        // --- mandatory AS_PATH loop check (before import policy) ---
        let loop_ev = if sess.kind == SessionKind::EBgp
            && incoming.as_path.iter().any(|a| *a == own_as)
        {
            Some(LoopEvidence {
                kind: "as-path-loop".into(),
                detail: format!(
                    "incoming AS_PATH {:?} already contains local AS {own_as}: refused per RFC 4271 §9.1.2",
                    incoming.as_path
                ),
                session: sid.clone(),
                as_path: incoming.as_path.clone(),
                own_as,
            })
        } else {
            None
        };

        // --- iBGP split-horizon: route learned from iBGP peer cannot be re-advertised
        // to another iBGP peer. At import it is accepted (it may be selected), but the
        // rule is enforced at export; here we annotate provenance. ---

        let mut route = incoming.clone();
        route.provenance = match sess.kind {
            SessionKind::EBgp => Provenance::EBgp,
            SessionKind::IBgp => Provenance::IBgp,
        };
        route.ingress_session = Some(sid.clone());
        if route.first_as.is_none() {
            route.first_as = route.as_path.first().copied();
        }

        let peer = from.clone();
        let rules = self.nodes[&node].spec.policy.import.clone();
        let (verdict, mutated, _prepend) = eval_policy(&rules, &route, &peer, Decision::Accept);

        let policy_accepted = verdict.decision == PVerdict::Accept;
        let loop_rejected = loop_ev.is_some();
        let accepted = !loop_rejected && policy_accepted;

        let mut best_changed = false;
        let mut best = self.nodes[&node].best.get(&prefix).cloned();

        if loop_rejected {
            // RFC 4271: an UPDATE failing the AS_PATH loop check is dropped, AND the
            // NLRI it carries represents the peer's current advertisement — the old
            // entry from this session no longer exists, so it must be removed (the
            // UPDATE replaces it with nothing usable). Evidence is recorded below.
            let removed = self
                .nodes
                .get_mut(&node)
                .unwrap()
                .rib_in
                .remove(&(sid.clone(), prefix.clone()));
            if removed.is_some() {
                let (changed, b, _) = self.reevaluate(&node, &prefix);
                best_changed = changed;
                best = b;
            }
        } else if accepted {
            // An accepted UPDATE replaces the previous entry from this session.
            self.nodes
                .get_mut(&node)
                .unwrap()
                .rib_in
                .insert((sid.clone(), prefix.clone()), mutated.clone());
            let (changed, b, _) = self.reevaluate(&node, &prefix);
            best_changed = changed;
            best = b;
        } else {
            // Policy-based rejection: the previous Adj-RIB-In entry is LEFT UNCHANGED
            // (an administrative refusal, not a protocol replacement). Evidence is kept.
        }

        let reason = if loop_ev.is_some() {
            "as-path-loop".to_string()
        } else {
            verdict.reason.clone()
        };

        let record = ReceiveRecord {
            session: sid.clone(),
            from: from.clone(),
            prefix: prefix.clone(),
            accepted,
            reason,
            policy: verdict,
            loop_evidence: loop_ev.clone(),
            route_after: if accepted { Some(mutated) } else { None },
            best_changed,
            best: best.clone(),
        };

        let exports = if best_changed {
            self.export_best(&node, &prefix)
        } else {
            Vec::new()
        };

        let selection = if accepted {
            self.last_selection
                .get(&(node.clone(), prefix.clone()))
                .cloned()
        } else {
            None
        };

        self.record(
            Step {
                seq: self.messages,
                tick,
                kind: StepKind::Receive,
                node: node.clone(),
                prefix: Some(prefix.clone()),
                summary: format!(
                    "{} receives {} from {} => {}",
                    node,
                    prefix,
                    from,
                    if accepted { "accepted" } else { "rejected" }
                ),
                receive: Some(record),
                exports: vec![],
                selection: None,
            },
            exports,
            selection,
        );
    }

    fn handle_withdraw(&mut self, msg: Scheduled) {
        let sid = msg.session.clone().unwrap();
        let sess = self.sessions[&sid].clone();
        let node = sess.remote.clone();
        let from = sess.local.clone();
        let prefix = msg.prefix.clone().unwrap();
        let tick = msg.tick;

        // Explicit WITHDRAW removes the previous Adj-RIB-In entry even if present.
        let removed = self
            .nodes
            .get_mut(&node)
            .unwrap()
            .rib_in
            .remove(&(sid.clone(), prefix.clone()));
        let (best_changed, best, selection) = self.reevaluate(&node, &prefix);
        let exports = if best_changed {
            self.export_best(&node, &prefix)
        } else {
            Vec::new()
        };

        self.record(
            Step {
                seq: self.messages,
                tick,
                kind: StepKind::Withdraw,
                node: node.clone(),
                prefix: Some(prefix.clone()),
                summary: format!(
                    "{} withdraws {} from {} (entry {}): best_changed={}",
                    node,
                    prefix,
                    from,
                    if removed.is_some() {
                        "present"
                    } else {
                        "absent"
                    },
                    best_changed
                ),
                receive: None,
                exports: vec![],
                selection: None,
            },
            exports,
            selection,
        );
        let _ = best;
    }

    /// Recompute best path for one prefix at one node.
    fn reevaluate(
        &mut self,
        node: &NodeId,
        prefix: &Prefix,
    ) -> (bool, Option<Route>, Option<SelectionReport>) {
        let mut candidates: Vec<Candidate> = Vec::new();

        if let Some(r) = self.nodes[node].origins.get(prefix) {
            candidates.push(Candidate {
                node: node.clone(),
                ingress_session: None,
                route: r.clone(),
            });
        }
        let entries: Vec<(SessionId, Route)> = self.nodes[node]
            .rib_in
            .iter()
            .filter(|((_, p), _)| p == prefix)
            .map(|(k, v)| (k.0.clone(), v.clone()))
            .collect();
        let own_as = self.nodes[node].spec.asn;
        for (sid, mut route) in entries {
            // RIB-level hard constraint independent of policy: an eBGP-learned route
            // whose AS_PATH contains the local AS is never eligible (RFC 4271 §9.1.2).
            // This mirrors a router re-checking RIB entries when the best path changes;
            // the original import refusal already left evidence. Routes learned over
            // iBGP may legitimately contain the local AS (within-AS propagation).
            let ingress_kind = self.sessions[&sid].kind;
            if ingress_kind == SessionKind::EBgp && route.as_path.iter().any(|a| *a == own_as) {
                continue;
            }
            let peer = self.sessions[&sid].local.clone();
            route
                .first_as
                .get_or_insert_with(|| route.as_path.first().copied().unwrap_or(own_as));
            candidates.push(Candidate {
                node: peer,
                ingress_session: Some(sid),
                route,
            });
        }

        let report = select(&candidates);
        let new_best = report.winner.as_ref().and_then(|winner| {
            candidates
                .iter()
                .find(|c| &c.node == winner)
                .map(|c| c.route.clone())
        });
        let equal_peer = report.equal_peer.clone();

        let old = self.nodes[node].best.get(prefix).cloned();
        let changed = old != new_best;
        let rt = self.nodes.get_mut(node).unwrap();
        match &new_best {
            Some(r) => {
                rt.best.insert(prefix.clone(), r.clone());
            }
            None => {
                rt.best.remove(prefix);
            }
        }
        rt.equal_peer.remove(prefix);
        if let Some(ep) = equal_peer {
            rt.equal_peer.insert(prefix.clone(), ep);
        }
        self.last_selection
            .insert((node.clone(), prefix.clone()), report.clone());
        (changed, new_best, Some(report))
    }

    fn schedule_send(&mut self, sess: &Session, prefix: Prefix, route: Option<Route>) {
        let kind = if route.is_some() {
            MsgKind::Receive
        } else {
            MsgKind::Withdraw
        };
        self.schedule(Scheduled {
            tick: self.current_tick() + sess.delay.max(1),
            seq: 0,
            kind,
            node: sess.remote.clone(),
            session: Some(sess.id.clone()),
            prefix: Some(prefix),
            route,
            announcement: None,
        });
    }

    fn current_tick(&self) -> u64 {
        self.steps.last().map(|s| s.tick).unwrap_or(0)
    }

    /// Evaluate export policy + loop/split-horizon checks for every outgoing session
    /// and schedule resulting UPDATEs / WITHDRAWs.
    fn export_best(&mut self, node: &NodeId, prefix: &Prefix) -> Vec<ExportRecord> {
        let best: Option<Route> = self.nodes[node].best.get(prefix).cloned();
        let own_as = self.nodes[node].spec.asn;
        let sids = self.out_sessions.get(node).cloned().unwrap_or_default();
        let rules = self.nodes[node].spec.policy.export.clone();
        let cur_tick = self.current_tick();
        let _ = cur_tick;
        let mut records = Vec::new();

        for sid in sids {
            let sess = self.sessions[&sid].clone();
            let remote_as = self.nodes[&sess.remote].spec.asn;

            let best = best.clone();
            let (published, reason, policy, loop_ev, out_route) = match &best {
                None => (false, "no-best-path".to_string(), None, None, None),
                Some(b) => {
                    // iBGP split-horizon (evidence before policy is even consulted).
                    if sess.kind == SessionKind::IBgp && b.provenance == Provenance::IBgp {
                        (false, "ibgp-split-horizon".to_string(), None, None, None)
                    } else {
                        let (verdict, mutated, prepend_n) =
                            eval_policy(&rules, b, &sess.remote, Decision::Accept);
                        if verdict.decision != PVerdict::Accept {
                            (
                                false,
                                format!("export-rejected: {}", verdict.reason),
                                Some(verdict),
                                None,
                                None,
                            )
                        } else {
                            let mut outbound = mutated;
                            // Originated routes carry an EMPTY AS_PATH internally; the
                            // advertising AS is prepended on eBGP export per RFC 4271.
                            // Policy prepends add further copies of the local AS.
                            if sess.kind == SessionKind::EBgp {
                                for _ in 0..(1 + prepend_n) {
                                    outbound.as_path.insert(0, own_as);
                                }
                            } else if prepend_n > 0 {
                                for _ in 0..prepend_n {
                                    outbound.as_path.insert(0, own_as);
                                }
                            }
                            let _ = own_as;
                            // eBGP loop prevention is enforced by the RECEIVER at import
                            // (RFC 4271 §9.1.2). We therefore send the UPDATE even when
                            // the remote AS is already on the path, so the refusal shows
                            // up as explicit import-side loop evidence at that neighbor.
                            let _ = remote_as;
                            (
                                true,
                                "exported".to_string(),
                                Some(verdict),
                                None,
                                Some(outbound),
                            )
                        }
                    }
                }
            };

            let key = (sid.clone(), prefix.clone());
            let previous = self
                .nodes
                .get(node)
                .unwrap()
                .advertised
                .get(&key)
                .cloned()
                .flatten();

            let mut suppressed = Vec::new();
            let sendable = out_route.clone();
            match (published, &sendable) {
                (true, Some(route)) => {
                    if previous.as_ref() == Some(route) {
                        suppressed.push(SuppressionEvidence {
                            session: sid.clone(),
                            reason: "unchanged".into(),
                            detail: "advertised route identical to last UPDATE: no message sent"
                                .into(),
                        });
                    } else {
                        self.schedule_send(&sess, prefix.clone(), Some(route.clone()));
                        self.nodes
                            .get_mut(node)
                            .unwrap()
                            .advertised
                            .insert(key.clone(), Some(route.clone()));
                    }
                }
                (true, None) => unreachable!("published routes always carry an outbound route"),
                (false, _) => {
                    if previous.is_some() {
                        self.schedule_send(&sess, prefix.clone(), None);
                        suppressed.push(SuppressionEvidence {
                            session: sid.clone(),
                            reason: "withdraw-scheduled".into(),
                            detail: format!("previous UPDATE withdrawn ({reason})"),
                        });
                    } else if best.is_some() {
                        suppressed.push(SuppressionEvidence {
                            session: sid.clone(),
                            reason: reason.clone(),
                            detail: "route never advertised on this session; no UPDATE emitted"
                                .into(),
                        });
                    }
                    self.nodes
                        .get_mut(node)
                        .unwrap()
                        .advertised
                        .insert(key.clone(), None);
                }
            }

            records.push(ExportRecord {
                session: sid,
                to: sess.remote.clone(),
                prefix: prefix.clone(),
                published,
                reason,
                policy,
                loop_evidence: loop_ev,
                suppressed,
                route: out_route,
            });
        }

        records
    }

    fn canon_route(r: &Route) -> String {
        let mut r = r.clone();
        r.communities.sort();
        serde_json::to_string(&r).unwrap_or_default()
    }

    /// Global state signature used for cycle detection. It folds:
    /// * every node's up flag, best routes, equal-best peers and Adj-RIB-In;
    /// * every node's last advertisement marker per (session, prefix);
    /// * the pending queue in a SEQUENCE-NUMBER-INDEPENDENT canonical form (tick offsets
    ///   relative to the earliest queued event), so an identical routing state with an
    ///   identical relative schedule recurs at a later absolute tick and proves a cycle.
    fn state_signature(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (id, rt) in &self.nodes {
            let mut chunk = format!("node={id};up={}", rt.up);
            for (pfx, route) in &rt.best {
                chunk.push_str(&format!("|best:{pfx}={}", Self::canon_route(route)));
            }
            for (pfx, peer) in &rt.equal_peer {
                chunk.push_str(&format!("|eq:{pfx}={peer}"));
            }
            let mut rib: Vec<String> = rt
                .rib_in
                .iter()
                .map(|((s, p), r)| format!("{s}/{p}={}", Self::canon_route(r)))
                .collect();
            rib.sort();
            for e in rib {
                chunk.push_str(&format!("|in:{e}"));
            }
            let mut adv: Vec<String> = rt
                .advertised
                .iter()
                .map(|((s, p), r)| format!("{s}/{p}={}", if r.is_some() { "adv" } else { "wd" }))
                .collect();
            adv.sort();
            for e in adv {
                chunk.push_str(&format!("|out:{e}"));
            }
            parts.push(chunk);
        }

        if !self.queue.is_empty() {
            let base_tick = self.queue.iter().map(|m| m.tick).min().unwrap_or(0);
            let mut q: Vec<String> = self
                .queue
                .iter()
                .map(|m| {
                    format!(
                        "{}:{}:{}:{}:{}:{}",
                        m.tick.saturating_sub(base_tick),
                        m.order_key_kind(),
                        m.node,
                        m.session.clone().unwrap_or_default(),
                        m.prefix.clone().unwrap_or_default(),
                        m.route.as_ref().map(Self::canon_route).unwrap_or_default()
                    )
                })
                .collect();
            q.sort();
            parts.push("queue=".to_string() + &q.join(";"));
        }

        fingerprint_hex(&parts)
    }

    fn cycle_proof(
        &self,
        sig: String,
        prev_step: usize,
        cur_step: usize,
        prev_tick: u64,
        cur_tick: u64,
    ) -> CycleProof {
        let mut prefixes: Vec<Prefix> = Vec::new();
        let mut nodes: Vec<NodeId> = Vec::new();
        let mut idxs: Vec<usize> = Vec::new();
        for st in &self.steps {
            if st.seq > prev_step && st.seq <= cur_step {
                idxs.push(st.seq);
                nodes.push(st.node.clone());
                if let Some(p) = &st.prefix {
                    prefixes.push(p.clone());
                }
            }
        }
        prefixes.sort();
        prefixes.dedup();
        nodes.sort();
        nodes.dedup();
        CycleProof {
            state_signature: sig,
            first_seen_at_step: prev_step,
            recurred_at_step: cur_step,
            first_seen_tick: prev_tick,
            recurred_tick: cur_tick,
            involved_prefixes: prefixes,
            involved_nodes: nodes,
            cycle_steps: idxs,
        }
    }

    fn finish(
        self,
        status: RunStatus,
        cycle: Option<CycleProof>,
        inconclusive_reason: Option<String>,
    ) -> RunResult {
        let mut states = Vec::new();
        let mut best = Vec::new();
        let mut advertised = Vec::new();

        for (id, rt) in &self.nodes {
            let mut adv_map: BTreeMap<String, Route> = BTreeMap::new();
            for ((sid, pfx), marker) in &rt.advertised {
                if let Some(route) = marker {
                    adv_map.insert(format!("{sid}|{pfx}"), route.clone());
                    let sess = &self.sessions[sid];
                    advertised.push(AdvertisedRoute {
                        session: sid.clone(),
                        from: id.clone(),
                        to: sess.remote.clone(),
                        prefix: pfx.clone(),
                        route: route.clone(),
                    });
                }
            }
            states.push(NodeState {
                node: id.clone(),
                best: rt.best.clone(),
                equal_peer: rt.equal_peer.clone(),
                advertised: adv_map,
            });
            for (pfx, route) in &rt.best {
                best.push(BestEntry {
                    node: id.clone(),
                    prefix: pfx.clone(),
                    route: route.clone(),
                    equal_peer: rt.equal_peer.get(pfx).cloned(),
                });
            }
        }

        let ticks = self.steps.last().map(|s| s.tick).unwrap_or(0);
        let final_sig = self.state_signature();

        let fp_payload = serde_json::json!({
            "engine_version": ENGINE_VERSION,
            "status": status,
            "messages_processed": self.messages,
            "steps": self.steps,
            "final_state": final_sig,
        });
        let trace_fingerprint = fingerprint_hex(&fp_payload);

        RunResult {
            status,
            steps: self.steps,
            states,
            best,
            advertised,
            trace_fingerprint,
            final_state_signature: final_sig,
            messages_processed: self.messages,
            ticks,
            cycle,
            inconclusive_reason,
        }
    }
}

/// Convenience entry point.
pub fn simulate(input: &ScenarioInput) -> RunResult {
    Engine::new(input).run()
}

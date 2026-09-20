//! Domain model: topology, policies, announcements and runtime routes.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type NodeId = String;
pub type Prefix = String;
pub type SessionId = String;

/// Ordered list of AS numbers, nearest-AS first (BGP AS_PATH convention).
pub type AsPath = Vec<u32>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    EBgp,
    IBgp,
}

impl SessionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionKind::EBgp => "ebgp",
            SessionKind::IBgp => "ibgp",
        }
    }
}

/// A directed BGP session between two nodes. Attributes sent on `local -> remote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    pub local: NodeId,
    pub remote: NodeId,
    pub kind: SessionKind,
    /// Propagation delay in virtual ticks (deterministic scheduler units).
    #[serde(default = "default_delay")]
    pub delay: u64,
}

fn default_delay() -> u64 {
    1
}

/// Where a route first came from at a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    Origin,
    EBgp,
    IBgp,
}

impl Provenance {
    pub fn rank(&self) -> u8 {
        // locally originated beats eBGP beats iBGP (standard tie-break stage).
        match self {
            Provenance::Origin => 0,
            Provenance::EBgp => 1,
            Provenance::IBgp => 2,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Provenance::Origin => "origin",
            Provenance::EBgp => "ebgp",
            Provenance::IBgp => "ibgp",
        }
    }
}

/// A routed prefix candidate with its BGP attributes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub prefix: Prefix,
    pub as_path: AsPath,
    #[serde(default = "default_local_pref")]
    pub local_pref: i64,
    #[serde(default)]
    pub med: Option<i64>,
    #[serde(default)]
    pub communities: Vec<String>,
    pub provenance: Provenance,
    /// Session this route entered on (stable id; used for split-horizon and tie-break).
    #[serde(default)]
    pub ingress_session: Option<SessionId>,
    /// For originated routes: logical "neighbor AS" used for MED grouping. Own AS for
    /// locally originated routes (RFC 4271 MED comparison is moot for one origin).
    #[serde(default)]
    pub first_as: Option<u32>,
}

fn default_local_pref() -> i64 {
    100
}

impl Route {
    pub fn origin(prefix: Prefix, own_as: u32) -> Route {
        Route {
            prefix,
            as_path: vec![],
            local_pref: default_local_pref(),
            med: Some(0),
            communities: vec![],
            provenance: Provenance::Origin,
            ingress_session: None,
            first_as: Some(own_as),
        }
    }

    pub fn neighbor_as(&self) -> Option<u32> {
        // The AS that advertised the route = leftmost AS_PATH entry; for originated
        // routes we fall back to the stored first_as.
        self.as_path.first().copied().or(self.first_as)
    }
}

/// Comparison operator for match conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cmp {
    Eq,
    Ne,
    In,
    NotIn,
    Matches,
    Gte,
    Lte,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    #[serde(default)]
    pub peer: Option<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_cmp: Option<Cmp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_path_len: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_path_len_cmp: Option<Cmp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub as_path_contains: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_pref: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_pref_cmp: Option<Cmp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub med: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub med_cmp: Option<Cmp>,
    /// Community presence: `in` means "any of", `not-in` means "none of".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub community_any: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community_any_cmp: Option<Cmp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Accept,
    Reject,
}

/// What happens after a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnMatch {
    /// No rule matched (default policy), or matched but evaluation continues.
    Continue,
    /// Matched and policy evaluation stops with accept.
    Accept,
    /// Matched and policy evaluation stops with reject.
    Reject,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_local_pref: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_med: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add_community: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove_communities: Vec<String>,
    /// Number of extra local ASes to prepend (export) — prepend of the advertising
    /// node's own AS beyond the standard eBGP prepend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_path_prepend: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub when: Match,
    #[serde(default)]
    pub do_: Action,
    /// continue | accept | reject
    #[serde(default = "default_on_match")]
    pub on_match: OnMatch,
}

fn default_on_match() -> OnMatch {
    OnMatch::Continue
}

/// Named import/export policy attached to a node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub import: Vec<Rule>,
    #[serde(default)]
    pub export: Vec<Rule>,
}

/// Initial prefix injection (stable announcement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    pub id: String,
    pub node: NodeId,
    pub prefix: Prefix,
    #[serde(default = "default_local_pref")]
    pub local_pref: i64,
    #[serde(default = "default_med_zero")]
    pub med: Option<i64>,
    #[serde(default)]
    pub communities: Vec<String>,
}

fn default_med_zero() -> Option<i64> {
    Some(0)
}

/// A virtual event: withdrawal of a previously announced prefix or a neighbor restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum EventSpec {
    Withdraw {
        id: String,
        announcement: String,
        tick: u64,
    },
    Restart {
        id: String,
        node: NodeId,
        tick: u64,
    },
}

impl EventSpec {
    pub fn tick(&self) -> u64 {
        match self {
            EventSpec::Withdraw { tick, .. } | EventSpec::Restart { tick, .. } => *tick,
        }
    }
    pub fn id(&self) -> &str {
        match self {
            EventSpec::Withdraw { id, .. } | EventSpec::Restart { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub nodes: BTreeMap<NodeId, NodeSpec>,
    pub sessions: Vec<Session>,
    #[serde(default)]
    pub announcements: Vec<Announcement>,
    #[serde(default)]
    pub events: Vec<EventSpec>,
    /// Safety cap on processed virtual messages; exceeding it yields an `inconclusive`
    /// verdict, never a claimed non-convergence.
    #[serde(default = "default_max_iterations")]
    pub max_iterations: usize,
}

fn default_max_iterations() -> usize {
    100_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSpec {
    pub asn: u32,
    #[serde(default)]
    pub x: f64,
    #[serde(default)]
    pub y: f64,
    #[serde(default)]
    pub policy: Policy,
}

/// Runtime edit payload used by previews/commits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EditSet {
    /// Replace a rule (matched by node + direction + rule id), or insert if `upsert`.
    #[serde(default)]
    pub rules: Vec<RuleEdit>,
    #[serde(default)]
    pub removed_rule_ids: Vec<RuleRef>,
    #[serde(default)]
    pub withdraw: Vec<String>,
    #[serde(default)]
    pub restart: Vec<NodeId>,
    /// Restart tick relative to the base scenario timeline end.
    #[serde(default)]
    pub restart_tick: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    pub node: NodeId,
    pub direction: Direction,
    pub rule: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Import,
    Export,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::Import => "import",
            Direction::Export => "export",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEdit {
    pub node: NodeId,
    pub direction: Direction,
    pub rule: Rule,
    #[serde(default)]
    pub upsert: bool,
}

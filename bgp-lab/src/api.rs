//! HTTP JSON API + embedded static browser UI.

use crate::engine::{simulate, RunResult};
use crate::fingerprint::{canonical_string, fingerprint_hex};
use crate::model::*;
use crate::scenario::{branch, concurrent_diff, EditPreview};
use crate::store::Store;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tiny_http::{Header, Method, Request, Response, Server};

pub struct App {
    pub store: Store,
}

#[derive(Serialize)]
struct ScenarioSummary {
    id: String,
    name: String,
    parent_id: Option<String>,
    input_fingerprint: String,
    created_at: String,
}

#[derive(Serialize)]
struct ComputeResponse {
    scenario_id: String,
    reused: bool,
    trace_fingerprint: String,
    result: RunResult,
}

/// Impact analysis: nodes/prefixes/publication differences between two runs.
#[derive(Debug, Clone, Serialize)]
pub struct Impact {
    pub affected_nodes: Vec<NodeId>,
    pub affected_prefixes: Vec<Prefix>,
    pub best_path_diffs: Vec<PathDiff>,
    pub publication_diffs: Vec<PublicationDiff>,
    /// When the FINAL state matches but the convergence trajectory differs
    /// (restart/reconvergence), the differing intermediate node/prefix pairs are
    /// still surfaced so the user sees the blast radius before committing.
    pub intermediate_diffs: Vec<PathDiff>,
    pub trace_changed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathDiff {
    pub node: NodeId,
    pub prefix: Prefix,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicationDiff {
    pub session: SessionId,
    pub from: NodeId,
    pub to: NodeId,
    pub prefix: Prefix,
    pub change: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

fn path_label(r: Option<&crate::model::Route>) -> Option<String> {
    r.map(|r| {
        format!(
            "[lp={}, med={}, path={}, comm={}]",
            r.local_pref,
            r.med.unwrap_or(0),
            r.as_path
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            r.communities.join(",")
        )
    })
}

/// Per (node, prefix) count of convergence events the node participated in. A
/// restart re-processes the prefix even when the final best route is identical.
fn intermediate_transitions(r: &RunResult) -> std::collections::BTreeMap<(NodeId, Prefix), usize> {
    let mut out: std::collections::BTreeMap<(NodeId, Prefix), usize> =
        std::collections::BTreeMap::new();
    for step in &r.steps {
        if let Some(pfx) = &step.prefix {
            // A receive/withdraw/origin event directly concerns (node, prefix).
            *out.entry((step.node.clone(), pfx.clone())).or_insert(0) += 1;
        }
        if matches!(step.kind, crate::engine::StepKind::Restart) {
            // Restart events carry no single prefix; attribute to every prefix the node
            // re-originates/re-learns in subsequent steps.
            let pfx_set: std::collections::BTreeSet<Prefix> = r
                .best
                .iter()
                .filter(|b| b.node == step.node)
                .map(|b| b.prefix.clone())
                .collect();
            for pfx in pfx_set {
                *out.entry((step.node.clone(), pfx)).or_insert(0) += 1;
            }
        }
    }
    out
}

pub fn impact(before: &RunResult, after: &RunResult) -> Impact {
    let mut best_before: BTreeMap<(NodeId, Prefix), crate::model::Route> = BTreeMap::new();
    let mut best_after = best_before.clone();
    for b in &before.best {
        best_before.insert((b.node.clone(), b.prefix.clone()), b.route.clone());
    }
    for b in &after.best {
        best_after.insert((b.node.clone(), b.prefix.clone()), b.route.clone());
    }
    let mut keys: std::collections::BTreeSet<(NodeId, Prefix)> =
        best_before.keys().cloned().collect();
    keys.extend(best_after.keys().cloned());

    let mut nodes = Vec::new();
    let mut prefixes = Vec::new();
    let mut path_diffs = Vec::new();
    for k in &keys {
        let b = best_before.get(k);
        let a = best_after.get(k);
        if b == a {
            continue;
        }
        path_diffs.push(PathDiff {
            node: k.0.clone(),
            prefix: k.1.clone(),
            before: path_label(b),
            after: path_label(a),
        });
        if !nodes.contains(&k.0) {
            nodes.push(k.0.clone());
        }
        if !prefixes.contains(&k.1) {
            prefixes.push(k.1.clone());
        }
    }

    let mut adv_before: BTreeMap<(SessionId, Prefix), crate::engine::AdvertisedRoute> =
        BTreeMap::new();
    let mut adv_after = adv_before.clone();
    for a in &before.advertised {
        adv_before.insert((a.session.clone(), a.prefix.clone()), a.clone());
    }
    for a in &after.advertised {
        adv_after.insert((a.session.clone(), a.prefix.clone()), a.clone());
    }
    let mut akeys: std::collections::BTreeSet<(SessionId, Prefix)> =
        adv_before.keys().cloned().collect();
    akeys.extend(adv_after.keys().cloned());
    let mut pub_diffs = Vec::new();
    for k in akeys {
        let b = adv_before.get(&k);
        let a = adv_after.get(&k);
        let same = b.map(|x| &x.route) == a.map(|x| &x.route);
        if same {
            continue;
        }
        let (change, from, to) = match (b, a) {
            (Some(_), Some(ar)) => ("modified", ar.from.clone(), ar.to.clone()),
            (None, Some(ar)) => ("new", ar.from.clone(), ar.to.clone()),
            (Some(br), None) => ("withdrawn", br.from.clone(), br.to.clone()),
            (None, None) => unreachable!(),
        };
        if !nodes.contains(&from) {
            nodes.push(from.clone());
        }
        if !prefixes.contains(&k.1) {
            prefixes.push(k.1.clone());
        }
        pub_diffs.push(PublicationDiff {
            session: k.0.clone(),
            from,
            to,
            prefix: k.1.clone(),
            change: change.into(),
            before: path_label(b.map(|x| &x.route)),
            after: path_label(a.map(|x| &x.route)),
        });
    }

    // Intermediate convergence participation: nodes/prefixes present in the branch
    // trajectory but with a different number/kind of processing steps.
    let before_trans = intermediate_transitions(before);
    let after_trans = intermediate_transitions(after);
    let mut intermediate_diffs = Vec::new();
    let keys: std::collections::BTreeSet<(NodeId, Prefix)> = before_trans
        .keys()
        .chain(after_trans.keys())
        .cloned()
        .collect();
    for (n, p) in keys {
        let bc = *before_trans.get(&(n.clone(), p.clone())).unwrap_or(&0);
        let ac = *after_trans.get(&(n.clone(), p.clone())).unwrap_or(&0);
        if bc != ac {
            intermediate_diffs.push(PathDiff {
                node: n.clone(),
                prefix: p.clone(),
                before: Some(format!("{bc} convergence step(s)")),
                after: Some(format!("{ac} convergence step(s)")),
            });
            if !nodes.contains(&n) {
                nodes.push(n);
            }
            if !prefixes.contains(&p) {
                prefixes.push(p);
            }
        }
    }

    let trace_changed = before.trace_fingerprint != after.trace_fingerprint;
    Impact {
        affected_nodes: nodes,
        affected_prefixes: prefixes,
        best_path_diffs: path_diffs,
        publication_diffs: pub_diffs,
        intermediate_diffs,
        trace_changed,
    }
}

impl App {
    pub fn new(store_path: &str) -> std::io::Result<App> {
        let store = Store::open(store_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(App { store })
    }

    pub fn seed_fixtures(&self) -> std::io::Result<()> {
        use crate::fixtures::*;
        for scenario in [
            basic_preferences(),
            med_community_rewrite(),
            as_path_loop(),
            equal_paths(),
            crate::fixtures::dispute_wheel(),
        ] {
            let json = canonical_string(&scenario);
            let fp = fingerprint_hex(&scenario);
            let id = &fp[..16];
            if self.store.get_scenario(id).map_err(e500)?.is_none() {
                self.store
                    .upsert_scenario(id, &scenario.name, None, &scenario, &json, &fp)
                    .map_err(e500)?;
                let result = simulate(&scenario);
                self.store.save_run(id, &result).map_err(e500)?;
            }
        }
        Ok(())
    }

    fn compute(&self, id: &str, input: &ScenarioInput) -> Result<ComputeResponse, String> {
        let fp = fingerprint_hex(input);
        // Deduplication by input fingerprint: identical inputs reuse the recorded trace
        // fingerprint instead of recomputing a divergent result.
        if let Some((_, trace_fp)) = self
            .store
            .lookup_computation(&fp)
            .map_err(|e| e.to_string())?
        {
            if let Some(row) = self.store.latest_run(id).map_err(|e| e.to_string())? {
                let result: RunResult =
                    serde_json::from_str(&row.result_json).map_err(|e| e.to_string())?;
                return Ok(ComputeResponse {
                    scenario_id: id.to_string(),
                    reused: true,
                    trace_fingerprint: trace_fp,
                    result,
                });
            }
        }
        let result = simulate(input);
        self.store
            .save_run(id, &result)
            .map_err(|e| e.to_string())?;
        Ok(ComputeResponse {
            scenario_id: id.to_string(),
            reused: false,
            trace_fingerprint: result.trace_fingerprint.clone(),
            result,
        })
    }
}

fn e500<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

#[derive(Deserialize)]
struct PreviewReq {
    edits: EditSet,
    #[serde(default)]
    branch_name: Option<String>,
    #[serde(default)]
    save_draft: Option<String>,
}

#[derive(Deserialize)]
struct CommitReq {
    edits: EditSet,
    branch_name: String,
}

#[derive(Deserialize)]
struct DraftsDiffReq {
    left_scenario: String,
    right_scenario: String,
}

fn json_response<T: Serialize>(status: u16, body: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let data = serde_json::to_vec(body).unwrap();
    let mut resp = Response::from_data(data).with_status_code(status);
    let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    resp.add_header(h);
    resp
}

fn json_error(status: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(status, &serde_json::json!({ "error": msg }))
}

fn read_body(req: &mut Request) -> Result<String, String> {
    let mut body = String::new();
    req.as_reader()
        .read_to_string(&mut body)
        .map_err(|e| e.to_string())?;
    Ok(body)
}

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");

impl App {
    pub fn serve(&self, listen: &str) -> std::io::Result<()> {
        let server = Server::http(listen).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("bind {listen}: {e}"))
        })?;
        eprintln!("bgp-lab listening on http://{listen}");
        for request in server.incoming_requests() {
            self.route(request);
        }
        Ok(())
    }

    fn route(&self, mut req: Request) {
        let method = req.method().clone();
        let raw_url = req.url().to_string();
        let (path, query) = raw_url.split_once('?').unwrap_or((&raw_url, ""));
        let _ = query;

        let resp: Response<std::io::Cursor<Vec<u8>>> = match (&method, path) {
            (Method::Get, "/") | (Method::Get, "/index.html") => {
                let mut r = Response::from_string(INDEX_HTML);
                let h = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                    .unwrap();
                r.add_header(h);
                r
            }
            (Method::Get, "/app.js") => {
                let mut r = Response::from_string(APP_JS);
                let h = Header::from_bytes(
                    &b"application/javascript"[..],
                    &b"text/javascript; charset=utf-8"[..],
                )
                .unwrap();
                r.add_header(h);
                r
            }
            (Method::Get, "/api/scenarios") => self.list_scenarios(),
            (Method::Post, "/api/scenarios") => self.create_scenario(&mut req),
            (Method::Get, p) if p.starts_with("/api/scenarios/") => {
                let id = p.trim_start_matches("/api/scenarios/");
                let (id, tail) = id.split_once('/').unwrap_or((id, ""));
                match tail {
                    "" | "result" => self.get_scenario(id),
                    _ => json_error(404, "not found"),
                }
            }
            (Method::Post, p) if p.starts_with("/api/scenarios/") && p.ends_with("/preview") => {
                let id = p
                    .trim_start_matches("/api/scenarios/")
                    .trim_end_matches("/preview");
                self.preview(id, &mut req)
            }
            (Method::Post, p) if p.starts_with("/api/scenarios/") && p.ends_with("/commit") => {
                let id = p
                    .trim_start_matches("/api/scenarios/")
                    .trim_end_matches("/commit");
                self.commit(id, &mut req)
            }
            (Method::Post, "/api/drafts/diff") => self.drafts_diff(&mut req),
            (Method::Get, "/api/health") => json_response(200, &serde_json::json!({"ok": true})),
            _ => json_error(404, "not found"),
        };

        let _ = req.respond(resp);
    }

    fn list_scenarios(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        match self.store.list_scenarios() {
            Ok(rows) => {
                let summaries: Vec<ScenarioSummary> = rows
                    .into_iter()
                    .map(|r| ScenarioSummary {
                        id: r.id,
                        name: r.name,
                        parent_id: r.parent_id,
                        input_fingerprint: r.input_fingerprint,
                        created_at: r.created_at,
                    })
                    .collect();
                json_response(200, &serde_json::json!({ "scenarios": summaries }))
            }
            Err(e) => json_error(500, &e.to_string()),
        }
    }

    fn create_scenario(&self, req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return json_error(400, &e),
        };
        let input: ScenarioInput = match serde_json::from_str(&body) {
            Ok(i) => i,
            Err(e) => return json_error(400, &format!("invalid scenario: {e}")),
        };
        if let Err(e) = validate(&input) {
            return json_error(400, &e);
        }
        let fp = fingerprint_hex(&input);
        let id = fp[..16].to_string();
        let json = canonical_string(&input);
        if let Err(e) = self
            .store
            .upsert_scenario(&id, &input.name, None, &input, &json, &fp)
        {
            return json_error(500, &e.to_string());
        }
        match self.compute(&id, &input) {
            Ok(r) => json_response(201, &r),
            Err(e) => json_error(500, &e),
        }
    }

    fn get_scenario(&self, id: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let row = match self.store.get_scenario(id) {
            Ok(Some(r)) => r,
            Ok(None) => return json_error(404, "scenario not found"),
            Err(e) => return json_error(500, &e.to_string()),
        };
        let input: ScenarioInput = serde_json::from_str(&row.input_json).unwrap();
        let result = self.store.latest_run(id).ok().flatten();
        let result_json =
            result.map(|r| serde_json::from_str::<serde_json::Value>(&r.result_json).unwrap());
        json_response(
            200,
            &serde_json::json!({
                "id": row.id,
                "name": row.name,
                "parent_id": row.parent_id,
                "input_fingerprint": row.input_fingerprint,
                "input": input,
                "result": result_json,
            }),
        )
    }

    fn preview(&self, id: &str, req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
        let row = match self.store.get_scenario(id) {
            Ok(Some(r)) => r,
            Ok(None) => return json_error(404, "scenario not found"),
            Err(e) => return json_error(500, &e.to_string()),
        };
        let base: ScenarioInput = serde_json::from_str(&row.input_json).unwrap();
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return json_error(400, &e),
        };
        let preq: PreviewReq = match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(e) => return json_error(400, &format!("invalid preview request: {e}")),
        };

        let preview: EditPreview = match branch(
            &base,
            &preq.edits,
            preq.branch_name
                .unwrap_or_else(|| format!("{}-branch", base.name)),
        ) {
            Ok(p) => p,
            Err(e) => return json_error(400, &e),
        };
        if let Err(e) = validate(&preview.scenario) {
            return json_error(400, &e);
        }

        let base_result = match self.store.latest_run(id) {
            Ok(Some(r)) => serde_json::from_str::<RunResult>(&r.result_json).unwrap(),
            _ => simulate(&base),
        };
        let branch_result = simulate(&preview.scenario);
        let imp = impact(&base_result, &branch_result);

        if let Some(label) = &preq.save_draft {
            let rev = self
                .store
                .latest_run(id)
                .ok()
                .flatten()
                .map(|r| r.id)
                .unwrap_or(0);
            let draft_id = format!("{id}:{}", label.replace(' ', "-"));
            if let Err(e) = self
                .store
                .save_draft(&draft_id, id, label, &preq.edits, rev)
            {
                return json_error(500, &e.to_string());
            }
        }

        json_response(
            200,
            &serde_json::json!({
                "diffs": preview.diffs,
                "affected_nodes": imp.affected_nodes,
                "affected_prefixes": imp.affected_prefixes,
                "best_path_diffs": imp.best_path_diffs,
                "publication_diffs": imp.publication_diffs,
                "intermediate_diffs": imp.intermediate_diffs,
                "trace_changed": imp.trace_changed,
                "scenario": preview.scenario,
                "result": branch_result,
            }),
        )
    }

    fn commit(&self, id: &str, req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
        let row = match self.store.get_scenario(id) {
            Ok(Some(r)) => r,
            Ok(None) => return json_error(404, "scenario not found"),
            Err(e) => return json_error(500, &e.to_string()),
        };
        let base: ScenarioInput = serde_json::from_str(&row.input_json).unwrap();
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return json_error(400, &e),
        };
        let creq: CommitReq = match serde_json::from_str(&body) {
            Ok(c) => c,
            Err(e) => return json_error(400, &format!("invalid commit request: {e}")),
        };

        let preview = match branch(&base, &creq.edits, creq.branch_name) {
            Ok(p) => p,
            Err(e) => return json_error(400, &e),
        };
        if let Err(e) = validate(&preview.scenario) {
            return json_error(400, &e);
        }
        // Only stable results or results with a verifiable non-convergence proof are
        // allowed to "publish" as a committed branch.
        use crate::engine::RunStatus;
        let result = simulate(&preview.scenario);
        match result.status {
            RunStatus::Stable | RunStatus::Oscillation => {}
            RunStatus::Inconclusive => {
                return json_error(
                    409,
                    "refusing to publish branch: simulation is inconclusive (cap hit, no proof)",
                )
            }
        }

        let fp = fingerprint_hex(&preview.scenario);
        let new_id = fp[..16].to_string();
        let json = canonical_string(&preview.scenario);
        if let Err(e) = self.store.upsert_scenario(
            &new_id,
            &preview.scenario.name,
            Some(id),
            &preview.scenario,
            &json,
            &fp,
        ) {
            return json_error(500, &e.to_string());
        }
        match self.compute(&new_id, &preview.scenario) {
            Ok(r) => json_response(
                201,
                &serde_json::json!({
                    "scenario_id": new_id,
                    "parent_id": id,
                    "diffs": preview.diffs,
                    "compute": r,
                }),
            ),
            Err(e) => json_error(500, &e),
        }
    }

    fn drafts_diff(&self, req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
        let body = match read_body(req) {
            Ok(b) => b,
            Err(e) => return json_error(400, &e),
        };
        let dreq: DraftsDiffReq = match serde_json::from_str(&body) {
            Ok(d) => d,
            Err(e) => return json_error(400, &format!("invalid request: {e}")),
        };
        let load = |id: &str| -> Result<ScenarioInput, String> {
            self.store
                .get_scenario(id)
                .map_err(|e| e.to_string())?
                .map(|r| serde_json::from_str(&r.input_json).unwrap())
                .ok_or_else(|| format!("scenario {id} not found"))
        };
        // If both scenarios share a parent, diff against the common parent; else use
        // the left scenario as the implicit base.
        let lrow = self.store.get_scenario(&dreq.left_scenario).ok().flatten();
        let rrow = self.store.get_scenario(&dreq.right_scenario).ok().flatten();
        let base_id = match (&lrow, &rrow) {
            (Some(l), Some(r)) if l.parent_id == r.parent_id => l.parent_id.clone(),
            _ => Some(dreq.left_scenario.clone()),
        };
        let base = match base_id.and_then(|b| self.store.get_scenario(&b).ok().flatten()) {
            Some(row) => serde_json::from_str(&row.input_json).unwrap(),
            None => return json_error(404, "base scenario not found"),
        };
        match (load(&dreq.left_scenario), load(&dreq.right_scenario)) {
            (Ok(left), Ok(right)) => {
                let diffs = concurrent_diff(&base, &left, &right);
                json_response(200, &serde_json::json!({ "diffs": diffs }))
            }
            (Err(e), _) | (_, Err(e)) => json_error(404, &e),
        }
    }
}

fn validate(input: &ScenarioInput) -> Result<(), String> {
    for s in &input.sessions {
        if !input.nodes.contains_key(&s.local) {
            return Err(format!(
                "session {} references unknown local node {}",
                s.id, s.local
            ));
        }
        if !input.nodes.contains_key(&s.remote) {
            return Err(format!(
                "session {} references unknown remote node {}",
                s.id, s.remote
            ));
        }
        if s.delay == 0 {
            return Err(format!("session {} delay must be >= 1 tick", s.id));
        }
    }
    for a in &input.announcements {
        if !input.nodes.contains_key(&a.node) {
            return Err(format!("announcement {} on unknown node {}", a.id, a.node));
        }
    }
    for ev in &input.events {
        match ev {
            EventSpec::Withdraw { announcement, .. } => {
                if !input.announcements.iter().any(|a| &a.id == announcement) {
                    return Err(format!(
                        "event withdraws unknown announcement {announcement}"
                    ));
                }
            }
            EventSpec::Restart { node, .. } => {
                if !input.nodes.contains_key(node) {
                    return Err(format!("restart on unknown node {node}"));
                }
            }
        }
    }
    Ok(())
}

// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network DiffApply inverse synthesis (DR-46).
//!
//! For tools whose [`crate::executors::network::restore_method`]
//! returns `DiffApply`, the inverse is a sequence of CLI invocations
//! that re-introduce removed entries and remove added ones. This
//! module parses `ip -j ...` JSON dumps (Linux) and computes those
//! invocations from a pre/after pair.
//!
//! ## Why JSON, not the human-formatted output
//!
//! `ip route show` (no `-j`) produces a free-form line for each
//! route; parsing it correctly requires reproducing iproute2's
//! formatter and tracking minor version drift. The capture tier
//! already uses `ip -j` so the planner consumes its output verbatim.
//! Both `before_state` and `after_state` in
//! [`crate::events::CaptureEventKind::NetworkOp`] are the JSON bytes
//! emitted by `ip -j`.
//!
//! ## Scope
//!
//! Fully implemented: `IpRoute`, `IpAddr`, `IpLink` (Linux iproute2
//! JSON), `Networksetup` (M06.1, DNS-only first ship), `Route` and
//! `Ifconfig` (M06.3, macOS via `netstat -nrf inet` and `ifconfig
//! -a` text snapshots — see DR-44).

use crate::events::NetworkTool;
use serde::Deserialize;

/// Top-level dispatch: pick the right per-tool synthesiser and return
/// its inverse invocations. Returns `Vec::new()` for tools we don't
/// implement or for malformed JSON — the caller (planner) treats
/// empty as "no inverse available" and emits a warning so the user
/// can rollback by hand.
pub fn synthesise_diff_apply_inverse(
    tool: NetworkTool,
    before_state: &[u8],
    after_state: &[u8],
) -> Vec<Vec<String>> {
    match tool {
        NetworkTool::IpRoute => synthesise_ip_route(before_state, after_state),
        NetworkTool::IpAddr => synthesise_ip_addr(before_state, after_state),
        NetworkTool::IpLink => synthesise_ip_link(before_state, after_state),
        NetworkTool::Networksetup => synthesise_networksetup(before_state, after_state),
        NetworkTool::Route => synthesise_route(before_state, after_state),
        NetworkTool::Ifconfig => synthesise_ifconfig(before_state, after_state),
        // FullReload / DiffApplyWithReset tools don't reach this
        // function; the planner gates by restore_method first.
        NetworkTool::Iptables
        | NetworkTool::Ip6tables
        | NetworkTool::Nft
        | NetworkTool::Ufw
        | NetworkTool::Pfctl => Vec::new(),
    }
}

// =================================================================
// ip route
// =================================================================

/// One row from `ip -j route show`. Only the fields we use for
/// identity + emission are deserialised; the rest of the per-route
/// JSON is intentionally ignored.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct IpRouteRow {
    dst: String,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    dev: Option<String>,
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    metric: Option<u32>,
    #[serde(default)]
    prefsrc: Option<String>,
}

impl IpRouteRow {
    /// Identity key for diff: a route is the same when (dst, dev,
    /// table, metric) match. Kernel routes with different metrics
    /// can coexist for the same destination; ignoring the metric in
    /// identity would conflate them.
    fn identity(&self) -> (String, String, String, u32) {
        (
            self.dst.clone(),
            self.dev.clone().unwrap_or_default(),
            self.table.clone().unwrap_or_else(|| "main".to_string()),
            self.metric.unwrap_or(0),
        )
    }

    fn to_argv(&self) -> Vec<String> {
        let mut v = vec!["ip".to_string(), "route".to_string()];
        // Action placeholder — caller substitutes "add"/"del".
        v.push("PLACEHOLDER".to_string());
        v.push(self.dst.clone());
        if let Some(g) = &self.gateway {
            v.push("via".to_string());
            v.push(g.clone());
        }
        if let Some(d) = &self.dev {
            v.push("dev".to_string());
            v.push(d.clone());
        }
        if let Some(s) = &self.scope {
            v.push("scope".to_string());
            v.push(s.clone());
        }
        if let Some(p) = &self.protocol {
            v.push("proto".to_string());
            v.push(p.clone());
        }
        if let Some(m) = self.metric {
            v.push("metric".to_string());
            v.push(m.to_string());
        }
        if let Some(ps) = &self.prefsrc {
            v.push("src".to_string());
            v.push(ps.clone());
        }
        if let Some(t) = &self.table
            && t != "main"
        {
            v.push("table".to_string());
            v.push(t.clone());
        }
        v
    }
}

fn synthesise_ip_route(before: &[u8], after: &[u8]) -> Vec<Vec<String>> {
    let Ok(pre): Result<Vec<IpRouteRow>, _> = serde_json::from_slice(before) else {
        return Vec::new();
    };
    let Ok(post): Result<Vec<IpRouteRow>, _> = serde_json::from_slice(after) else {
        return Vec::new();
    };
    let mut inverse = Vec::new();
    // Routes added by the command (in post but not pre) → del.
    for r in &post {
        if !pre.iter().any(|p| p.identity() == r.identity()) {
            let mut argv = r.to_argv();
            argv[2] = "del".to_string();
            inverse.push(argv);
        }
    }
    // Routes removed by the command (in pre but not post) → add back.
    for r in &pre {
        if !post.iter().any(|p| p.identity() == r.identity()) {
            let mut argv = r.to_argv();
            argv[2] = "add".to_string();
            inverse.push(argv);
        }
    }
    inverse
}

// =================================================================
// ip addr
// =================================================================

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct IpAddrIface {
    ifname: String,
    #[serde(default)]
    addr_info: Vec<IpAddrInfo>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct IpAddrInfo {
    family: String,
    local: String,
    prefixlen: u8,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    broadcast: Option<String>,
}

impl IpAddrInfo {
    /// Identity: (family, local, prefixlen). Address-level dedup.
    fn identity(&self) -> (String, String, u8) {
        (self.family.clone(), self.local.clone(), self.prefixlen)
    }
}

fn synthesise_ip_addr(before: &[u8], after: &[u8]) -> Vec<Vec<String>> {
    let Ok(pre): Result<Vec<IpAddrIface>, _> = serde_json::from_slice(before) else {
        return Vec::new();
    };
    let Ok(post): Result<Vec<IpAddrIface>, _> = serde_json::from_slice(after) else {
        return Vec::new();
    };
    let mut inverse = Vec::new();
    // Index pre/post by ifname for per-iface diff.
    use std::collections::HashMap;
    let pre_by_if: HashMap<&str, &IpAddrIface> =
        pre.iter().map(|i| (i.ifname.as_str(), i)).collect();
    let post_by_if: HashMap<&str, &IpAddrIface> =
        post.iter().map(|i| (i.ifname.as_str(), i)).collect();

    // Addresses added in post but absent in pre → del.
    for (ifname, post_iface) in &post_by_if {
        let empty: Vec<IpAddrInfo> = Vec::new();
        let pre_addrs = pre_by_if
            .get(ifname)
            .map(|i| &i.addr_info)
            .unwrap_or(&empty);
        for a in &post_iface.addr_info {
            if !pre_addrs.iter().any(|p| p.identity() == a.identity()) {
                inverse.push(addr_argv("del", ifname, a));
            }
        }
    }
    // Addresses absent in post but present in pre → add back.
    for (ifname, pre_iface) in &pre_by_if {
        let empty: Vec<IpAddrInfo> = Vec::new();
        let post_addrs = post_by_if
            .get(ifname)
            .map(|i| &i.addr_info)
            .unwrap_or(&empty);
        for a in &pre_iface.addr_info {
            if !post_addrs.iter().any(|p| p.identity() == a.identity()) {
                inverse.push(addr_argv("add", ifname, a));
            }
        }
    }
    inverse
}

fn addr_argv(action: &str, ifname: &str, a: &IpAddrInfo) -> Vec<String> {
    let mut v = vec![
        "ip".to_string(),
        "addr".to_string(),
        action.to_string(),
        format!("{}/{}", a.local, a.prefixlen),
        "dev".to_string(),
        ifname.to_string(),
    ];
    if let Some(b) = &a.broadcast {
        v.push("broadcast".to_string());
        v.push(b.clone());
    }
    if let Some(s) = &a.scope {
        v.push("scope".to_string());
        v.push(s.clone());
    }
    v
}

// =================================================================
// ip link
// =================================================================

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct IpLinkRow {
    ifname: String,
    #[serde(default)]
    operstate: Option<String>,
    #[serde(default)]
    mtu: Option<u32>,
    #[serde(default)]
    address: Option<String>,
}

fn synthesise_ip_link(before: &[u8], after: &[u8]) -> Vec<Vec<String>> {
    let Ok(pre): Result<Vec<IpLinkRow>, _> = serde_json::from_slice(before) else {
        return Vec::new();
    };
    let Ok(post): Result<Vec<IpLinkRow>, _> = serde_json::from_slice(after) else {
        return Vec::new();
    };
    let mut inverse = Vec::new();
    for post_row in &post {
        let Some(pre_row) = pre.iter().find(|p| p.ifname == post_row.ifname) else {
            // New iface in post but not pre — `ip link del` would
            // remove it. We don't emit that automatically: link
            // additions usually come from `ip link add` for tunnels
            // or veths, and the right inverse is complex enough that
            // we leave it to the user. Surface as a no-op for now.
            continue;
        };
        // operstate flip → ip link set <if> up/down. The kernel
        // reports operstate in uppercase ("UP", "DOWN", "UNKNOWN").
        // The set command uses lowercase verbs.
        if let (Some(pre_state), Some(post_state)) = (&pre_row.operstate, &post_row.operstate)
            && pre_state != post_state
        {
            let pre_norm = pre_state.to_ascii_uppercase();
            // Only flip when both states are concrete UP/DOWN. We
            // skip ambiguous transitions involving UNKNOWN since
            // the right verb is unclear.
            if matches!(pre_norm.as_str(), "UP" | "DOWN") {
                let verb = if pre_norm == "UP" { "up" } else { "down" };
                inverse.push(vec![
                    "ip".to_string(),
                    "link".to_string(),
                    "set".to_string(),
                    post_row.ifname.clone(),
                    verb.to_string(),
                ]);
            }
        }
        // MTU change → set it back.
        if let (Some(pre_mtu), Some(post_mtu)) = (pre_row.mtu, post_row.mtu)
            && pre_mtu != post_mtu
        {
            inverse.push(vec![
                "ip".to_string(),
                "link".to_string(),
                "set".to_string(),
                post_row.ifname.clone(),
                "mtu".to_string(),
                pre_mtu.to_string(),
            ]);
        }
    }
    inverse
}

// =================================================================
// ufw (DR-47)
// =================================================================

/// Threshold for switching from per-rule delete to a single
/// `ufw --force reset` plus reapply. Above this many net changes,
/// individual deletes/adds become noisy and error-prone; one reset
/// is cleaner. 10 is the documented default from the sprint
/// open-question. Users may override by configuration once we
/// expose a knob.
pub const UFW_RESET_THRESHOLD: usize = 10;

/// Synthesise ufw inverse invocations. `before` and `after` are the
/// raw `UfwInspector::collect_state` blobs (`status verbose` +
/// `\n---\n` + `status numbered`).
///
/// Decision logic:
/// 1. Parse both blobs into rule-string sets.
/// 2. Compute `added = after - before` and `removed = before - after`.
/// 3. If `added.len() + removed.len() <= UFW_RESET_THRESHOLD`:
///    emit `ufw delete <rule>` per added rule, then `ufw <rule>` per
///    removed rule. Order: deletes first so reinstated rules don't
///    collide with the rules they're replacing.
/// 4. Otherwise: emit one `ufw --force reset`, then `ufw <rule>` for
///    every rule in `before`. This is the safe-but-disruptive path.
///
/// Returns `Vec::new()` when both states parse empty or when the
/// before/after rule sets are identical.
pub fn synthesise_ufw_inverse(before: &[u8], after: &[u8]) -> Vec<Vec<String>> {
    let before_rules = parse_ufw_rules(before);
    let after_rules = parse_ufw_rules(after);

    let before_set: std::collections::BTreeSet<&String> = before_rules.iter().collect();
    let after_set: std::collections::BTreeSet<&String> = after_rules.iter().collect();

    let added: Vec<&&String> = after_set.difference(&before_set).collect();
    let removed: Vec<&&String> = before_set.difference(&after_set).collect();

    if added.is_empty() && removed.is_empty() {
        return Vec::new();
    }

    let total_changes = added.len() + removed.len();
    if total_changes > UFW_RESET_THRESHOLD {
        let mut out = vec![vec!["ufw".into(), "--force".into(), "reset".into()]];
        // Reapply in the captured order so rule numbering is preserved.
        for rule in &before_rules {
            out.push(rule_to_add_argv(rule));
        }
        return out;
    }

    let mut out = Vec::with_capacity(total_changes);
    // Deletes first: drop rules added since capture.
    for rule in &added {
        out.push(rule_to_delete_argv(rule));
    }
    // Then re-add: restore rules removed since capture.
    for rule in &removed {
        out.push(rule_to_add_argv(rule));
    }
    out
}

/// Parse a `UfwInspector::collect_state` blob into the ordered list
/// of rule body strings (the part after the `[N]` index). Returns
/// `Vec::new()` if the blob is malformed or ufw is inactive.
///
/// Looks at the `status numbered` half of the blob (after the
/// `\n---\n` separator). Lines that match `[ N] <body>` are
/// extracted; lines outside the rule table are ignored.
fn parse_ufw_rules(blob: &[u8]) -> Vec<String> {
    let s = match std::str::from_utf8(blob) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    // The capture blob has "verbose\n---\nnumbered". Take the numbered half.
    let numbered = s.split_once("\n---\n").map(|(_v, n)| n).unwrap_or(s);
    let mut rules = Vec::new();
    for line in numbered.lines() {
        let trimmed = line.trim_start();
        // Match "[N] " or "[ N] " prefix.
        if !trimmed.starts_with('[') {
            continue;
        }
        let rest = match trimmed.split_once(']') {
            Some((idx, rest)) => {
                if !idx[1..].trim().chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                rest.trim()
            }
            None => continue,
        };
        if rest.is_empty() {
            continue;
        }
        // Collapse internal whitespace runs and drop `(v6)` markers
        // so a v4/v6 mirror pair collapses to a single canonical
        // rule. ufw auto-creates the v6 mirror; we never want it
        // to produce a duplicate inverse invocation.
        let normalized: String = rest
            .split_whitespace()
            .filter(|t| *t != "(v6)")
            .collect::<Vec<_>>()
            .join(" ");
        if !normalized.is_empty() && !rules.iter().any(|r| r == &normalized) {
            rules.push(normalized);
        }
    }
    rules
}

/// Build a `ufw delete <rule>` argv. The rule string comes verbatim
/// from `parse_ufw_rules`; ufw accepts the same syntax for delete
/// that it does for the original add (modulo trailing v6 markers
/// which the wrapper preserves).
fn rule_to_delete_argv(rule: &str) -> Vec<String> {
    let mut argv: Vec<String> = vec!["ufw".into(), "delete".into()];
    for tok in canonicalize_ufw_rule(rule) {
        argv.push(tok);
    }
    argv
}

/// Build the original `ufw <rule>` argv to reinstate a rule.
fn rule_to_add_argv(rule: &str) -> Vec<String> {
    let mut argv: Vec<String> = vec!["ufw".into()];
    for tok in canonicalize_ufw_rule(rule) {
        argv.push(tok);
    }
    argv
}

/// Convert the parsed `status numbered` body to the argv form ufw
/// accepts for `ufw <action> ...`.
///
/// Status format: `<to> <ACTION> [IN|OUT|FWD] <from>` (with optional
/// `(v6)` markers and `from <addr> to <addr> port <port>` clauses).
///
/// Two output forms:
/// - Compact (`allow 80`): when the rule is `<to-token> <ACTION> IN Anywhere`
///   — the implicit IN/Anywhere is the ufw CLI default.
/// - Verbose (`allow in to any port 80 from <addr>`): for non-default
///   directions or non-default source addresses.
fn canonicalize_ufw_rule(rule: &str) -> Vec<String> {
    let tokens: Vec<&str> = rule.split_whitespace().filter(|t| *t != "(v6)").collect();
    let mut to_buf: Vec<String> = Vec::new();
    let mut from_buf: Vec<String> = Vec::new();
    let mut action: Option<String> = None;
    let mut direction: Option<String> = None;
    let mut seen_action = false;

    for tok in &tokens {
        if !seen_action {
            if matches!(*tok, "ALLOW" | "DENY" | "REJECT" | "LIMIT") {
                action = Some(tok.to_ascii_lowercase());
                seen_action = true;
                continue;
            }
            to_buf.push((*tok).to_string());
        } else if direction.is_none() && matches!(*tok, "IN" | "OUT" | "FWD") {
            direction = Some(tok.to_ascii_lowercase());
        } else {
            from_buf.push((*tok).to_string());
        }
    }

    let Some(act) = action else {
        // No action verb — fall back to the rule verbatim.
        return tokens.iter().map(|s| (*s).to_string()).collect();
    };

    let dir_is_default = direction.as_deref().is_none_or(|d| d == "in");
    let from_joined = from_buf.join(" ");
    let from_is_default = from_joined.eq_ignore_ascii_case("Anywhere") || from_joined.is_empty();
    let to_is_simple_token = to_buf.len() == 1
        && !to_buf[0].contains(' ')
        && !to_buf[0].eq_ignore_ascii_case("Anywhere");

    if dir_is_default && from_is_default && to_is_simple_token {
        return vec![act, to_buf.remove(0)];
    }

    // Verbose form.
    let mut out: Vec<String> = vec![act];
    if let Some(dir) = direction {
        out.push(dir);
    }
    if !from_is_default {
        out.push("from".into());
        out.push(from_joined);
    }
    if !to_buf.is_empty() {
        out.push("to".into());
        out.push("any".into());
        out.push("port".into());
        out.extend(to_buf);
    }
    out
}

// =================================================================
// networksetup (macOS) — M06.1: DNS-only first ship.
// =================================================================

/// Parsed shape of a captured `networksetup -getdnsservers
/// <service>` snapshot. The helper prepends a `# scope=<service>`
/// header line so we know which service to target on undo without
/// per-event scope plumbing through the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworksetupDnsSnapshot {
    /// Network service name (e.g. "Wi-Fi", "Ethernet").
    service: String,
    /// DNS servers in the order networksetup reported them. Empty
    /// when networksetup said "There aren't any DNS Servers set
    /// on <service>." — undo of "added DNS" must restore the
    /// empty state via the literal `empty` arg to setdnsservers.
    servers: Vec<String>,
}

/// Parse a captured DNS snapshot. Returns None when the header
/// line is missing or malformed (defensive — synthesizer emits
/// no inverse, planner logs a Informational warning).
fn parse_networksetup_dns_snapshot(bytes: &[u8]) -> Option<NetworksetupDnsSnapshot> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    let header = lines.next()?;
    let service = header.strip_prefix("# scope=")?.to_string();
    if service.is_empty() {
        return None;
    }
    let mut servers = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // "There aren't any DNS Servers set on <service>." → no
        // servers configured. The undo for "added DNS" is to
        // restore that empty state via `setdnsservers <svc> empty`.
        if trimmed.starts_with("There aren't any DNS Servers set") {
            continue;
        }
        servers.push(trimmed.to_string());
    }
    Some(NetworksetupDnsSnapshot { service, servers })
}

fn synthesise_networksetup(before: &[u8], after: &[u8]) -> Vec<Vec<String>> {
    let Some(pre) = parse_networksetup_dns_snapshot(before) else {
        return Vec::new();
    };
    // Best-effort consistency: the pre + post snapshots should
    // share a service (the user's `-setdnsservers <svc>` invocation
    // didn't switch services mid-flight). When `after` doesn't
    // parse, fall through — the undo's `setdnsservers` is still
    // correct since we use `pre`'s service identity.
    if let Some(post) = parse_networksetup_dns_snapshot(after)
        && post.service != pre.service
    {
        // Different services in before/after → we don't have a
        // single coherent inverse; bail. The planner will surface
        // an Informational warning to the operator.
        return Vec::new();
    }
    // If servers didn't actually change (e.g. user re-set the same
    // list), the undo is a no-op.
    if let Some(post) = parse_networksetup_dns_snapshot(after)
        && post.servers == pre.servers
    {
        return Vec::new();
    }
    let mut argv = vec![
        "networksetup".to_string(),
        "-setdnsservers".to_string(),
        pre.service,
    ];
    if pre.servers.is_empty() {
        // The literal "empty" arg clears DNS servers on the
        // service. networksetup uses this sentinel because passing
        // zero positional servers is ambiguous with usage errors.
        argv.push("empty".to_string());
    } else {
        argv.extend(pre.servers);
    }
    vec![argv]
}

// =================================================================
// route (macOS, M06.3, DR-44)
// =================================================================
//
// `route` on macOS has no JSON dump form; the helper captures
// `netstat -nrf inet` as a flat table. We parse the table into
// (destination, gateway, iface) triples and diff.
//
// Inverse:
//   - destination in post but not pre → `route delete -net <dst>`
//     (the gateway is dropped on delete — route(8) doesn't accept
//     it for network routes; see sprint doc)
//   - destination in pre but not post → `route add -net <dst> <gw>`
//     restoring the prior gateway.
//
// We skip host routes managed by the kernel (Flags=UH for `127.x`,
// Flags starting with `UC` link routes for connected interfaces).
// Those churn under VPN clients and aren't user-issued. Heuristic:
// only diff rows whose destination is a CIDR-ish form (contains
// `.` or `/`, isn't `default`, isn't pure host loopback).

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RouteRow {
    destination: String,
    gateway: String,
    iface: String,
}

impl RouteRow {
    fn identity(&self) -> (String, String) {
        (self.destination.clone(), self.iface.clone())
    }
}

fn parse_netstat_routes(blob: &[u8]) -> Vec<RouteRow> {
    let text = String::from_utf8_lossy(blob);
    let mut out = Vec::new();
    let mut in_table = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Header rows. `netstat -nrf inet` emits:
        //   Routing tables
        //   <blank>
        //   Internet:
        //   Destination        Gateway   Flags   ...   Netif Expire
        //   <data...>
        if trimmed == "Routing tables" || trimmed.ends_with(':') {
            continue;
        }
        if trimmed.starts_with("Destination") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        let mut cols = trimmed.split_whitespace();
        let Some(dst) = cols.next() else { continue };
        let Some(gw) = cols.next() else { continue };
        // Flags is col 3; col 4 is Netif (varies by macOS version).
        let _flags = cols.next();
        let iface = cols.next().unwrap_or("").to_string();
        out.push(RouteRow {
            destination: dst.to_string(),
            gateway: gw.to_string(),
            iface,
        });
    }
    out
}

/// Decide whether a route looks user-issuable (so the inverse is
/// safe to synthesise). Kernel-managed connected/host routes
/// (`link#NN` gateways, loopback hosts, IPv6 link-local, `127.x`
/// containers) are skipped.
fn route_is_diff_candidate(r: &RouteRow) -> bool {
    if r.gateway.starts_with("link#") {
        return false;
    }
    if r.destination.starts_with("127.") {
        return false;
    }
    // The `default` route is user-issuable in principle but undoing
    // it would knock the box off the network mid-session. Skip — if
    // the user wants to undo a default-route swap, they can do it
    // manually with a clear warning emitted upstream.
    if r.destination == "default" {
        return false;
    }
    true
}

fn synthesise_route(before: &[u8], after: &[u8]) -> Vec<Vec<String>> {
    let pre = parse_netstat_routes(before);
    let post = parse_netstat_routes(after);
    let mut inverse = Vec::new();
    // Added → delete.
    for r in &post {
        if !route_is_diff_candidate(r) {
            continue;
        }
        if !pre.iter().any(|p| p.identity() == r.identity()) {
            inverse.push(vec![
                "route".to_string(),
                "delete".to_string(),
                "-net".to_string(),
                r.destination.clone(),
            ]);
        }
    }
    // Removed → re-add with the original gateway.
    for r in &pre {
        if !route_is_diff_candidate(r) {
            continue;
        }
        if !post.iter().any(|p| p.identity() == r.identity()) {
            inverse.push(vec![
                "route".to_string(),
                "add".to_string(),
                "-net".to_string(),
                r.destination.clone(),
                r.gateway.clone(),
            ]);
        }
    }
    inverse
}

// =================================================================
// ifconfig (macOS, M06.3, DR-44)
// =================================================================
//
// `ifconfig -a` emits per-interface blocks:
//   en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
//       inet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255
//       inet 10.0.0.5 netmask 0xff000000 broadcast 10.255.255.255
//       status: active
//
// We parse into a per-interface (flags-has-UP, inet-addrs) tuple
// and synthesise:
//   - UP→DOWN flip → `ifconfig <if> up`
//   - DOWN→UP flip → `ifconfig <if> down`
//   - inet added in post → `ifconfig <if> -alias <addr>` (delete)
//   - inet removed in post → `ifconfig <if> alias <addr> netmask <mask>`

#[derive(Debug, Clone, PartialEq, Eq)]
struct IfconfigIface {
    name: String,
    is_up: bool,
    inets: Vec<IfconfigInet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IfconfigInet {
    addr: String,
    /// Native ifconfig form, e.g. `0xffffff00`. Pass-through to the
    /// inverse `ifconfig alias` command verbatim.
    netmask: String,
}

fn parse_ifconfig(blob: &[u8]) -> Vec<IfconfigIface> {
    let text = String::from_utf8_lossy(blob);
    let mut out: Vec<IfconfigIface> = Vec::new();
    for line in text.lines() {
        // New interface block when the line starts at col 0 with
        // `<name>: flags=...`.
        if !line.starts_with(char::is_whitespace)
            && let Some(colon) = line.find(':')
        {
            let name = line[..colon].to_string();
            let is_up = line.contains("<UP,") || line.contains(",UP,") || line.contains(",UP>");
            out.push(IfconfigIface {
                name,
                is_up,
                inets: Vec::new(),
            });
            continue;
        }
        let trimmed = line.trim_start();
        // inet line: `inet 192.168.1.10 netmask 0xffffff00 ...`.
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            let mut toks = rest.split_whitespace();
            let Some(addr) = toks.next() else { continue };
            let mut netmask = String::new();
            while let Some(t) = toks.next() {
                if t == "netmask"
                    && let Some(n) = toks.next()
                {
                    netmask = n.to_string();
                    break;
                }
            }
            if let Some(iface) = out.last_mut() {
                iface.inets.push(IfconfigInet {
                    addr: addr.to_string(),
                    netmask,
                });
            }
        }
    }
    out
}

fn synthesise_ifconfig(before: &[u8], after: &[u8]) -> Vec<Vec<String>> {
    let pre = parse_ifconfig(before);
    let post = parse_ifconfig(after);
    let mut inverse = Vec::new();
    for post_if in &post {
        let Some(pre_if) = pre.iter().find(|i| i.name == post_if.name) else {
            continue;
        };
        // UP/DOWN flip.
        if pre_if.is_up != post_if.is_up {
            let verb = if pre_if.is_up { "up" } else { "down" };
            inverse.push(vec![
                "ifconfig".to_string(),
                post_if.name.clone(),
                verb.to_string(),
            ]);
        }
        // Addresses added in post but not pre → -alias to remove.
        for inet in &post_if.inets {
            if !pre_if.inets.iter().any(|p| p.addr == inet.addr) {
                inverse.push(vec![
                    "ifconfig".to_string(),
                    post_if.name.clone(),
                    "-alias".to_string(),
                    inet.addr.clone(),
                ]);
            }
        }
        // Addresses present in pre but missing in post → restore alias.
        for inet in &pre_if.inets {
            if !post_if.inets.iter().any(|p| p.addr == inet.addr) {
                let mut argv = vec![
                    "ifconfig".to_string(),
                    post_if.name.clone(),
                    "alias".to_string(),
                    inet.addr.clone(),
                ];
                if !inet.netmask.is_empty() {
                    argv.push("netmask".to_string());
                    argv.push(inet.netmask.clone());
                }
                inverse.push(argv);
            }
        }
    }
    inverse
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // ip route
    // -----------------------------------------------------------------

    #[test]
    fn ip_route_added_route_is_inverted_via_del() {
        let pre = b"[]";
        let post = br#"[{"dst":"10.0.0.0/24","gateway":"192.168.1.1","dev":"eth0","metric":100}]"#;
        let inv = synthesise_ip_route(pre, post);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0][0], "ip");
        assert_eq!(inv[0][1], "route");
        assert_eq!(inv[0][2], "del");
        assert_eq!(inv[0][3], "10.0.0.0/24");
        assert!(inv[0].iter().any(|s| s == "via"));
    }

    #[test]
    fn ip_route_removed_route_is_inverted_via_add() {
        let pre =
            br#"[{"dst":"10.0.0.0/24","gateway":"192.168.1.1","dev":"eth0","scope":"global"}]"#;
        let post = b"[]";
        let inv = synthesise_ip_route(pre, post);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0][2], "add");
        // Scope flows through.
        assert!(inv[0].iter().any(|s| s == "scope"));
        assert!(inv[0].iter().any(|s| s == "global"));
    }

    #[test]
    fn ip_route_identical_before_and_after_emits_nothing() {
        let same = br#"[{"dst":"10.0.0.0/24","dev":"eth0"}]"#;
        assert!(synthesise_ip_route(same, same).is_empty());
    }

    #[test]
    fn ip_route_distinguishes_routes_by_metric() {
        // Same dst+dev, different metric → distinct routes.
        let pre = br#"[
            {"dst":"10.0.0.0/24","dev":"eth0","metric":100},
            {"dst":"10.0.0.0/24","dev":"eth0","metric":200}
        ]"#;
        let post = br#"[{"dst":"10.0.0.0/24","dev":"eth0","metric":100}]"#;
        let inv = synthesise_ip_route(pre, post);
        // Only the metric=200 route was removed; inverse re-adds it.
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0][2], "add");
        assert!(inv[0].iter().any(|s| s == "200"));
    }

    #[test]
    fn ip_route_malformed_json_returns_empty() {
        assert!(synthesise_ip_route(b"not json", b"[]").is_empty());
        assert!(synthesise_ip_route(b"[]", b"not json").is_empty());
    }

    #[test]
    fn ip_route_non_main_table_is_preserved_in_inverse() {
        let pre = br#"[{"dst":"10.0.0.0/24","dev":"wg0","table":"100"}]"#;
        let post = b"[]";
        let inv = synthesise_ip_route(pre, post);
        assert_eq!(inv.len(), 1);
        assert!(inv[0].iter().any(|s| s == "table"));
        assert!(inv[0].iter().any(|s| s == "100"));
    }

    #[test]
    fn ip_route_main_table_is_not_emitted_redundantly() {
        // table=main is the default; emitting `table main` in the
        // argv is harmless but noisy.
        let pre = br#"[{"dst":"10.0.0.0/24","dev":"eth0","table":"main"}]"#;
        let post = b"[]";
        let inv = synthesise_ip_route(pre, post);
        assert!(!inv[0].iter().any(|s| s == "table"));
    }

    // -----------------------------------------------------------------
    // ip addr
    // -----------------------------------------------------------------

    #[test]
    fn ip_addr_added_address_is_inverted_via_del() {
        let pre = br#"[{"ifname":"eth0","addr_info":[]}]"#;
        let post = br#"[{"ifname":"eth0","addr_info":[
            {"family":"inet","local":"192.168.1.10","prefixlen":24,"scope":"global"}
        ]}]"#;
        let inv = synthesise_ip_addr(pre, post);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0][0], "ip");
        assert_eq!(inv[0][1], "addr");
        assert_eq!(inv[0][2], "del");
        assert_eq!(inv[0][3], "192.168.1.10/24");
        assert_eq!(inv[0][4], "dev");
        assert_eq!(inv[0][5], "eth0");
    }

    #[test]
    fn ip_addr_removed_address_is_inverted_via_add() {
        let pre = br#"[{"ifname":"eth0","addr_info":[
            {"family":"inet","local":"10.0.0.5","prefixlen":24,"scope":"global"}
        ]}]"#;
        let post = br#"[{"ifname":"eth0","addr_info":[]}]"#;
        let inv = synthesise_ip_addr(pre, post);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0][2], "add");
    }

    #[test]
    fn ip_addr_handles_new_interface_with_addresses() {
        // wg0 didn't exist pre; appears post with one address — inverse is `addr del`.
        let pre = b"[]";
        let post = br#"[{"ifname":"wg0","addr_info":[
            {"family":"inet","local":"10.0.0.1","prefixlen":24,"scope":"global"}
        ]}]"#;
        let inv = synthesise_ip_addr(pre, post);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0][2], "del");
    }

    // -----------------------------------------------------------------
    // ip link
    // -----------------------------------------------------------------

    #[test]
    fn ip_link_operstate_up_to_down_inverts_to_up() {
        let pre = br#"[{"ifname":"eth0","operstate":"UP","mtu":1500}]"#;
        let post = br#"[{"ifname":"eth0","operstate":"DOWN","mtu":1500}]"#;
        let inv = synthesise_ip_link(pre, post);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0], vec!["ip", "link", "set", "eth0", "up"]);
    }

    #[test]
    fn ip_link_mtu_change_inverts_to_pre_value() {
        let pre = br#"[{"ifname":"eth0","operstate":"UP","mtu":1500}]"#;
        let post = br#"[{"ifname":"eth0","operstate":"UP","mtu":9000}]"#;
        let inv = synthesise_ip_link(pre, post);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0], vec!["ip", "link", "set", "eth0", "mtu", "1500"]);
    }

    #[test]
    fn ip_link_operstate_unknown_is_skipped() {
        // UNKNOWN → DOWN: we don't know the "up" verb's correctness
        // here, so skip rather than emit a bad invocation.
        let pre = br#"[{"ifname":"lo","operstate":"UNKNOWN","mtu":65536}]"#;
        let post = br#"[{"ifname":"lo","operstate":"DOWN","mtu":65536}]"#;
        let inv = synthesise_ip_link(pre, post);
        assert!(inv.is_empty());
    }

    #[test]
    fn ip_link_both_state_and_mtu_change_emits_two_invocations() {
        let pre = br#"[{"ifname":"eth0","operstate":"UP","mtu":1500}]"#;
        let post = br#"[{"ifname":"eth0","operstate":"DOWN","mtu":9000}]"#;
        let inv = synthesise_ip_link(pre, post);
        assert_eq!(inv.len(), 2);
        // Order: state, then mtu (per the function body).
        assert!(inv[0].iter().any(|s| s == "up"));
        assert!(inv[1].iter().any(|s| s == "mtu"));
    }

    #[test]
    fn ip_link_new_interface_in_post_is_skipped() {
        // wg0 didn't exist pre; we don't auto-emit `ip link del`.
        let pre = b"[]";
        let post = br#"[{"ifname":"wg0","operstate":"UP","mtu":1420}]"#;
        let inv = synthesise_ip_link(pre, post);
        assert!(inv.is_empty());
    }

    // -----------------------------------------------------------------
    // Dispatch
    // -----------------------------------------------------------------

    #[test]
    fn dispatch_unsupported_tool_returns_empty() {
        // route / ifconfig / networksetup are documented gaps.
        for tool in [
            NetworkTool::Route,
            NetworkTool::Ifconfig,
            NetworkTool::Networksetup,
            // Full-reload tools should also return empty here —
            // the planner gates them upstream.
            NetworkTool::Iptables,
            NetworkTool::Nft,
        ] {
            assert!(synthesise_diff_apply_inverse(tool, b"[]", b"[]").is_empty());
        }
    }

    #[test]
    fn dispatch_routes_to_ip_route() {
        let post = br#"[{"dst":"10.0.0.0/24","dev":"eth0"}]"#;
        let inv = synthesise_diff_apply_inverse(NetworkTool::IpRoute, b"[]", post);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0][2], "del");
    }

    // -----------------------------------------------------------------
    // ufw (DR-47)
    // -----------------------------------------------------------------

    fn ufw_blob(verbose: &str, numbered: &str) -> Vec<u8> {
        format!("{verbose}\n---\n{numbered}").into_bytes()
    }

    const VERBOSE_SAMPLE: &str = "Status: active\nLogging: on (low)\n";

    #[test]
    fn ufw_added_rule_yields_single_delete() {
        // Before: empty rules. After: one rule added.
        let before = ufw_blob(VERBOSE_SAMPLE, "Status: active\n\n");
        let after = ufw_blob(
            VERBOSE_SAMPLE,
            "Status: active\n\n     To                         Action      From\n\
             [ 1] 8080                       ALLOW IN    Anywhere\n",
        );
        let inv = synthesise_ufw_inverse(&before, &after);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0], vec!["ufw", "delete", "allow", "8080"]);
    }

    #[test]
    fn ufw_removed_rule_yields_single_add() {
        let before = ufw_blob(
            VERBOSE_SAMPLE,
            "Status: active\n\n[ 1] 22/tcp                     ALLOW IN    Anywhere\n",
        );
        let after = ufw_blob(VERBOSE_SAMPLE, "Status: active\n\n");
        let inv = synthesise_ufw_inverse(&before, &after);
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0], vec!["ufw", "allow", "22/tcp"]);
    }

    #[test]
    fn ufw_under_threshold_emits_per_rule_inverse() {
        // 3 rules added — under threshold; per-rule deletes.
        let before = ufw_blob(VERBOSE_SAMPLE, "Status: active\n\n");
        let after = ufw_blob(
            VERBOSE_SAMPLE,
            "Status: active\n\n\
             [ 1] 80                         ALLOW IN    Anywhere\n\
             [ 2] 443                        ALLOW IN    Anywhere\n\
             [ 3] 8080                       ALLOW IN    Anywhere\n",
        );
        let inv = synthesise_ufw_inverse(&before, &after);
        assert_eq!(inv.len(), 3);
        assert!(inv.iter().all(|v| v[1] == "delete"));
    }

    #[test]
    fn ufw_over_threshold_emits_reset_plus_reapply() {
        // 11 rules added — exceeds UFW_RESET_THRESHOLD (10). We
        // emit `ufw --force reset` + zero rules to reapply since
        // before was empty.
        let mut numbered = String::from("Status: active\n\n");
        for i in 1..=11 {
            numbered.push_str(&format!(
                "[{i:>2}] {port:<25} ALLOW IN    Anywhere\n",
                port = 8000 + i
            ));
        }
        let before = ufw_blob(VERBOSE_SAMPLE, "Status: active\n\n");
        let after = ufw_blob(VERBOSE_SAMPLE, &numbered);
        let inv = synthesise_ufw_inverse(&before, &after);
        assert_eq!(inv[0], vec!["ufw", "--force", "reset"]);
        assert_eq!(inv.len(), 1, "before was empty, no rules to reapply");
    }

    #[test]
    fn ufw_over_threshold_reapplies_before_rules_in_order() {
        // 11 rules removed — reset, then reapply each of the 11.
        let mut before_numbered = String::from("Status: active\n\n");
        for i in 1..=11 {
            before_numbered.push_str(&format!(
                "[{i:>2}] {port:<25} ALLOW IN    Anywhere\n",
                port = 9000 + i
            ));
        }
        let before = ufw_blob(VERBOSE_SAMPLE, &before_numbered);
        let after = ufw_blob(VERBOSE_SAMPLE, "Status: active\n\n");
        let inv = synthesise_ufw_inverse(&before, &after);
        assert_eq!(inv.len(), 12);
        assert_eq!(inv[0], vec!["ufw", "--force", "reset"]);
        assert_eq!(inv[1], vec!["ufw", "allow", "9001"]);
        assert_eq!(inv[11], vec!["ufw", "allow", "9011"]);
    }

    #[test]
    fn ufw_identical_before_after_emits_no_inverse() {
        let blob = ufw_blob(
            VERBOSE_SAMPLE,
            "Status: active\n\n[ 1] 80 ALLOW IN Anywhere\n",
        );
        let inv = synthesise_ufw_inverse(&blob, &blob);
        assert!(inv.is_empty());
    }

    #[test]
    fn ufw_v6_marker_is_dropped_for_dedup() {
        // The v4 and v6 mirror rules collapse to the same rule
        // string after `(v6)` is stripped, so they shouldn't
        // generate duplicate inverse invocations on identical state.
        let before = ufw_blob(
            VERBOSE_SAMPLE,
            "Status: active\n\n\
             [ 1] 80                         ALLOW IN    Anywhere\n\
             [ 2] 80 (v6)                    ALLOW IN    Anywhere (v6)\n",
        );
        let after = ufw_blob(VERBOSE_SAMPLE, "Status: active\n\n");
        let inv = synthesise_ufw_inverse(&before, &after);
        // Both rows collapse to "80 ALLOW IN Anywhere" → single add.
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0], vec!["ufw", "allow", "80"]);
    }

    #[test]
    fn ufw_complex_rule_uses_verbose_form() {
        let before = ufw_blob(
            VERBOSE_SAMPLE,
            "Status: active\n\n\
             [ 1] 22/tcp                     ALLOW IN    192.168.1.0/24\n",
        );
        let after = ufw_blob(VERBOSE_SAMPLE, "Status: active\n\n");
        let inv = synthesise_ufw_inverse(&before, &after);
        assert_eq!(inv.len(), 1);
        let argv = &inv[0];
        assert_eq!(argv[0], "ufw");
        assert_eq!(argv[1], "allow");
        assert!(argv.contains(&"192.168.1.0/24".to_string()), "{argv:?}");
        assert!(argv.contains(&"22/tcp".to_string()), "{argv:?}");
    }

    #[test]
    fn ufw_malformed_blob_yields_no_inverse() {
        let before = b"garbage with no numbered section".to_vec();
        let after = b"different garbage".to_vec();
        let inv = synthesise_ufw_inverse(&before, &after);
        assert!(inv.is_empty());
    }

    // M06.1 — networksetup DNS synthesizer.

    #[test]
    fn networksetup_parses_scope_header_and_servers() {
        let raw = b"# scope=Wi-Fi\n1.1.1.1\n8.8.8.8\n";
        let snap = parse_networksetup_dns_snapshot(raw).expect("parses");
        assert_eq!(snap.service, "Wi-Fi");
        assert_eq!(snap.servers, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[test]
    fn networksetup_parses_empty_dns_form() {
        // The literal "There aren't any DNS Servers set on Wi-Fi."
        // is networksetup's way of saying "no DNS configured".
        let raw = b"# scope=Wi-Fi\nThere aren't any DNS Servers set on Wi-Fi.\n";
        let snap = parse_networksetup_dns_snapshot(raw).expect("parses");
        assert_eq!(snap.service, "Wi-Fi");
        assert!(snap.servers.is_empty());
    }

    #[test]
    fn networksetup_returns_none_on_missing_header() {
        let raw = b"1.1.1.1\n8.8.8.8\n";
        assert!(parse_networksetup_dns_snapshot(raw).is_none());
    }

    #[test]
    fn networksetup_synthesises_setdnsservers_with_pre_list() {
        let before = b"# scope=Wi-Fi\n1.1.1.1\n8.8.8.8\n".to_vec();
        let after = b"# scope=Wi-Fi\n9.9.9.9\n".to_vec();
        let inv = synthesise_networksetup(&before, &after);
        assert_eq!(inv.len(), 1);
        assert_eq!(
            inv[0],
            vec![
                "networksetup",
                "-setdnsservers",
                "Wi-Fi",
                "1.1.1.1",
                "8.8.8.8"
            ]
        );
    }

    #[test]
    fn networksetup_synthesises_empty_arg_when_pre_was_empty() {
        // User added DNS to a previously-empty config; undo
        // restores the empty state via networksetup's "empty"
        // sentinel.
        let before = b"# scope=Wi-Fi\nThere aren't any DNS Servers set on Wi-Fi.\n".to_vec();
        let after = b"# scope=Wi-Fi\n1.1.1.1\n".to_vec();
        let inv = synthesise_networksetup(&before, &after);
        assert_eq!(
            inv[0],
            vec!["networksetup", "-setdnsservers", "Wi-Fi", "empty"]
        );
    }

    #[test]
    fn networksetup_no_op_when_servers_unchanged() {
        let before = b"# scope=Wi-Fi\n1.1.1.1\n".to_vec();
        let after = b"# scope=Wi-Fi\n1.1.1.1\n".to_vec();
        let inv = synthesise_networksetup(&before, &after);
        assert!(inv.is_empty());
    }

    #[test]
    fn networksetup_no_inverse_on_service_switch_mid_capture() {
        // Defensive: if somehow the pre + post snapshots scope to
        // different services, refuse to synthesize. This shouldn't
        // happen in practice (the wrapper passes one service per
        // event) but the safety check costs nothing.
        let before = b"# scope=Wi-Fi\n1.1.1.1\n".to_vec();
        let after = b"# scope=Ethernet\n1.1.1.1\n".to_vec();
        let inv = synthesise_networksetup(&before, &after);
        assert!(inv.is_empty());
    }

    // -----------------------------------------------------------------
    // route (macOS, M06.3)
    // -----------------------------------------------------------------

    const NETSTAT_BASELINE: &str = "\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
127                127.0.0.1          UCS            lo0
192.168.1          link#15            UCS            en0
";

    const NETSTAT_WITH_ADDED_ROUTE: &str = "\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
127                127.0.0.1          UCS            lo0
192.168.1          link#15            UCS            en0
240/4              127.0.0.1          UGSc           lo0
";

    #[test]
    fn route_added_emits_delete() {
        let inv = synthesise_route(
            NETSTAT_BASELINE.as_bytes(),
            NETSTAT_WITH_ADDED_ROUTE.as_bytes(),
        );
        assert_eq!(inv.len(), 1, "expected one inverse, got {inv:?}");
        assert_eq!(inv[0][0], "route");
        assert_eq!(inv[0][1], "delete");
        assert_eq!(inv[0][2], "-net");
        assert_eq!(inv[0][3], "240/4");
    }

    #[test]
    fn route_removed_emits_add_with_gateway() {
        let inv = synthesise_route(
            NETSTAT_WITH_ADDED_ROUTE.as_bytes(),
            NETSTAT_BASELINE.as_bytes(),
        );
        assert_eq!(inv.len(), 1, "expected one inverse, got {inv:?}");
        assert_eq!(inv[0][0], "route");
        assert_eq!(inv[0][1], "add");
        assert_eq!(inv[0][2], "-net");
        assert_eq!(inv[0][3], "240/4");
        assert_eq!(inv[0][4], "127.0.0.1");
    }

    #[test]
    fn route_identical_emits_nothing() {
        let inv = synthesise_route(NETSTAT_BASELINE.as_bytes(), NETSTAT_BASELINE.as_bytes());
        assert!(inv.is_empty());
    }

    #[test]
    fn route_skips_kernel_managed_link_routes() {
        // Only the kernel-managed `link#15` route differs — the
        // synthesiser must ignore it (would be unsafe to undo).
        let pre = "\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
";
        let post = "\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
192.168.5          link#22            UCS            en1
";
        let inv = synthesise_route(pre.as_bytes(), post.as_bytes());
        assert!(inv.is_empty(), "link#-gateway route must be skipped");
    }

    #[test]
    fn route_skips_default_route_changes() {
        // Even if the default route flips, we don't auto-undo:
        // would knock the box off the network.
        let pre = "\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
";
        let post = "\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.0.0.1           UGScg          en1
";
        let inv = synthesise_route(pre.as_bytes(), post.as_bytes());
        assert!(inv.is_empty(), "default-route flip must not auto-undo");
    }

    // -----------------------------------------------------------------
    // ifconfig (macOS, M06.3)
    // -----------------------------------------------------------------

    const IFCONFIG_EN0_UP: &str = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255
\tstatus: active
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
";

    const IFCONFIG_EN0_DOWN: &str = "\
en0: flags=8862<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255
\tstatus: inactive
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
";

    const IFCONFIG_EN0_WITH_ALIAS: &str = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.10 netmask 0xffffff00 broadcast 192.168.1.255
\tinet 10.99.0.5 netmask 0xffffff00 broadcast 10.99.0.255
\tstatus: active
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
";

    #[test]
    fn ifconfig_up_to_down_emits_up() {
        let inv = synthesise_ifconfig(IFCONFIG_EN0_UP.as_bytes(), IFCONFIG_EN0_DOWN.as_bytes());
        assert!(
            inv.iter().any(|cmd| cmd == &vec!["ifconfig", "en0", "up"]),
            "missing en0 up inverse, got {inv:?}"
        );
    }

    #[test]
    fn ifconfig_down_to_up_emits_down() {
        let inv = synthesise_ifconfig(IFCONFIG_EN0_DOWN.as_bytes(), IFCONFIG_EN0_UP.as_bytes());
        assert!(
            inv.iter()
                .any(|cmd| cmd == &vec!["ifconfig", "en0", "down"]),
            "missing en0 down inverse, got {inv:?}"
        );
    }

    #[test]
    fn ifconfig_alias_added_emits_minus_alias() {
        let inv = synthesise_ifconfig(
            IFCONFIG_EN0_UP.as_bytes(),
            IFCONFIG_EN0_WITH_ALIAS.as_bytes(),
        );
        // Should emit `ifconfig en0 -alias 10.99.0.5`.
        assert!(
            inv.iter().any(|cmd| {
                cmd.len() >= 4
                    && cmd[0] == "ifconfig"
                    && cmd[2] == "-alias"
                    && cmd[3] == "10.99.0.5"
            }),
            "missing -alias inverse, got {inv:?}"
        );
    }

    #[test]
    fn ifconfig_alias_removed_emits_alias_with_netmask() {
        let inv = synthesise_ifconfig(
            IFCONFIG_EN0_WITH_ALIAS.as_bytes(),
            IFCONFIG_EN0_UP.as_bytes(),
        );
        let restore = inv
            .iter()
            .find(|cmd| cmd.len() >= 4 && cmd[2] == "alias" && cmd[3] == "10.99.0.5")
            .expect("alias-restore inverse missing");
        // Should carry the netmask through.
        assert!(
            restore.iter().any(|t| t == "netmask"),
            "alias restore lacks netmask, got {restore:?}"
        );
        assert!(
            restore.iter().any(|t| t == "0xffffff00"),
            "alias restore lacks captured netmask value"
        );
    }

    #[test]
    fn ifconfig_identical_emits_nothing() {
        let inv = synthesise_ifconfig(IFCONFIG_EN0_UP.as_bytes(), IFCONFIG_EN0_UP.as_bytes());
        assert!(inv.is_empty());
    }
}

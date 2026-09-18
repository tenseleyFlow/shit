// SPDX-License-Identifier: AGPL-3.0-or-later

//! docker argv classifier — used by the capture-time hook to decide
//! which verb a `docker ...` invocation maps to. The hook calls
//! `classify_docker_argv(argv)`; on a destructive verb, it captures
//! the appropriate pre-state (inspect + commit / save / volume-tar /
//! network-inspect) before the real exec.
//!
//! Stage 1 of C04.2 ships the classifier + tests; wiring the helper
//! `container-event` ctl request, the docker-commit stash flow, and
//! the daemon-side pairing is DR-CR-21..26.

/// What the argv signalled. `None` means "no capture needed"
/// (read-only verb, unrecognized verb, or argv that doesn't look
/// like docker at all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerVerb {
    /// `docker rm [-f] <id...>` / `docker container rm [-f] <id...>`.
    /// The wrapper inspect-captures each id; if `force=true`, it
    /// `docker commit`s any running containers into a `shit-stash`
    /// image before the real `rm -f` lands.
    Rm { ids: Vec<String>, force: bool },
    /// `docker rmi <image...>` / `docker image rm <image...>`. The
    /// wrapper `docker save`s each image to a stash tarball before
    /// the real delete.
    Rmi { images: Vec<String> },
    /// `docker volume rm <vol...>`. The wrapper tars each volume's
    /// contents into a stash blob before the real delete.
    VolumeRm { names: Vec<String> },
    /// `docker network rm <net...>`. The wrapper inspect-captures
    /// each network's driver / subnet / gateway / options before the
    /// real delete.
    NetworkRm { names: Vec<String> },
    /// `docker stop <id...>` / `docker kill <id...>`. Restart-hint
    /// only; we don't lose the container state, just the running
    /// process. The wrapper inspect-captures so undo can re-`start`.
    StopOrKill {
        ids: Vec<String>,
        /// `true` for `kill`, `false` for `stop`. Reverse is identical
        /// (`docker start`); only used for the user-facing note.
        was_kill: bool,
    },
    /// AU23 / DR-CR-51 — `docker pull <image>` / `docker image pull
    /// <image>`. Not destructive (image is added to the local store);
    /// captured so `shit show` can render the resolved manifest digest
    /// alongside the user-typed (often floating) tag. Pre-phase fires
    /// without journaling (no useful state to capture before the pull
    /// resolves the digest); the digest comes from the helper's
    /// post-phase handler running `docker inspect --format '{{.Id}}'`
    /// after the real pull succeeds.
    Pull { images: Vec<String> },
}

/// Classify an argv as a destructive docker verb or a tracked
/// non-destructive verb (`pull`, AU23). Returns `None` for
/// truly-read-only verbs (ps, logs, inspect, version, info, login)
/// and for argv that don't look like docker.
pub fn classify_docker_argv(argv: &[String]) -> Option<DockerVerb> {
    if argv.first().map(String::as_str) != Some("docker") {
        return None;
    }
    let idx = peel_global_flags(argv, 1);
    let verb = argv.get(idx)?;
    let rest = &argv[idx + 1..];

    match verb.as_str() {
        "rm" => classify_rm(rest),
        "rmi" => classify_rmi(rest),
        "stop" => classify_stop_or_kill(rest, false),
        "kill" => classify_stop_or_kill(rest, true),
        "pull" => classify_pull(rest),
        // `docker container <subcommand>` long form.
        "container" => match rest.first().map(String::as_str) {
            Some("rm") => classify_rm(&rest[1..]),
            Some("stop") => classify_stop_or_kill(&rest[1..], false),
            Some("kill") => classify_stop_or_kill(&rest[1..], true),
            _ => None,
        },
        // `docker image <subcommand>` long form.
        "image" => match rest.first().map(String::as_str) {
            Some("rm") => classify_rmi(&rest[1..]),
            Some("pull") => classify_pull(&rest[1..]),
            _ => None,
        },
        "volume" => match rest.first().map(String::as_str) {
            Some("rm") => classify_volume_rm(&rest[1..]),
            _ => None,
        },
        "network" => match rest.first().map(String::as_str) {
            Some("rm") => classify_network_rm(&rest[1..]),
            _ => None,
        },
        _ => None,
    }
}

/// Return whether Docker argv carries anything between the executable name
/// and the top-level verb. The initial lossless image-removal boundary does
/// not accept global flags: they can redirect the client to another daemon or
/// otherwise change capture semantics independently of the verb classifier.
pub fn has_global_prefix(argv: &[String]) -> bool {
    argv.first().map(String::as_str) == Some("docker") && peel_global_flags(argv, 1) != 1
}

/// Conservative allow-list for commands that cannot mutate container-engine
/// state. Container hook admission is default-deny: a new Docker/Podman verb
/// must be reviewed before it can bypass capture, rather than being treated as
/// read-only merely because the destructive classifier does not know it yet.
pub fn is_explicitly_read_only_argv(argv: &[String]) -> bool {
    if !matches!(argv.first().map(String::as_str), Some("docker" | "podman"))
        || peel_global_flags(argv, 1) != 1
    {
        return false;
    }
    let verb = argv.get(1).map(String::as_str);
    let subverb = argv.get(2).map(String::as_str);
    match verb {
        Some(
            "diff" | "events" | "history" | "images" | "info" | "inspect" | "logs" | "port" | "ps"
            | "search" | "stats" | "top" | "version" | "wait",
        ) => true,
        Some("container") => matches!(
            subverb,
            Some("diff" | "inspect" | "list" | "logs" | "ls" | "port" | "stats" | "top" | "wait")
        ),
        Some("image") => matches!(subverb, Some("history" | "inspect" | "list" | "ls")),
        Some("network" | "volume") => matches!(subverb, Some("inspect" | "list" | "ls")),
        Some("context") => matches!(subverb, Some("inspect" | "list" | "ls" | "show")),
        Some("system") => matches!(subverb, Some("df" | "info")),
        Some("manifest") => matches!(subverb, Some("inspect")),
        _ => false,
    }
}

/// Skip past pre-verb global flags. Mirrors the kubectl peel: pairs
/// like `--host unix:///...` count as 2, `--debug` / `--log-level=info`
/// as 1.
fn peel_global_flags(argv: &[String], start: usize) -> usize {
    let mut idx = start;
    while idx < argv.len() {
        let tok = &argv[idx];
        if tok.starts_with("--") || tok.starts_with('-') {
            if tok.contains('=') {
                idx += 1;
            } else if idx + 1 < argv.len() && !is_verb(&argv[idx + 1]) {
                idx += 2;
            } else {
                idx += 1;
            }
        } else {
            break;
        }
    }
    idx
}

fn is_verb(s: &str) -> bool {
    matches!(
        s,
        "rm" | "rmi"
            | "run"
            | "create"
            | "start"
            | "stop"
            | "kill"
            | "restart"
            | "exec"
            | "ps"
            | "logs"
            | "inspect"
            | "images"
            | "version"
            | "info"
            | "login"
            | "logout"
            | "pull"
            | "push"
            | "build"
            | "commit"
            | "save"
            | "load"
            | "tag"
            | "untag"
            | "container"
            | "image"
            | "volume"
            | "network"
            | "system"
            | "compose"
            | "artifact"
            | "buildx"
            | "builder"
            | "checkpoint"
            | "config"
            | "context"
            | "farm"
            | "kube"
            | "machine"
            | "manifest"
            | "node"
            | "plugin"
            | "pod"
            | "secret"
            | "service"
            | "stack"
            | "swarm"
            | "events"
            | "stats"
    )
}

/// Collect positional arguments using a per-verb option grammar. Unknown
/// options return `None` so the wrapper can refuse a potentially destructive
/// invocation instead of guessing whether the following token is an option
/// value or a target.
fn positionals(
    rest: &[String],
    long_bool: &[&str],
    long_value: &[&str],
    short_bool: &[u8],
    short_value: &[u8],
) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut index = 0;
    let mut positional_only = false;
    while index < rest.len() {
        let token = &rest[index];
        if positional_only || token == "-" || !token.starts_with('-') {
            out.push(token.clone());
            index += 1;
            continue;
        }
        if token == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if let Some(option) = token.strip_prefix("--") {
            let (name, inline_value) = option
                .split_once('=')
                .map_or((option, None), |(name, value)| (name, Some(value)));
            if long_bool.contains(&name) {
                index += 1;
                continue;
            }
            if long_value.contains(&name) {
                if inline_value.is_some_and(|value| !value.is_empty()) {
                    index += 1;
                } else if inline_value.is_none() && index + 1 < rest.len() {
                    index += 2;
                } else {
                    return None;
                }
                continue;
            }
            return None;
        }

        let cluster = &token.as_bytes()[1..];
        if cluster.is_empty() {
            out.push(token.clone());
            index += 1;
            continue;
        }
        let mut consumed_following_value = false;
        for (offset, flag) in cluster.iter().copied().enumerate() {
            if short_bool.contains(&flag) {
                continue;
            }
            if short_value.contains(&flag) {
                if offset + 1 == cluster.len() {
                    if index + 1 >= rest.len() {
                        return None;
                    }
                    consumed_following_value = true;
                }
                // The remainder of this token is the attached option value.
                break;
            }
            return None;
        }
        index += if consumed_following_value { 2 } else { 1 };
    }
    Some(out)
}

/// Detect the `-f` / `--force` flag anywhere in the trailing args.
fn has_force(rest: &[String]) -> bool {
    rest.iter().any(|token| {
        token == "--force"
            || token.starts_with("--force=")
            || (token.starts_with('-')
                && !token.starts_with("--")
                && token.as_bytes()[1..].contains(&b'f'))
    })
}

fn classify_rm(rest: &[String]) -> Option<DockerVerb> {
    let ids = positionals(rest, &["force", "link", "volumes"], &[], b"flv", b"")?;
    if ids.is_empty() {
        return None;
    }
    Some(DockerVerb::Rm {
        ids,
        force: has_force(rest),
    })
}

fn classify_rmi(rest: &[String]) -> Option<DockerVerb> {
    let images = positionals(rest, &["force", "no-prune"], &[], b"f", b"")?;
    if images.is_empty() {
        return None;
    }
    Some(DockerVerb::Rmi { images })
}

fn classify_volume_rm(rest: &[String]) -> Option<DockerVerb> {
    let names = positionals(rest, &["force"], &[], b"f", b"")?;
    if names.is_empty() {
        return None;
    }
    Some(DockerVerb::VolumeRm { names })
}

fn classify_network_rm(rest: &[String]) -> Option<DockerVerb> {
    let names = positionals(rest, &["force"], &[], b"f", b"")?;
    if names.is_empty() {
        return None;
    }
    Some(DockerVerb::NetworkRm { names })
}

/// AU23 — `docker pull [opts] <image> [<image> ...]`. Each positional
/// is an image reference (tag or digest); flags are skipped via
/// `positionals`. Returns `None` for `docker pull` with no positional
/// (which would error out at the real docker anyway).
fn classify_pull(rest: &[String]) -> Option<DockerVerb> {
    let images = positionals(
        rest,
        &["all-tags", "quiet", "disable-content-trust"],
        &["platform"],
        b"aq",
        b"",
    )?;
    if images.is_empty() {
        return None;
    }
    Some(DockerVerb::Pull { images })
}

fn classify_stop_or_kill(rest: &[String], was_kill: bool) -> Option<DockerVerb> {
    let ids = if was_kill {
        positionals(rest, &[], &["signal"], b"", b"s")?
    } else {
        positionals(rest, &[], &["signal", "time"], b"", b"st")?
    };
    if ids.is_empty() {
        return None;
    }
    Some(DockerVerb::StopOrKill { ids, was_kill })
}

/// Conservative guard for classifier gaps. If this returns true while the
/// typed classifier returns `None`, the wrapper must stop before invoking the
/// runtime; treating an unfamiliar destructive option as read-only would be a
/// capture bypass.
pub fn looks_potentially_destructive(argv: &[String]) -> bool {
    if !matches!(argv.first().map(String::as_str), Some("docker" | "podman")) {
        return false;
    }
    let index = peel_global_flags(argv, 1);
    let Some(verb) = argv.get(index).map(String::as_str) else {
        return false;
    };
    let subverb = argv.get(index + 1).map(String::as_str);
    match verb {
        // Podman exposes `untag` as a top-level operation. Although it often
        // leaves the underlying layers behind, it destroys the user's named
        // reference and therefore needs the same pre-image discipline as
        // `rmi`.
        "rm" | "rmi" | "remove" | "prune" | "untag" => true,

        // Docker and Podman both grow new object namespaces over time. Keep
        // this deletion-oriented safety net deliberately broader than the
        // typed capture classifier: an unsupported family must stop at the
        // wrapper instead of silently reaching the real runtime untracked.
        "artifact" | "buildx" | "builder" | "checkpoint" | "config" | "container" | "context"
        | "farm" | "image" | "machine" | "manifest" | "network" | "node" | "plugin" | "pod"
        | "secret" | "service" | "stack" | "volume" => {
            matches!(subverb, Some("rm" | "remove" | "prune" | "reset"))
        }
        "compose" => matches!(subverb, Some("down" | "rm" | "remove" | "prune")),
        "kube" => matches!(subverb, Some("down")),
        "system" => matches!(subverb, Some("prune" | "reset")),
        "swarm" => matches!(subverb, Some("leave")),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classify_rm_force_single_container() {
        let v = classify_docker_argv(&argv(&["docker", "rm", "-f", "web"]));
        assert_eq!(
            v,
            Some(DockerVerb::Rm {
                ids: vec!["web".into()],
                force: true,
            })
        );
    }

    #[test]
    fn classify_rm_force_long_form() {
        let v = classify_docker_argv(&argv(&["docker", "container", "rm", "--force", "abc123"]));
        assert_eq!(
            v,
            Some(DockerVerb::Rm {
                ids: vec!["abc123".into()],
                force: true,
            })
        );
    }

    #[test]
    fn classify_rm_multiple_ids_no_force() {
        let v = classify_docker_argv(&argv(&["docker", "rm", "c1", "c2", "c3"]));
        assert_eq!(
            v,
            Some(DockerVerb::Rm {
                ids: vec!["c1".into(), "c2".into(), "c3".into()],
                force: false,
            })
        );
    }

    #[test]
    fn classify_rm_combined_force_and_volumes_flags() {
        let v = classify_docker_argv(&argv(&["docker", "rm", "-fv", "web"]));
        assert_eq!(
            v,
            Some(DockerVerb::Rm {
                ids: vec!["web".into()],
                force: true,
            })
        );
    }

    #[test]
    fn classify_rm_no_positionals_is_none() {
        // `docker rm` alone is an error in docker too.
        let v = classify_docker_argv(&argv(&["docker", "rm", "-f"]));
        assert!(v.is_none());
    }

    #[test]
    fn classify_rmi_with_tag() {
        let v = classify_docker_argv(&argv(&["docker", "rmi", "nginx:1.25"]));
        assert_eq!(
            v,
            Some(DockerVerb::Rmi {
                images: vec!["nginx:1.25".into()]
            })
        );
    }

    #[test]
    fn classify_rmi_accepts_no_prune_boolean() {
        let v = classify_docker_argv(&argv(&["docker", "rmi", "--no-prune", "nginx:1.25"]));
        assert_eq!(
            v,
            Some(DockerVerb::Rmi {
                images: vec!["nginx:1.25".into()]
            })
        );
    }

    #[test]
    fn classify_rmi_long_form() {
        let v = classify_docker_argv(&argv(&["docker", "image", "rm", "alpine"]));
        assert_eq!(
            v,
            Some(DockerVerb::Rmi {
                images: vec!["alpine".into()]
            })
        );
    }

    #[test]
    fn detects_every_global_prefix_before_the_verb() {
        for args in [
            &[
                "docker",
                "--context",
                "remote",
                "rmi",
                "--no-prune",
                "image:v1",
            ][..],
            &["docker", "--host=tcp://example", "rmi", "image:v1"],
            &["docker", "-D", "rmi", "image:v1"],
            &["docker", "--", "rmi", "image:v1"],
        ] {
            assert!(has_global_prefix(&argv(args)), "{args:?}");
        }
        assert!(!has_global_prefix(&argv(&[
            "docker",
            "rmi",
            "--no-prune",
            "image:v1",
        ])));
    }

    #[test]
    fn read_only_allowlist_is_default_deny_and_rejects_global_prefixes() {
        for args in [
            &["docker", "ps"][..],
            &["docker", "image", "inspect", "example:v1"],
            &["docker", "context", "show"],
            &["podman", "volume", "ls"],
        ] {
            assert!(is_explicitly_read_only_argv(&argv(args)), "{args:?}");
        }
        for args in [
            &["docker", "pull", "example:v1"][..],
            &["docker", "tag", "a", "b"],
            &["docker", "load"],
            &["docker", "future-mutator", "x"],
            &["podman", "untag", "example:v1"],
            &["docker", "--context", "default", "ps"],
        ] {
            assert!(!is_explicitly_read_only_argv(&argv(args)), "{args:?}");
        }
    }

    #[test]
    fn classify_volume_rm() {
        let v = classify_docker_argv(&argv(&["docker", "volume", "rm", "pgdata"]));
        assert_eq!(
            v,
            Some(DockerVerb::VolumeRm {
                names: vec!["pgdata".into()]
            })
        );
    }

    #[test]
    fn classify_volume_rm_force_flag_passes_through() {
        let v = classify_docker_argv(&argv(&["docker", "volume", "rm", "--force", "v1"]));
        assert_eq!(
            v,
            Some(DockerVerb::VolumeRm {
                names: vec!["v1".into()]
            })
        );
    }

    #[test]
    fn classify_network_rm() {
        let v = classify_docker_argv(&argv(&["docker", "network", "rm", "frontend"]));
        assert_eq!(
            v,
            Some(DockerVerb::NetworkRm {
                names: vec!["frontend".into()]
            })
        );
    }

    #[test]
    fn classify_stop() {
        let v = classify_docker_argv(&argv(&["docker", "stop", "web"]));
        assert_eq!(
            v,
            Some(DockerVerb::StopOrKill {
                ids: vec!["web".into()],
                was_kill: false,
            })
        );
    }

    #[test]
    fn classify_kill_short_form() {
        let v = classify_docker_argv(&argv(&["docker", "kill", "web"]));
        assert_eq!(
            v,
            Some(DockerVerb::StopOrKill {
                ids: vec!["web".into()],
                was_kill: true,
            })
        );
    }

    #[test]
    fn read_only_verbs_classify_none() {
        // AU23: pull moved out of read-only into Pull-tracked.
        for verb in ["ps", "logs", "inspect", "version", "info", "images"] {
            assert!(
                classify_docker_argv(&argv(&["docker", verb])).is_none(),
                "expected None for {verb}"
            );
            assert!(
                classify_docker_argv(&argv(&["docker", verb, "x"])).is_none(),
                "expected None for {verb} x"
            );
        }
    }

    #[test]
    fn empty_or_non_docker_argv_is_none() {
        assert!(classify_docker_argv(&[]).is_none());
        assert!(classify_docker_argv(&argv(&["podman", "rm", "x"])).is_none());
        assert!(classify_docker_argv(&argv(&["docker"])).is_none());
    }

    #[test]
    fn classify_pull_single_image() {
        let v = classify_docker_argv(&argv(&["docker", "pull", "alpine:latest"]));
        assert_eq!(
            v,
            Some(DockerVerb::Pull {
                images: vec!["alpine:latest".into()],
            })
        );
    }

    #[test]
    fn classify_pull_long_form() {
        // `docker image pull alpine` — same shape as `docker image rm`.
        let v = classify_docker_argv(&argv(&["docker", "image", "pull", "alpine"]));
        assert_eq!(
            v,
            Some(DockerVerb::Pull {
                images: vec!["alpine".into()],
            })
        );
    }

    #[test]
    fn classify_pull_with_flag() {
        // `docker pull --platform linux/amd64 alpine` — flag-and-value
        // pair gets skipped by `positionals`.
        let v = classify_docker_argv(&argv(&[
            "docker",
            "pull",
            "--platform",
            "linux/amd64",
            "alpine",
        ]));
        assert_eq!(
            v,
            Some(DockerVerb::Pull {
                images: vec!["alpine".into()],
            })
        );
    }

    #[test]
    fn classify_pull_with_no_image_is_none() {
        // `docker pull` alone would error at real docker; we surface
        // None so the wrapper short-circuits cleanly.
        assert!(classify_docker_argv(&argv(&["docker", "pull"])).is_none());
    }

    #[test]
    fn pre_verb_global_flags_are_peeled() {
        // `docker --host unix:///var/run/docker.sock rm -f web`
        let v = classify_docker_argv(&argv(&[
            "docker",
            "--host",
            "unix:///var/run/docker.sock",
            "rm",
            "-f",
            "web",
        ]));
        assert_eq!(
            v,
            Some(DockerVerb::Rm {
                ids: vec!["web".into()],
                force: true,
            })
        );
    }

    #[test]
    fn equals_form_global_flag_is_one_token() {
        // `docker --log-level=debug rmi nginx`
        let v = classify_docker_argv(&argv(&["docker", "--log-level=debug", "rmi", "nginx"]));
        assert_eq!(
            v,
            Some(DockerVerb::Rmi {
                images: vec!["nginx".into()]
            })
        );
    }

    #[test]
    fn unknown_verb_classifies_none() {
        let v = classify_docker_argv(&argv(&["docker", "buildx", "prune"]));
        assert!(v.is_none());
    }

    #[test]
    fn unknown_destructive_option_is_not_treated_as_a_target() {
        let command = argv(&["docker", "rm", "--future-option", "value", "web"]);
        assert!(classify_docker_argv(&command).is_none());
        assert!(looks_potentially_destructive(&command));
    }

    #[test]
    fn prune_families_are_conservatively_destructive() {
        for command in [
            argv(&["docker", "system", "prune"]),
            argv(&["docker", "builder", "prune"]),
            argv(&["docker", "buildx", "prune"]),
            argv(&["podman", "image", "prune"]),
        ] {
            assert!(looks_potentially_destructive(&command), "{command:?}");
        }
    }

    #[test]
    fn unsupported_destructive_namespaces_fail_closed() {
        for command in [
            argv(&["docker", "service", "rm", "api"]),
            argv(&["docker", "stack", "rm", "demo"]),
            argv(&["docker", "context", "rm", "remote"]),
            argv(&["docker", "swarm", "leave", "--force"]),
            argv(&["podman", "pod", "rm", "workers"]),
            argv(&["podman", "machine", "rm", "dev"]),
            argv(&["podman", "secret", "rm", "token"]),
            argv(&["podman", "manifest", "rm", "index"]),
            argv(&["podman", "kube", "down", "app.yml"]),
            argv(&["podman", "system", "reset", "--force"]),
            argv(&["podman", "untag", "example:old"]),
        ] {
            assert!(looks_potentially_destructive(&command), "{command:?}");
        }
    }

    #[test]
    fn namespace_after_boolean_global_flag_is_not_swallowed_as_its_value() {
        assert!(looks_potentially_destructive(&argv(&[
            "docker", "--debug", "service", "rm", "api"
        ])));
        assert!(looks_potentially_destructive(&argv(&[
            "podman", "--remote", "pod", "rm", "workers"
        ])));
    }

    #[test]
    fn destructive_word_used_as_read_only_target_is_not_a_false_positive() {
        assert!(!looks_potentially_destructive(&argv(&[
            "docker", "inspect", "rm"
        ])));
    }
}

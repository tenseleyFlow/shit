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
}

/// Classify an argv as a destructive docker verb. Returns `None` for
/// read-only verbs (ps, logs, inspect, version, info, login, pull) and
/// for argv that don't look like docker.
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
            | "events"
            | "stats"
    )
}

/// Collect positional non-flag arguments (skipping pair-style flags).
/// Returns the positionals in order.
fn positionals(rest: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = rest.iter().peekable();
    while let Some(tok) = iter.next() {
        if tok.starts_with('-') {
            // Inline `--flag=value` is one token; bare `--flag value`
            // consumes the next token as its value. The flag set for
            // rm/rmi/volume-rm/network-rm is small enough that this
            // glob behaves correctly. Special-case `-f` / `--force`
            // / `-v` / `--volumes` since they take no value.
            if matches!(
                tok.as_str(),
                "-f" | "--force" | "-v" | "--volumes" | "--link"
            ) {
                continue;
            }
            if !tok.contains('=')
                && let Some(next) = iter.peek()
                && !next.starts_with('-')
            {
                iter.next();
            }
            continue;
        }
        out.push(tok.clone());
    }
    out
}

/// Detect the `-f` / `--force` flag anywhere in the trailing args.
fn has_force(rest: &[String]) -> bool {
    rest.iter().any(|t| t == "-f" || t == "--force")
}

fn classify_rm(rest: &[String]) -> Option<DockerVerb> {
    let ids = positionals(rest);
    if ids.is_empty() {
        return None;
    }
    Some(DockerVerb::Rm {
        ids,
        force: has_force(rest),
    })
}

fn classify_rmi(rest: &[String]) -> Option<DockerVerb> {
    let images = positionals(rest);
    if images.is_empty() {
        return None;
    }
    Some(DockerVerb::Rmi { images })
}

fn classify_volume_rm(rest: &[String]) -> Option<DockerVerb> {
    let names = positionals(rest);
    if names.is_empty() {
        return None;
    }
    Some(DockerVerb::VolumeRm { names })
}

fn classify_network_rm(rest: &[String]) -> Option<DockerVerb> {
    let names = positionals(rest);
    if names.is_empty() {
        return None;
    }
    Some(DockerVerb::NetworkRm { names })
}

fn classify_stop_or_kill(rest: &[String], was_kill: bool) -> Option<DockerVerb> {
    let ids = positionals(rest);
    if ids.is_empty() {
        return None;
    }
    Some(DockerVerb::StopOrKill { ids, was_kill })
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
        for verb in ["ps", "logs", "inspect", "version", "info", "images", "pull"] {
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
}

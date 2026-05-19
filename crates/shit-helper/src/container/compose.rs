// SPDX-License-Identifier: AGPL-3.0-or-later

//! docker-compose argv classifier — C04.4.
//!
//! Two binary shapes are accepted:
//!
//! - `docker-compose <verb> ...` (the standalone v1 binary, still
//!   ubiquitous in CI).
//! - `docker compose <verb> ...` (the v2 plugin shipped with modern
//!   Docker Desktop / Docker CE; `docker` argv[0] + `compose` argv[1]
//!   in the front position).
//!
//! Classifier returns a `ComposeVerb` carrying only the flag-level
//! shape: which file(s) were passed via `-f`, whether `--project-name`
//! / `-p` was overridden, and (for `down`) whether `-v` /
//! `--volumes` was set. The actual per-service expansion happens at
//! daemon-side capture time by shelling `docker compose config
//! --services` (DR-CR-26); the helper-side parser intentionally does
//! NOT pull in a YAML dependency just to enumerate service names.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeVerb {
    /// `docker compose down [-v|--volumes]`. Reverse: `docker compose
    /// up -d` (volume recreation from stashes is opt-in via
    /// `shit undo --restore-volumes` when `with_volumes` was true).
    Down {
        files: Vec<String>,
        project_override: Option<String>,
        with_volumes: bool,
    },
    /// `docker compose up [-d]`. Capture only that the project came
    /// up; reverse is `docker compose down`. The detached flag is
    /// preserved on reverse so we don't accidentally daemonize at
    /// undo time.
    Up {
        files: Vec<String>,
        project_override: Option<String>,
        detached: bool,
    },
    /// `docker compose stop [<service>...]`. Restart-hint only;
    /// reverse is `docker compose start`.
    Stop {
        files: Vec<String>,
        project_override: Option<String>,
        services: Vec<String>,
    },
    /// `docker compose rm [-f|--force] [-s|--stop] [-v|--volumes]
    /// [<service>...]`. The wrapper inspects each service's container
    /// IDs and routes through the docker rm capture path.
    Rm {
        files: Vec<String>,
        project_override: Option<String>,
        services: Vec<String>,
        force: bool,
        with_volumes: bool,
    },
}

/// Classify an argv as a destructive docker-compose verb. Returns
/// `None` for read-only verbs (ps/logs/config/version) and for argv
/// that don't look like docker-compose.
pub fn classify_compose_argv(argv: &[String]) -> Option<ComposeVerb> {
    let (verb_idx, head) = peel_binary_and_global_flags(argv)?;
    let (files, project_override, verb_idx) = peel_compose_flags(argv, verb_idx);
    let verb = argv.get(verb_idx)?;
    let rest = &argv[verb_idx + 1..];

    match (head, verb.as_str()) {
        (_, "down") => Some(ComposeVerb::Down {
            files,
            project_override,
            with_volumes: has_flag(rest, &["-v", "--volumes"]),
        }),
        (_, "up") => Some(ComposeVerb::Up {
            files,
            project_override,
            detached: has_flag(rest, &["-d", "--detach"]),
        }),
        (_, "stop") => Some(ComposeVerb::Stop {
            files,
            project_override,
            services: positionals(rest),
        }),
        (_, "rm") => Some(ComposeVerb::Rm {
            files,
            project_override,
            services: positionals(rest),
            force: has_flag(rest, &["-f", "--force"]),
            with_volumes: has_flag(rest, &["-v", "--volumes"]),
        }),
        _ => None,
    }
}

/// Identifies which binary shape we're looking at. Used only for
/// reporting; the verb-parsing logic is the same for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComposeHead {
    Standalone,    // docker-compose ...
    DockerCompose, // docker compose ...
}

/// Returns `(idx_of_verb_after_compose_flags_unpeeled, head_kind)`.
/// Errors if argv[0] isn't a recognized binary.
fn peel_binary_and_global_flags(argv: &[String]) -> Option<(usize, ComposeHead)> {
    let head_token = argv.first()?.as_str();
    let (head, mut idx) = match head_token {
        "docker-compose" => (ComposeHead::Standalone, 1),
        "docker" => {
            // Skip any pre-`compose` global flags. `docker --host ...
            // compose down` is legal.
            let mut i = 1;
            while i < argv.len() {
                let tok = &argv[i];
                if tok == "compose" {
                    i += 1;
                    break;
                }
                if tok.starts_with('-') {
                    if tok.contains('=') {
                        i += 1;
                    } else if i + 1 < argv.len() && argv[i + 1] != "compose" {
                        i += 2;
                    } else {
                        i += 1;
                    }
                } else {
                    // First positional that isn't `compose` → not us.
                    return None;
                }
            }
            (ComposeHead::DockerCompose, i)
        }
        _ => return None,
    };
    // Strip any compose-side pre-verb global flags that are NOT
    // `-f` / `-p` (those land in `peel_compose_flags`).
    while idx < argv.len() {
        let tok = &argv[idx];
        if tok == "-f"
            || tok == "--file"
            || tok == "-p"
            || tok == "--project-name"
            || tok.starts_with("--file=")
            || tok.starts_with("--project-name=")
        {
            break;
        }
        if tok.starts_with("--") || tok.starts_with('-') {
            if tok.contains('=') {
                idx += 1;
            } else if idx + 1 < argv.len() && !is_compose_verb(&argv[idx + 1]) {
                idx += 2;
            } else {
                idx += 1;
            }
        } else {
            break;
        }
    }
    Some((idx, head))
}

fn is_compose_verb(s: &str) -> bool {
    matches!(
        s,
        "up" | "down"
            | "start"
            | "stop"
            | "restart"
            | "rm"
            | "ps"
            | "logs"
            | "config"
            | "version"
            | "build"
            | "pull"
            | "exec"
            | "run"
            | "kill"
            | "pause"
            | "unpause"
            | "top"
            | "events"
            | "port"
            | "images"
    )
}

/// Consume the file (`-f`) and project (`-p`) flags that may appear
/// in any order before the verb. Returns `(files, project, new_idx)`.
fn peel_compose_flags(argv: &[String], start: usize) -> (Vec<String>, Option<String>, usize) {
    let mut files = Vec::new();
    let mut project = None;
    let mut idx = start;
    while idx < argv.len() {
        let tok = &argv[idx];
        match tok.as_str() {
            "-f" | "--file" => {
                if let Some(v) = argv.get(idx + 1) {
                    files.push(v.clone());
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            s if s.starts_with("--file=") => {
                files.push(s["--file=".len()..].to_string());
                idx += 1;
            }
            "-p" | "--project-name" => {
                if let Some(v) = argv.get(idx + 1) {
                    project = Some(v.clone());
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            s if s.starts_with("--project-name=") => {
                project = Some(s["--project-name=".len()..].to_string());
                idx += 1;
            }
            _ => break,
        }
    }
    (files, project, idx)
}

fn has_flag(rest: &[String], names: &[&str]) -> bool {
    rest.iter().any(|t| names.contains(&t.as_str()))
}

fn positionals(rest: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = rest.iter().peekable();
    while let Some(tok) = iter.next() {
        if tok.starts_with('-') {
            // Same simple peel as docker.rs; the compose-side rm/up/down
            // flags we care about are no-value (-d / -v / -f / --force /
            // --volumes / --detach / --remove-orphans).
            if matches!(
                tok.as_str(),
                "-d" | "--detach"
                    | "-v"
                    | "--volumes"
                    | "-f"
                    | "--force"
                    | "-s"
                    | "--stop"
                    | "--remove-orphans"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn down_standalone_binary() {
        let v = classify_compose_argv(&argv(&["docker-compose", "down"]));
        assert_eq!(
            v,
            Some(ComposeVerb::Down {
                files: vec![],
                project_override: None,
                with_volumes: false,
            })
        );
    }

    #[test]
    fn down_docker_compose_plugin_form() {
        let v = classify_compose_argv(&argv(&["docker", "compose", "down"]));
        assert_eq!(
            v,
            Some(ComposeVerb::Down {
                files: vec![],
                project_override: None,
                with_volumes: false,
            })
        );
    }

    #[test]
    fn down_with_volumes_flag() {
        let v = classify_compose_argv(&argv(&["docker", "compose", "down", "-v"]));
        assert_eq!(
            v,
            Some(ComposeVerb::Down {
                files: vec![],
                project_override: None,
                with_volumes: true,
            })
        );
    }

    #[test]
    fn down_with_volumes_long_form() {
        let v = classify_compose_argv(&argv(&["docker-compose", "down", "--volumes"]));
        assert_eq!(
            v,
            Some(ComposeVerb::Down {
                files: vec![],
                project_override: None,
                with_volumes: true,
            })
        );
    }

    #[test]
    fn down_with_file_and_project_override() {
        let v = classify_compose_argv(&argv(&[
            "docker",
            "compose",
            "-f",
            "stack.yml",
            "-p",
            "myapp",
            "down",
        ]));
        assert_eq!(
            v,
            Some(ComposeVerb::Down {
                files: vec!["stack.yml".into()],
                project_override: Some("myapp".into()),
                with_volumes: false,
            })
        );
    }

    #[test]
    fn down_with_multiple_files() {
        let v = classify_compose_argv(&argv(&[
            "docker-compose",
            "-f",
            "base.yml",
            "-f",
            "prod.yml",
            "down",
        ]));
        assert_eq!(
            v,
            Some(ComposeVerb::Down {
                files: vec!["base.yml".into(), "prod.yml".into()],
                project_override: None,
                with_volumes: false,
            })
        );
    }

    #[test]
    fn down_equals_form_file_flag() {
        let v = classify_compose_argv(&argv(&[
            "docker",
            "compose",
            "--file=docker-compose.yml",
            "down",
        ]));
        assert_eq!(
            v,
            Some(ComposeVerb::Down {
                files: vec!["docker-compose.yml".into()],
                project_override: None,
                with_volumes: false,
            })
        );
    }

    #[test]
    fn up_detached_classifies() {
        let v = classify_compose_argv(&argv(&["docker", "compose", "up", "-d"]));
        assert_eq!(
            v,
            Some(ComposeVerb::Up {
                files: vec![],
                project_override: None,
                detached: true,
            })
        );
    }

    #[test]
    fn stop_with_services() {
        let v = classify_compose_argv(&argv(&["docker-compose", "stop", "web", "worker"]));
        assert_eq!(
            v,
            Some(ComposeVerb::Stop {
                files: vec![],
                project_override: None,
                services: vec!["web".into(), "worker".into()],
            })
        );
    }

    #[test]
    fn rm_force_with_volumes_and_services() {
        let v = classify_compose_argv(&argv(&["docker", "compose", "rm", "-f", "-v", "web", "db"]));
        assert_eq!(
            v,
            Some(ComposeVerb::Rm {
                files: vec![],
                project_override: None,
                services: vec!["web".into(), "db".into()],
                force: true,
                with_volumes: true,
            })
        );
    }

    #[test]
    fn read_only_verbs_classify_none() {
        for verb in ["ps", "logs", "config", "version", "build"] {
            assert!(
                classify_compose_argv(&argv(&["docker-compose", verb])).is_none(),
                "expected None for {verb}"
            );
            assert!(
                classify_compose_argv(&argv(&["docker", "compose", verb])).is_none(),
                "expected None for {verb}"
            );
        }
    }

    #[test]
    fn docker_run_does_not_match_compose() {
        // `docker run` (no `compose`) must not match — that's the
        // docker classifier's territory.
        let v = classify_compose_argv(&argv(&["docker", "run", "alpine"]));
        assert!(v.is_none());
    }

    #[test]
    fn docker_with_host_then_compose_down() {
        // Pre-`compose` global flags should be peeled.
        let v = classify_compose_argv(&argv(&[
            "docker",
            "--host",
            "unix:///var/run/docker.sock",
            "compose",
            "down",
        ]));
        assert_eq!(
            v,
            Some(ComposeVerb::Down {
                files: vec![],
                project_override: None,
                with_volumes: false,
            })
        );
    }

    #[test]
    fn empty_or_unrelated_argv_is_none() {
        assert!(classify_compose_argv(&[]).is_none());
        assert!(classify_compose_argv(&argv(&["podman-compose", "down"])).is_none());
        assert!(classify_compose_argv(&argv(&["docker-compose"])).is_none());
    }
}

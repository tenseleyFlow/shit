// SPDX-License-Identifier: AGPL-3.0-or-later

//! podman argv classifier — C04.3.
//!
//! Podman is intentionally docker-API-compatible at the CLI surface
//! for every verb we care about (`rm` / `rmi` / `volume rm` / `network
//! rm` / `stop` / `kill`). The classifier swaps `argv[0]` from
//! `"podman"` to `"docker"`, calls into the docker classifier, and
//! returns the result re-typed as a `PodmanVerb`. The 1:1 mapping is
//! intentional — the runtime-side identity lives on
//! `InverseOp::ContainerRestore::runtime`, not on the verb shape.
//!
//! Rootless mode (podman's default) doesn't change verb syntax; the
//! capture-time daemon route uses `podman info --format json` to
//! discover the rootless storage roots, but that's executor-side
//! (C04.5), not classifier-side.

use super::docker::{DockerVerb, classify_docker_argv};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodmanVerb {
    Rm {
        ids: Vec<String>,
        force: bool,
    },
    Rmi {
        images: Vec<String>,
    },
    VolumeRm {
        names: Vec<String>,
    },
    NetworkRm {
        names: Vec<String>,
    },
    StopOrKill {
        ids: Vec<String>,
        was_kill: bool,
    },
    /// AU23 — `podman pull <image>`. Same semantics as docker pull;
    /// helper post-handler captures the resolved digest via
    /// `podman inspect --format '{{.Id}}'`.
    Pull {
        images: Vec<String>,
    },
}

impl From<DockerVerb> for PodmanVerb {
    fn from(v: DockerVerb) -> Self {
        match v {
            DockerVerb::Rm { ids, force } => Self::Rm { ids, force },
            DockerVerb::Rmi { images } => Self::Rmi { images },
            DockerVerb::VolumeRm { names } => Self::VolumeRm { names },
            DockerVerb::NetworkRm { names } => Self::NetworkRm { names },
            DockerVerb::StopOrKill { ids, was_kill } => Self::StopOrKill { ids, was_kill },
            DockerVerb::Pull { images } => Self::Pull { images },
        }
    }
}

/// Classify an argv as a destructive podman verb. Returns `None` for
/// read-only verbs and for argv that don't look like podman.
pub fn classify_podman_argv(argv: &[String]) -> Option<PodmanVerb> {
    if argv.first().map(String::as_str) != Some("podman") {
        return None;
    }
    // Swap argv[0] to "docker" and delegate. The allocation is once
    // per destructive verb invocation; container ops are not a hot
    // path so the simpler-shared-code wins over avoiding the clone.
    let mut translated = Vec::with_capacity(argv.len());
    translated.push("docker".to_string());
    translated.extend_from_slice(&argv[1..]);
    classify_docker_argv(&translated).map(PodmanVerb::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn rm_force_classifies_as_podman_rm() {
        let v = classify_podman_argv(&argv(&["podman", "rm", "-f", "web"]));
        assert_eq!(
            v,
            Some(PodmanVerb::Rm {
                ids: vec!["web".into()],
                force: true,
            })
        );
    }

    #[test]
    fn rmi_classifies_as_podman_rmi() {
        let v = classify_podman_argv(&argv(&["podman", "rmi", "alpine:3.20"]));
        assert_eq!(
            v,
            Some(PodmanVerb::Rmi {
                images: vec!["alpine:3.20".into()]
            })
        );
    }

    #[test]
    fn volume_rm_long_form() {
        let v = classify_podman_argv(&argv(&["podman", "volume", "rm", "pgdata"]));
        assert_eq!(
            v,
            Some(PodmanVerb::VolumeRm {
                names: vec!["pgdata".into()]
            })
        );
    }

    #[test]
    fn network_rm_classifies() {
        let v = classify_podman_argv(&argv(&["podman", "network", "rm", "frontend"]));
        assert_eq!(
            v,
            Some(PodmanVerb::NetworkRm {
                names: vec!["frontend".into()]
            })
        );
    }

    #[test]
    fn stop_classifies_with_was_kill_false() {
        let v = classify_podman_argv(&argv(&["podman", "stop", "web"]));
        assert_eq!(
            v,
            Some(PodmanVerb::StopOrKill {
                ids: vec!["web".into()],
                was_kill: false,
            })
        );
    }

    #[test]
    fn kill_classifies_with_was_kill_true() {
        let v = classify_podman_argv(&argv(&["podman", "kill", "web"]));
        assert_eq!(
            v,
            Some(PodmanVerb::StopOrKill {
                ids: vec!["web".into()],
                was_kill: true,
            })
        );
    }

    #[test]
    fn read_only_verbs_classify_none() {
        for verb in ["ps", "logs", "inspect", "images", "info"] {
            assert!(classify_podman_argv(&argv(&["podman", verb])).is_none());
            assert!(classify_podman_argv(&argv(&["podman", verb, "x"])).is_none());
        }
    }

    #[test]
    fn docker_argv_does_not_match_podman_classifier() {
        // Containment check: a `docker` argv should not be misclassified
        // by `classify_podman_argv`. The per-binary checks must be tight
        // so the wrappers don't double-capture.
        let v = classify_podman_argv(&argv(&["docker", "rm", "-f", "web"]));
        assert!(v.is_none());
    }

    #[test]
    fn rootless_remote_flag_passes_through() {
        // `podman --remote rm -f web` — global flag peeled, verb matches.
        let v = classify_podman_argv(&argv(&["podman", "--remote", "rm", "-f", "web"]));
        assert_eq!(
            v,
            Some(PodmanVerb::Rm {
                ids: vec!["web".into()],
                force: true,
            })
        );
    }

    #[test]
    fn empty_or_short_argv_is_none() {
        assert!(classify_podman_argv(&[]).is_none());
        assert!(classify_podman_argv(&argv(&["podman"])).is_none());
    }
}

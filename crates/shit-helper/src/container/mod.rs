// SPDX-License-Identifier: AGPL-3.0-or-later

// C04 container-runtime capture (docker/podman/compose). Each
// submodule owns a per-tool argv classifier — the verbs we want to
// snapshot before they run (rm/rmi/volume-rm/network-rm/...). The
// helper's capture hook invokes `shit-helper container-event <tool>
// <pre|post>` (gated on DR-CR-26 — the daemon-side pairing matches
// the cloud-event pattern from C03).
//
// Stage 1 ships the parsers + argv classifiers; the helper CLI
// subcommand and the docker-commit / docker-save / volume-tar
// stashing path are deferred to the same wave as DR-CR-11/16.
#![allow(dead_code)]

pub mod compose;
pub mod docker;
pub mod podman;

#[allow(unused_imports)]
pub use compose::{ComposeVerb, classify_compose_argv};
#[allow(unused_imports)]
pub use docker::{DockerVerb, classify_docker_argv};
#[allow(unused_imports)]
pub use podman::{PodmanVerb, classify_podman_argv};

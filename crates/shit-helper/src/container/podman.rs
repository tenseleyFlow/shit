// SPDX-License-Identifier: AGPL-3.0-or-later

//! podman argv classifier — stub. C04.3 fills this in by delegating
//! to the docker classifier (podman is API-compatible enough that the
//! verb shapes overlap completely for rm/rmi/volume-rm/network-rm).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodmanVerb {
    /// Re-uses the docker verb shape; C04.3 wires the actual classifier.
    PlaceholderForC04_3,
}

pub fn classify_podman_argv(_argv: &[String]) -> Option<PodmanVerb> {
    None
}

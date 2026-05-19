// SPDX-License-Identifier: AGPL-3.0-or-later

//! docker-compose argv classifier — stub. C04.4 parses the compose
//! file (docker-compose.yml / compose.yaml) for the service list and
//! emits per-service Rm captures grouped by project.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeVerb {
    /// Placeholder; C04.4 fills in `Down { project, services, file,
    /// with_volumes }` and the parser path.
    PlaceholderForC04_4,
}

pub fn classify_compose_argv(_argv: &[String]) -> Option<ComposeVerb> {
    None
}

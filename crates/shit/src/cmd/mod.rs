// SPDX-License-Identifier: AGPL-3.0-or-later

//! Subcommand bodies. The CLI parser lives in `main.rs`; each
//! subcommand's *behavior* lives here.

pub mod auto_inject;
pub mod bookmark;
pub mod cloud_hooks;
pub mod completions;
pub mod config;
pub mod container_hooks;
pub mod container_stashes;
pub mod ctl_client;
pub mod db_hooks;
pub mod descriptors;
pub mod disable;
pub mod forget;
pub mod gc;
pub mod install;
pub mod list;
pub mod manpages;
pub mod metrics;
pub mod net_hooks;
pub mod no_protect;
pub mod pin;
pub mod pkg_hooks;
pub mod proc_hooks;
pub mod redo;
pub mod show;
pub mod svc_hooks;
pub mod undo;

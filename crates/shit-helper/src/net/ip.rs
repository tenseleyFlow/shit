// SPDX-License-Identifier: AGPL-3.0-or-later

//! ip (Linux) inspector (S17.8).
//!
//! Linux's `ip` command splits naturally by object (`route`,
//! `addr`, `link`). The wrapper passes the object via the dispatch
//! kind ([`NetToolWire::IpRoute`] / `IpAddr` / `IpLink`); the
//! inspector captures `ip -j <object> show` for the requested
//! object.
//!
//! The `-j` (JSON) form is stable across iproute2 versions and
//! parses cleanly. The planner-side executor diffs the captured
//! JSON to synthesize `ip ... add` / `... del` invocations
//! (this is the `RestoreMethod::DiffApply` path — there's no
//! atomic `ip-restore`).

use std::process::Command;

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct IpInspector {
    pub object: IpObject,
}

#[derive(Debug, Clone, Copy)]
pub enum IpObject {
    Route,
    Addr,
    Link,
}

impl IpObject {
    fn arg(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::Addr => "addr",
            Self::Link => "link",
        }
    }
}

impl IpInspector {
    pub fn for_object(t: NetToolWire) -> Self {
        let object = match t {
            NetToolWire::IpAddr => IpObject::Addr,
            NetToolWire::IpLink => IpObject::Link,
            _ => IpObject::Route,
        };
        Self { object }
    }
}

impl NetInspector for IpInspector {
    fn tool(&self) -> NetToolWire {
        match self.object {
            IpObject::Route => NetToolWire::IpRoute,
            IpObject::Addr => NetToolWire::IpAddr,
            IpObject::Link => NetToolWire::IpLink,
        }
    }
    fn collect_state(&self, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        let out = Command::new("ip")
            .args(["-j", self.object.arg(), "show"])
            .output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "ip -j {} show exited {:?}: {}",
                self.object.arg(),
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_object_maps_correctly() {
        assert!(matches!(
            IpInspector::for_object(NetToolWire::IpAddr).object,
            IpObject::Addr
        ));
        assert!(matches!(
            IpInspector::for_object(NetToolWire::IpLink).object,
            IpObject::Link
        ));
        assert!(matches!(
            IpInspector::for_object(NetToolWire::IpRoute).object,
            IpObject::Route
        ));
    }

    #[test]
    fn object_arg_strings_stable() {
        assert_eq!(IpObject::Route.arg(), "route");
        assert_eq!(IpObject::Addr.arg(), "addr");
        assert_eq!(IpObject::Link.arg(), "link");
    }
}

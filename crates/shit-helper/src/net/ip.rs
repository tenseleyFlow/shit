// SPDX-License-Identifier: AGPL-3.0-or-later

//! ip (Linux) inspector (S17.8 fills in real `ip -j` capture).

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
        Ok(Vec::new())
    }
}

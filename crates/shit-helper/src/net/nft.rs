// SPDX-License-Identifier: AGPL-3.0-or-later

//! nft inspector (S17.5).
//!
//! State capture runs `nft list ruleset -a`. The `-a` flag includes
//! rule handles so the executor can issue precise deletes; the
//! standard reload path is simpler — `nft flush ruleset; nft -f
//! <dump>` — but the handles travel along in the dump for free.
//!
//! nft's transaction semantics are atomic by design — `nft -f`
//! applies the whole file in one kernel transaction or rolls back.
//! That's the only undo path that's safe under live traffic.

use std::process::Command;

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct NftInspector;

impl NetInspector for NftInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Nft
    }
    fn collect_state(&self, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        let out = Command::new("nft")
            .args(["list", "ruleset", "-a"])
            .output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "nft list exited {:?}: {}",
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
    fn nft_tool() {
        assert_eq!(NftInspector.tool(), NetToolWire::Nft);
    }
}

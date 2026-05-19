// SPDX-License-Identifier: AGPL-3.0-or-later

//! terraform argv classifier — used by the capture hook to decide
//! whether an invocation needs pre-state snapshotting via
//! `terraform state pull`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerraformVerb {
    Apply,
    Destroy,
    StateRm { addr: String },
    Import { addr: String, id: String },
}

pub fn classify_terraform_argv(argv: &[String]) -> Option<TerraformVerb> {
    if argv.first().map(String::as_str) != Some("terraform") {
        return None;
    }
    let verb = argv.get(1)?;
    let rest = &argv[2..];
    match verb.as_str() {
        "apply" => Some(TerraformVerb::Apply),
        "destroy" => Some(TerraformVerb::Destroy),
        "state" => {
            // `terraform state rm <addr>` or `terraform state push|pull|...`.
            let sub = rest.first()?;
            if sub == "rm" {
                let addr = rest.iter().skip(1).find(|t| !t.starts_with('-'))?.clone();
                Some(TerraformVerb::StateRm { addr })
            } else {
                None
            }
        }
        "import" => {
            // `terraform import [opts] <addr> <id>`. Two positional after flags.
            let positional: Vec<&String> = rest.iter().filter(|t| !t.starts_with('-')).collect();
            if positional.len() < 2 {
                return None;
            }
            Some(TerraformVerb::Import {
                addr: positional[0].clone(),
                id: positional[1].clone(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn non_terraform_returns_none() {
        assert!(classify_terraform_argv(&argv(&["aws", "apply"])).is_none());
    }

    #[test]
    fn apply_classified() {
        assert_eq!(
            classify_terraform_argv(&argv(&["terraform", "apply"])),
            Some(TerraformVerb::Apply)
        );
    }

    #[test]
    fn apply_with_auto_approve_classified() {
        assert_eq!(
            classify_terraform_argv(&argv(&["terraform", "apply", "-auto-approve"])),
            Some(TerraformVerb::Apply)
        );
    }

    #[test]
    fn destroy_classified() {
        assert_eq!(
            classify_terraform_argv(&argv(&["terraform", "destroy"])),
            Some(TerraformVerb::Destroy)
        );
    }

    #[test]
    fn state_rm_classified() {
        let v =
            classify_terraform_argv(&argv(&["terraform", "state", "rm", "aws_instance.example"]))
                .unwrap();
        assert_eq!(
            v,
            TerraformVerb::StateRm {
                addr: "aws_instance.example".into()
            }
        );
    }

    #[test]
    fn state_push_returns_none() {
        // state push is not destructive in the same way as state rm
        // (it's normally used during recovery); skip.
        assert!(
            classify_terraform_argv(&argv(&["terraform", "state", "push", "x.tfstate"])).is_none()
        );
    }

    #[test]
    fn import_classified() {
        let v = classify_terraform_argv(&argv(&[
            "terraform",
            "import",
            "aws_instance.example",
            "i-abc",
        ]))
        .unwrap();
        assert_eq!(
            v,
            TerraformVerb::Import {
                addr: "aws_instance.example".into(),
                id: "i-abc".into()
            }
        );
    }

    #[test]
    fn import_with_flags_classified() {
        let v = classify_terraform_argv(&argv(&[
            "terraform",
            "import",
            "-input=false",
            "aws_instance.example",
            "i-abc",
        ]))
        .unwrap();
        assert!(matches!(v, TerraformVerb::Import { .. }));
    }

    #[test]
    fn plan_returns_none() {
        // plan is read-only; no capture.
        assert!(classify_terraform_argv(&argv(&["terraform", "plan"])).is_none());
    }
}

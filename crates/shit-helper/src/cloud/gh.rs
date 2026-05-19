// SPDX-License-Identifier: AGPL-3.0-or-later

//! gh-cli argv classifier — used by the capture hook to decide
//! whether an invocation needs pre-state snapshotting.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhVerb {
    ReleaseDelete { tag: String },
    ReleaseDeleteAsset { tag: String, asset: String },
    IssueClose { number: u64 },
    PrClose { number: u64 },
}

pub fn classify_gh_argv(argv: &[String]) -> Option<GhVerb> {
    if argv.first().map(String::as_str) != Some("gh") {
        return None;
    }
    // gh's verb structure is `gh <noun> <action> [args...]`. We match
    // on (noun, action) and skip positional args after.
    let noun = argv.get(1)?;
    let action = argv.get(2)?;
    let rest = &argv[3..];
    match (noun.as_str(), action.as_str()) {
        ("release", "delete") => {
            let tag = first_positional(rest)?;
            Some(GhVerb::ReleaseDelete { tag })
        }
        ("release", "delete-asset") => {
            // Two positional: tag, asset.
            let positionals: Vec<&String> = rest.iter().filter(|t| !t.starts_with('-')).collect();
            let tag = positionals.first()?.to_string();
            let asset = positionals.get(1)?.to_string();
            Some(GhVerb::ReleaseDeleteAsset { tag, asset })
        }
        ("issue", "close") => {
            let n: u64 = first_positional(rest)?.parse().ok()?;
            Some(GhVerb::IssueClose { number: n })
        }
        ("pr", "close") => {
            let n: u64 = first_positional(rest)?.parse().ok()?;
            Some(GhVerb::PrClose { number: n })
        }
        _ => None,
    }
}

fn first_positional(rest: &[String]) -> Option<String> {
    rest.iter().find(|t| !t.starts_with('-')).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn non_gh_returns_none() {
        assert!(classify_gh_argv(&argv(&["aws", "release", "delete", "v1"])).is_none());
    }

    #[test]
    fn unrecognized_noun_returns_none() {
        assert!(classify_gh_argv(&argv(&["gh", "repo", "view"])).is_none());
    }

    #[test]
    fn release_delete_classified() {
        let v = classify_gh_argv(&argv(&["gh", "release", "delete", "v1.0"])).unwrap();
        assert_eq!(v, GhVerb::ReleaseDelete { tag: "v1.0".into() });
    }

    #[test]
    fn release_delete_with_yes_flag_still_classified() {
        let v = classify_gh_argv(&argv(&["gh", "release", "delete", "v1.0", "--yes"])).unwrap();
        assert_eq!(v, GhVerb::ReleaseDelete { tag: "v1.0".into() });
    }

    #[test]
    fn release_delete_asset_classified() {
        let v = classify_gh_argv(&argv(&[
            "gh",
            "release",
            "delete-asset",
            "v1",
            "shit-x86_64.tar.gz",
        ]))
        .unwrap();
        assert_eq!(
            v,
            GhVerb::ReleaseDeleteAsset {
                tag: "v1".into(),
                asset: "shit-x86_64.tar.gz".into()
            }
        );
    }

    #[test]
    fn issue_close_classified() {
        let v = classify_gh_argv(&argv(&["gh", "issue", "close", "42"])).unwrap();
        assert_eq!(v, GhVerb::IssueClose { number: 42 });
    }

    #[test]
    fn pr_close_classified() {
        let v = classify_gh_argv(&argv(&["gh", "pr", "close", "7"])).unwrap();
        assert_eq!(v, GhVerb::PrClose { number: 7 });
    }

    #[test]
    fn issue_close_non_numeric_returns_none() {
        // gh accepts URL forms; we don't try to parse those in v1.
        assert!(
            classify_gh_argv(&argv(&[
                "gh",
                "issue",
                "close",
                "https://github.com/o/r/issues/9"
            ]))
            .is_none()
        );
    }

    #[test]
    fn read_only_verbs_return_none() {
        for parts in [
            ["gh", "release", "view", "v1"].as_slice(),
            &["gh", "issue", "view", "1"],
            &["gh", "pr", "view", "1"],
        ] {
            assert!(classify_gh_argv(&argv(parts)).is_none(), "{parts:?}");
        }
    }
}

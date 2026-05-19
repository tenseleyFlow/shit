// SPDX-License-Identifier: AGPL-3.0-or-later

//! aws-cli argv classifier — used by the capture hook to decide
//! whether an invocation needs pre-state snapshotting. Covers
//! `aws s3 cp/rm` and `aws ec2 terminate-instances/stop-instances`
//! in v1; iam and other services are out-of-scope.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsVerb {
    S3Cp {
        /// The remote bucket. For `cp local s3://bucket/key`, this is "bucket";
        /// for `cp s3://bucket/key local`, this is also "bucket" — but the
        /// classifier returns `None` for download (no remote mutation).
        bucket: String,
        key: String,
    },
    S3Rm {
        bucket: String,
        key: String,
    },
    Ec2Terminate {
        instance_ids: Vec<String>,
    },
    Ec2Stop {
        instance_ids: Vec<String>,
    },
}

pub fn classify_aws_argv(argv: &[String]) -> Option<AwsVerb> {
    if argv.first().map(String::as_str) != Some("aws") {
        return None;
    }
    let service = argv.get(1)?;
    let verb = argv.get(2)?;
    let rest = &argv[3..];
    match (service.as_str(), verb.as_str()) {
        ("s3", "cp") => classify_s3_cp(rest),
        ("s3", "rm") => classify_s3_rm(rest),
        ("ec2", "terminate-instances") => classify_ec2_action(rest, true),
        ("ec2", "stop-instances") => classify_ec2_action(rest, false),
        _ => None,
    }
}

fn classify_s3_cp(rest: &[String]) -> Option<AwsVerb> {
    // Two arg shapes:
    //   aws s3 cp <local> s3://bucket/key   (upload — mutation, capture)
    //   aws s3 cp s3://bucket/key <local>   (download — no mutation, skip)
    // We accept the upload form; downloads return None.
    let positional: Vec<&String> = rest.iter().filter(|t| !t.starts_with('-')).collect();
    if positional.len() < 2 {
        return None;
    }
    let src = positional[0];
    let dst = positional[1];
    let dst_remote = parse_s3_uri(dst);
    let src_remote = parse_s3_uri(src);
    match (src_remote, dst_remote) {
        (None, Some((bucket, key))) => Some(AwsVerb::S3Cp { bucket, key }),
        // download (no mutation), or s3-to-s3 (out of v1 scope) — skip
        _ => None,
    }
}

fn classify_s3_rm(rest: &[String]) -> Option<AwsVerb> {
    let positional: Vec<&String> = rest.iter().filter(|t| !t.starts_with('-')).collect();
    let target = positional.first()?;
    let (bucket, key) = parse_s3_uri(target)?;
    Some(AwsVerb::S3Rm { bucket, key })
}

fn classify_ec2_action(rest: &[String], terminate: bool) -> Option<AwsVerb> {
    // Look for `--instance-ids X Y Z`. The IDs follow as positional
    // tokens until the next flag.
    let mut iter = rest.iter();
    while let Some(tok) = iter.next() {
        if tok == "--instance-ids" {
            let mut ids = Vec::new();
            for next in iter.by_ref() {
                if next.starts_with('-') {
                    break;
                }
                ids.push(next.clone());
            }
            if ids.is_empty() {
                return None;
            }
            return Some(if terminate {
                AwsVerb::Ec2Terminate { instance_ids: ids }
            } else {
                AwsVerb::Ec2Stop { instance_ids: ids }
            });
        }
    }
    None
}

fn parse_s3_uri(s: &str) -> Option<(String, String)> {
    let rest = s.strip_prefix("s3://")?;
    let (bucket, key) = rest.split_once('/')?;
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some((bucket.to_string(), key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn non_aws_returns_none() {
        assert!(classify_aws_argv(&argv(&["echo", "s3", "cp"])).is_none());
    }

    #[test]
    fn s3_upload_classified() {
        let v = classify_aws_argv(&argv(&["aws", "s3", "cp", "local.txt", "s3://b/k"])).unwrap();
        assert_eq!(
            v,
            AwsVerb::S3Cp {
                bucket: "b".into(),
                key: "k".into()
            }
        );
    }

    #[test]
    fn s3_download_returns_none() {
        // Download from S3 doesn't mutate the remote; no capture needed.
        assert!(classify_aws_argv(&argv(&["aws", "s3", "cp", "s3://b/k", "local.txt"])).is_none());
    }

    #[test]
    fn s3_s3_returns_none() {
        // s3-to-s3 copy: mutation on dst but classifier limits to local-to-remote in v1.
        assert!(classify_aws_argv(&argv(&["aws", "s3", "cp", "s3://a/x", "s3://b/y"])).is_none());
    }

    #[test]
    fn s3_rm_classified() {
        let v = classify_aws_argv(&argv(&["aws", "s3", "rm", "s3://b/k"])).unwrap();
        assert_eq!(
            v,
            AwsVerb::S3Rm {
                bucket: "b".into(),
                key: "k".into()
            }
        );
    }

    #[test]
    fn s3_uri_without_key_returns_none() {
        assert!(classify_aws_argv(&argv(&["aws", "s3", "rm", "s3://b/"])).is_none());
        assert!(classify_aws_argv(&argv(&["aws", "s3", "rm", "s3:///k"])).is_none());
    }

    #[test]
    fn ec2_terminate_single_id_classified() {
        let v = classify_aws_argv(&argv(&[
            "aws",
            "ec2",
            "terminate-instances",
            "--instance-ids",
            "i-1",
        ]))
        .unwrap();
        assert_eq!(
            v,
            AwsVerb::Ec2Terminate {
                instance_ids: vec!["i-1".into()]
            }
        );
    }

    #[test]
    fn ec2_terminate_multiple_ids_classified() {
        let v = classify_aws_argv(&argv(&[
            "aws",
            "ec2",
            "terminate-instances",
            "--instance-ids",
            "i-1",
            "i-2",
            "i-3",
        ]))
        .unwrap();
        assert_eq!(
            v,
            AwsVerb::Ec2Terminate {
                instance_ids: vec!["i-1".into(), "i-2".into(), "i-3".into()]
            }
        );
    }

    #[test]
    fn ec2_stop_classified() {
        let v = classify_aws_argv(&argv(&[
            "aws",
            "ec2",
            "stop-instances",
            "--instance-ids",
            "i-1",
        ]))
        .unwrap();
        assert_eq!(
            v,
            AwsVerb::Ec2Stop {
                instance_ids: vec!["i-1".into()]
            }
        );
    }

    #[test]
    fn ec2_terminate_without_ids_returns_none() {
        assert!(classify_aws_argv(&argv(&["aws", "ec2", "terminate-instances"])).is_none());
    }

    #[test]
    fn unrecognized_service_returns_none() {
        assert!(classify_aws_argv(&argv(&["aws", "iam", "delete-user"])).is_none());
    }
}

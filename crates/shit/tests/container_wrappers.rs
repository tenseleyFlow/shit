// SPDX-License-Identifier: AGPL-3.0-or-later

//! Keep the installed POSIX container wrappers' prepare/runtime/finalize
//! contract in the ordinary `cargo test --workspace` gate.

#[cfg(unix)]
#[test]
fn container_wrapper_batch_protocol() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve workspace root");
    let script = workspace.join("packaging/container-hooks/test-wrappers.sh");
    let output = std::process::Command::new("/bin/sh")
        .arg(&script)
        .current_dir(&workspace)
        .output()
        .expect("run container wrapper protocol tests");
    assert!(
        output.status.success(),
        "container wrapper protocol tests failed (status={}):\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(unix)]
#[test]
fn cli_startup_atomically_refreshes_an_opted_in_stale_wrapper() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = tempfile::tempdir().expect("temporary config home");
    let bin = directory.path().join("shit/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let docker = bin.join("docker");
    std::fs::write(&docker, "#!/bin/sh\n# stale fail-open wrapper\n").unwrap();
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_shit"))
        .args(["internal", "new-uuid"])
        .env("XDG_CONFIG_HOME", directory.path())
        .output()
        .expect("run shit CLI");

    assert!(
        output.status.success(),
        "CLI startup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&docker).unwrap(),
        shit_shell::container_wrappers::DOCKER_WRAPPER.as_bytes()
    );
    assert_eq!(std::fs::metadata(&docker).unwrap().mode() & 0o777, 0o755);
    assert!(
        !bin.join("podman").exists(),
        "upgrade repair must preserve container-hook opt-in"
    );
}

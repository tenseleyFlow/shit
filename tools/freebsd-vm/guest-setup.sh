#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs INSIDE the FreeBSD guest as the `freebsd` user (provision.sh
# pipes it over ssh). Idempotent. Installs what the CI jobs install:
#
#   dr-smoke.yml freebsd-smoke (B04): rust gmake python3 sqlite3 doas
#                                     jq git vim gawk rsync
#   ci.yml freebsd-14:                gmake curl ca_root_nss + rustup 1.88
#
# Rust comes from rustup 1.88 on amd64 (DECISIONS D-4) instead of pkg
# rust; rustup ships no aarch64-unknown-freebsd host toolchain, so the
# arm64 guest keeps pkg rust. bash is not in either list because the
# CI image has it preinstalled; the stock VM image does not.

set -eu

say() { printf '[fbsd-vm-guest] %s\n' "$*"; }

say "$(uname -srm)"

PKGS="gmake python3 sqlite3 doas jq git vim gawk rsync curl ca_root_nss bash"
if [ "${FBSD_VM_ARCH:-amd64}" = aarch64 ]; then
  PKGS="${PKGS} rust"
fi
say "pkg install: ${PKGS}"
sudo env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null 2>&1 || true
# shellcheck disable=SC2086
sudo env ASSUME_ALWAYS_YES=yes pkg install -y ${PKGS} >/dev/null

say "doas.conf: permit nopass $(id -un) and :wheel"
printf 'permit nopass %s\npermit nopass :wheel\n' "$(id -un)" \
  | sudo tee /usr/local/etc/doas.conf >/dev/null
sudo chmod 0640 /usr/local/etc/doas.conf
if [ "$(doas /sbin/sysctl -n kern.ostype)" != FreeBSD ]; then
  say "doas check failed"
  exit 1
fi

if [ "${FBSD_VM_ARCH:-amd64}" = amd64 ]; then
  if ! "${HOME}/.cargo/bin/rustc" --version 2>/dev/null | grep -q '^rustc 1\.88\.'; then
    say "rustup: installing 1.88 (minimal + rustfmt + clippy)"
    fetch -q -o /tmp/rustup-init.sh https://sh.rustup.rs
    sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.88 \
      -c rustfmt -c clippy >/dev/null
    rm -f /tmp/rustup-init.sh
  fi
  say "$("${HOME}/.cargo/bin/rustc" --version)"
fi

# Second virtio disk -> `shitzfs` pool. A dataset mounted under /tmp
# is what the zfs-clone smokes look for, and TMPDIR=/tmp/zfs moves a
# smoke's whole scratch tree (watched dir + state) onto ZFS.
if [ -c /dev/vtbd1 ]; then
  sudo sysrc -q zfs_enable=YES >/dev/null
  sudo kldload -n zfs
  if ! zpool list -H shitzfs >/dev/null 2>&1; then
    say "zpool create shitzfs /dev/vtbd1"
    sudo zpool create -f shitzfs /dev/vtbd1
  fi
  if ! zfs list -H shitzfs/tmp >/dev/null 2>&1; then
    sudo zfs create -o mountpoint=/tmp/zfs shitzfs/tmp
  fi
  sudo chmod 1777 /tmp/zfs
  say "zfs: $(zfs list -H -o name,mountpoint shitzfs/tmp | tr '\t' ' ')"
fi

say "root fs: $(df -h / | tail -1)"
say "done"

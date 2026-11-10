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

# Privilege: sudo from the seed's user-data, else an existing doas,
# else running as root. Without any of them nothing below can work.
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif sudo -n true 2>/dev/null; then
  SUDO="sudo"
elif doas -n true 2>/dev/null; then
  SUDO="doas"
else
  say "no working sudo or doas for $(id -un); check the cidata user-data"
  exit 1
fi

PKGS="sudo gmake python3 sqlite3 doas jq git vim gawk rsync curl ca_root_nss bash zsh fish"
if [ "${FBSD_VM_ARCH:-amd64}" = aarch64 ]; then
  PKGS="${PKGS} rust"
fi
say "pkg install: ${PKGS}"
${SUDO} env ASSUME_ALWAYS_YES=yes pkg bootstrap -f >/dev/null 2>&1 || true
# shellcheck disable=SC2086
${SUDO} env ASSUME_ALWAYS_YES=yes pkg install -y ${PKGS} >/dev/null

say "doas.conf: permit nopass $(id -un) and :wheel"
printf 'permit nopass %s\npermit nopass :wheel\n' "$(id -un)" \
  | ${SUDO} tee /usr/local/etc/doas.conf >/dev/null
${SUDO} chmod 0640 /usr/local/etc/doas.conf
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
  ${SUDO} sysrc -q zfs_enable=YES >/dev/null
  ${SUDO} kldload -n zfs
  if ! zpool list -H shitzfs >/dev/null 2>&1; then
    say "zpool create shitzfs /dev/vtbd1"
    ${SUDO} zpool create -f shitzfs /dev/vtbd1
  fi
  if ! zfs list -H shitzfs/tmp >/dev/null 2>&1; then
    ${SUDO} zfs create -o mountpoint=/tmp/zfs shitzfs/tmp
  fi
  ${SUDO} chmod 1777 /tmp/zfs
  # B6: delegate snapshots to the login user, as the CI zfs leg does.
  ${SUDO} zfs allow -u "$(id -un)" snapshot,destroy,mount shitzfs/tmp
  say "zfs: $(zfs list -H -o name,mountpoint shitzfs/tmp | tr '\t' ' ')"
fi

say "root fs: $(df -h / | tail -1)"
say "done"

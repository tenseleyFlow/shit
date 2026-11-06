#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs inside an archlinux container with PKGBUILD, shit.install and a
# locally built shit-<ver>-x86_64-unknown-linux-gnu.tar.zst mounted at /work.
# makepkg finds the tarball next to the PKGBUILD and skips the download.
#
#   packaging/release-tarball.sh 0.1.0 x86_64-unknown-linux-gnu /tmp/aur
#   cp packaging/aur/PKGBUILD packaging/aur/shit.install packaging/aur/container-test.sh /tmp/aur/
#   sudo podman run --rm -v /tmp/aur:/work:Z docker.io/library/archlinux sh /work/container-test.sh
#
# Writes the regenerated .SRCINFO back to /work.

set -eux
pacman -Sy --noconfirm --needed base-devel libcap >/dev/null
useradd -m builder
cp -r /work /home/builder/pkg
chown -R builder /home/builder/pkg
cd /home/builder/pkg
su builder -c 'makepkg --printsrcinfo > .SRCINFO'
cp .SRCINFO /work/.SRCINFO
su builder -c 'makepkg -f --nodeps --skipchecksums'
ls -la ./*.pkg.tar.zst
pacman -Qlp ./*.pkg.tar.zst | grep -v -e 'hooks/' -e 'descriptors/'
pacman -U --noconfirm ./*.pkg.tar.zst
getcap /usr/bin/shit-helper
shit --version
shit doctor --json | head -c 600
ls /usr/lib/systemd/user/shit.service /var/lib/shit

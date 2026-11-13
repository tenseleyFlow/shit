#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build every spike prototype on FreeBSD 14. The module needs kernel
# sources in /usr/src/sys (src.txz from the matching release).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
make -C "$here/mac_shitpre"
make -C "$here/helper"
make -C "$here/audit"
make -C "$here/jail"

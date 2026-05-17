# dnf plugin — install to /usr/lib/python3/site-packages/dnf-plugins/
# (or wherever `python3 -c 'import dnf; print(dnf.__file__)'`'s parent
# leads).
#
# Hooks into dnf's `pre_transaction` and `transaction` signals, each
# invoking `shit-helper pkg-event dnf {pre,post}`. The plugin is
# best-effort: any subprocess failure is swallowed so dnf does not
# abort the user's transaction on shit-side error.
#
# Python compatibility: written for Python 3.9+ (RHEL 9 baseline);
# uses no f-strings with format specs that broke between 3.9 and 3.13.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import absolute_import

import subprocess

import dnf

HELPER = "/usr/local/bin/shit-helper"


class ShitRecord(dnf.Plugin):
    name = "shit_record"

    def __init__(self, base, cli):
        super(ShitRecord, self).__init__(base, cli)
        self.base = base

    def pre_transaction(self):
        self._fire("pre")

    def transaction(self):
        self._fire("post")

    def _fire(self, phase):
        try:
            subprocess.run(
                [HELPER, "pkg-event", "dnf", phase],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except Exception:
            # Hook-friendly: never let our subprocess failure leak
            # into dnf's own error path.
            pass

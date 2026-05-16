#!/bin/sh
# shit daemon FreeBSD launcher template.
# Substituted at install time:
#   @@SHITD_BIN@@    — absolute path to the shitd binary
#   @@CONFIG_PATH@@  — absolute path to the shitd config file
#   @@LOG_PATH@@     — absolute path for daemon(8) output
#
# FreeBSD has no per-user rc.d auto-start; this script uses daemon(8) to
# detach. Users typically wire it into their login shell's startup
# (e.g. ~/.profile) or run `shit service start` manually.
#
# Install: ~/.config/shit/start-daemon.sh

exec daemon -f -o @@LOG_PATH@@ -p @@LOG_PATH@@.pid -- @@SHITD_BIN@@ --foreground --config @@CONFIG_PATH@@

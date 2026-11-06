# Installing `shit` on Linux

All packages install `shit`, `shitd` and `shit-helper` in `/usr/bin`, a systemd user unit in `/usr/lib/systemd/user/shit.service`, shell hooks in `/usr/share/shit/shell/`, and apply `cap_bpf,cap_perfmon,cap_sys_admin+ep` to the helper. The builds are glibc (built on Ubuntu 22.04, glibc 2.35).

## Arch Linux (AUR)

```sh
yay -S shit-bin
```

The package's install hook runs `setcap` on `/usr/bin/shit-helper`. pacman clears file capabilities when it replaces the binary, so the hook runs again on upgrade.

## Debian and Ubuntu

```sh
sudo apt install ./shit_0.1.0-1_amd64.deb
```

## Fedora and RHEL

```sh
sudo dnf install ./shit-0.1.0-1.x86_64.rpm
```

## After installing

```sh
systemctl --user enable --now shit   # start the daemon
shit hooks install                   # add the shell hook
shit doctor                          # on a host with fanotify or eBPF-LSM the tier is not "degraded"
```

If `shit doctor` reports a missing capability, run `sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep /usr/bin/shit-helper`.

## From the release tarball

`shit-<version>-x86_64-unknown-linux-gnu.tar.zst` (and `aarch64`) holds the same tree under `bin/`, `lib/` and `share/shit/`. Extract it, copy `bin/*` to `/usr/local/bin`, and run `setcap` on the helper yourself.

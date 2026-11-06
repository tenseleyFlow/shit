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

`shit-<version>-x86_64-unknown-linux-gnu.tar.zst` (and `aarch64`) holds the same tree under `bin/`, `lib/` and `share/shit/`. Extract it, copy the files into `/usr/local`, give the helper its capabilities, and let `shit service install` write the systemd user unit with the real binary path:

```sh
tar --zstd -xf shit-0.1.0-x86_64-unknown-linux-gnu.tar.zst
cd shit-0.1.0-x86_64-unknown-linux-gnu
sudo cp bin/* /usr/local/bin/
sudo install -d /usr/local/lib/shit && sudo cp lib/* /usr/local/lib/shit/
sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep /usr/local/bin/shit-helper
shit service install
```

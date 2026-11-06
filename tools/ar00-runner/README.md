# AR00 self-hosted runner

The `linux-kernel-capture` job in `.github/workflows/dr-smoke.yml` runs on a
DigitalOcean droplet because stock GitHub-hosted Ubuntu images boot without
`bpf` in the active LSM list. The droplet is `shit-ar00-runner-20260521`
(`s-2vcpu-4gb`, region `nyc3`, labels `self-hosted,linux-kernel-capture`).

Files here:

- `cloud-init.yaml`: image contents.
- `build-image.sh`: builds the snapshot `shit-runner-image-YYYYMMDD`.
- `register-runner.sh <snapshot-id> [region]`: creates a droplet from the
  snapshot and registers it against `tenseleyFlow/shit`.

## Cost

A running 4 GB droplet costs about $0.036/hour, roughly $25/month. A
powered-off droplet is still billed for its disk and reserved resources, so
power-off cuts CPU-time use but does not reach $0. A snapshot costs about
$0.06/GB/month; destroy the droplet and keep only the snapshot to stop the
bulk of the spend. Decision D-7: stop the runner between Linux-lane sprints,
and delete the droplet only after the bare-metal `hasu` box has run the LSM
matrix green three times under the same label.

## Find the IDs

The droplet and snapshot IDs are not recorded in the repo.

    doctl compute droplet list --format ID,Name,Status,PublicIPv4 | grep shit-ar00
    doctl compute snapshot list --format ID,Name,CreatedAt | grep shit-runner-image

## Stop the runner

    doctl compute droplet-action shutdown <droplet-id> --wait   # graceful
    doctl compute droplet-action power-off <droplet-id> --wait  # if shutdown hangs

GitHub marks the runner offline within about a minute. The preflight job in
`dr-smoke.yml` then skips `linux-kernel-capture` with a visible "skipped"
status instead of leaving it queued.

## Start the runner

    doctl compute droplet-action power-on <droplet-id> --wait

The runner service is a systemd unit and starts on boot. Confirm it is back:

    gh api repos/tenseleyFlow/shit/actions/runners \
      --jq '.runners[] | [.name, .status, .busy] | @tsv'

Wait for `online` before pushing a PR that needs the LSM matrix, or re-run
the dr-smoke workflow afterward.

## Rebuild from snapshot

If the droplet is gone:

    bash tools/ar00-runner/register-runner.sh <snapshot-id> nyc3

Remove stale offline entries afterward with
`gh api -X DELETE repos/tenseleyFlow/shit/actions/runners/<runner-id>`.

## Preflight gate

`dr-smoke.yml` has a `runner-preflight` job on `ubuntu-24.04`. It lists the
repo's runners with `gh api` and sets `online=true` when a runner carrying the
`linux-kernel-capture` label has status `online`. The default `GITHUB_TOKEN`
cannot read the runner list, so the job falls back to the repository variable
`LSM_RUNNER_ONLINE` (`true` or `false`). Set it by hand when you power the
droplet on or off, or provide a `RUNNER_ADMIN_TOKEN` secret (PAT with
repo admin read) to get the live check:

    gh variable set LSM_RUNNER_ONLINE --body false -R tenseleyFlow/shit

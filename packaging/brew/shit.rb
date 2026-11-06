# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Formula for the tap tenseleyFlow/homebrew-tap (copy to Formula/shit.rb).
# Consumes the macOS arm64 release tarball produced by release.yml. That
# build is the un-entitled FSEvents + DYLD build; EndpointSecurity needs the
# power-user signing step described in the caveats.
#
# Per release: bump `version`, set `sha256` from the release's SHA256SUMS.
class Shit < Formula
  desc "Magic undo for the command line"
  homepage "https://github.com/tenseleyFlow/shit"
  version "0.1.0"
  url "https://github.com/tenseleyFlow/shit/releases/download/v#{version}/shit-#{version}-aarch64-apple-darwin-unentitled.tar.zst"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "AGPL-3.0-or-later"

  depends_on arch: :arm64
  depends_on :macos
  depends_on "zstd" => :build

  def install
    bin.install "bin/shit", "bin/shitd", "bin/shit-helper"
    # `shit dyld-hooks install` looks for the shim in HOMEBREW_PREFIX/lib.
    lib.install "lib/libshit_preload_shim.dylib"
    # Shell hooks, command wrappers, descriptors, the launchd plist and the
    # power-user signing script. setup-es-mode reads sign-for-power-user.sh
    # from HOMEBREW_PREFIX/share/shit.
    pkgshare.install Dir["share/shit/*"]
  end

  service do
    run [opt_bin/"shitd", "--foreground"]
    keep_alive crashed: true
    log_path var/"log/shit.log"
    error_log_path var/"log/shit.log"
  end

  def caveats
    <<~EOS
      This is the default install: FSEvents capture, post-mutation only, no
      change to SIP. `shit doctor` reports `fsevents-degraded`.

      Start the daemon and add the shell hook:
        brew services start shit
        shit hooks install

      For full pre-mutation capture (EndpointSecurity), read
        #{opt_pkgshare}/macos-power-user-install.md
      first. It requires disabling SIP and AuthRoot. Then run
        shit setup-es-mode --apply --i-understand-the-tradeoffs
      which calls #{opt_pkgshare}/sign-for-power-user.sh to sign the helper
      locally.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/shit --version")
    assert_match "doctor", shell_output("#{bin}/shit --help")
  end
end

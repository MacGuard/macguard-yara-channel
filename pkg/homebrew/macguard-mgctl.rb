# TEMPLATE for a Homebrew tap (not submitted anywhere). Fill url and sha256 from a published, verified release of the source archive.
# The formula is called macguard-mgctl and installs ONLY the command mgctl: the name 'mg' belongs to the mg editor formula.
class MacguardMgctl < Formula
  desc "mgctl, the canonical command of the MacGuard suite"
  homepage "https://github.com/MacGuard/macguard-yara-channel"
  url "https://example.invalid/REPLACE-WITH-RELEASE-URL/mgctl-0.1.0.tar.gz"
  sha256 "REPLACE-WITH-THE-SHA256-FROM-SHA256SUMS"
  license :cannot_represent # no licence has been chosen yet: owner decision

  depends_on "python@3"

  def install
    libexec.install "mgctl", "bin"
    (bin/"mgctl").write_env_script libexec/"bin/mgctl", {}
  end

  test do
    assert_match "mgctl", shell_output("#{bin}/mgctl --version")
  end
end

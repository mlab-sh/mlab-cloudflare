class MlabCloudflare < Formula
  desc "CLI over the Cloudflare API, for read-only account audit"
  homepage "https://github.com/mlab-sh/mlab-cloudflare"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cloudflare/releases/download/v#{version}/mlab-cloudflare-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "74d71e2668babf0f52cad194ab2123123bfab7359ce9721d15595d4e1fa24e09"
    else
      url "https://github.com/mlab-sh/mlab-cloudflare/releases/download/v#{version}/mlab-cloudflare-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "dd73be61eb9fcf408081a0a5110357d4735da3e07c20f736d287290c14ae5b64"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-cloudflare/releases/download/v#{version}/mlab-cloudflare-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "679fc5a73073c05473a08cbf2cee8e710c3eafe372233081d9665fc9a6231381"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cloudflare/releases/download/v#{version}/mlab-cloudflare-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "d191d801650a1290b0c52b1c3bb355a98ab91495b93a86ec108089292ed0367a"
    end
  end

  def install
    bin.install "mlab-cloudflare"
  end

  test do
    assert_match "mlab-cloudflare", shell_output("#{bin}/mlab-cloudflare --version")
  end
end

class Apex < Formula
  desc "Android app analysis and phone investigation (mlab.sh)"
  homepage "https://github.com/mlab-sh/apex"
  version "1.1.0"
  license "GPL-3.0-only"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/apex/releases/download/v#{version}/apex-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "41be283dd6fec81f9838d686a2bbf2ae0790c60ce3c6700937f0702ed88a4516"
    else
      url "https://github.com/mlab-sh/apex/releases/download/v#{version}/apex-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "995e87f876d132181e92171689fe0beeb610546900b2928aaf1c0147ad93c610"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/apex/releases/download/v#{version}/apex-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7dc9a988f80d68439c49dd1135e4c239f185063688d8b23356f67cd89ea1c45a"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/apex/releases/download/v#{version}/apex-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "d7171617be2947481396bf455f1bec4eee797f3f2167543818e2def74835ec0a"
    end
  end

  def install
    bin.install "apex"
  end

  test do
    assert_match "apex", shell_output("#{bin}/apex --version")
  end
end

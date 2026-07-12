class Apex < Formula
  desc "Static analysis for APK/IPA/AAB packages (mlab.sh)"
  homepage "https://github.com/mlab-sh/apex"
  version "1.0.0"
  license "GPL-3.0-only"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/apex/releases/download/v#{version}/apex-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "8dec059c72e95818728581fdf259c91c482ef14428bf9292310215f5202a9105"
    else
      url "https://github.com/mlab-sh/apex/releases/download/v#{version}/apex-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "e4195e171330fff191609b6038aff39bcef4f6afe3e81df1b24a2de155a58871"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/apex/releases/download/v#{version}/apex-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "e6b6eaa8b97040405469fa4aca922f004e35a32b9ee5c61f41588bfc6b051ac7"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/apex/releases/download/v#{version}/apex-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b7ab46787bbfced19fb12b3c53aa07c6415473df808830a799bcfaf2511151ab"
    end
  end

  def install
    bin.install "apex"
  end

  test do
    assert_match "apex", shell_output("#{bin}/apex --version")
  end
end

defmodule Dnscrypt.Types.CertificateTest do
  use ExUnit.Case
  doctest Dnscrypt

  @certdata_1 File.read!("test/data/live_data.txt")

  alias Dnscrypt.Types.Certificate

  describe "from_binary/1" do
    test "certdata_1 correctly parses" do
      cert = %Certificate{} = Certificate.from_binary(@certdata_1)

      assert cert.es_version == :xchacha20poly1305
    end
  end
end

defmodule Dnscrypt.Utils.CryptoTest do
  use ExUnit.Case
  doctest Dnscrypt.Utils.Crypto

  alias Dnscrypt.Utils.Crypto

  describe "nonce/1" do
    test "salsa nonce" do
      {:ok, nonce} = Crypto.nonce(:xsalsa20poly1305)
      assert byte_size(nonce) == 24
      assert is_binary(nonce)
    end

    test "xchacha nonce" do
      {:ok, nonce} = Crypto.nonce(:xchacha20poly1305)
      assert byte_size(nonce) == 24
      assert is_binary(nonce)
    end
  end
end

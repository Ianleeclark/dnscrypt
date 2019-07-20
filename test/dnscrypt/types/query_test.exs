defmodule Dnscrypt.Types.QueryTest do
  use ExUnit.Case
  doctest Dnscrypt

  alias Dnscrypt.Types.Query

  @client_magic :crypto.strong_rand_bytes(8)
  @client_pk :crypto.strong_rand_bytes(32)
  @client_nonce :crypto.strong_rand_bytes(24)
  @encrypted_query :crypto.strong_rand_bytes(256)

  describe "new/5" do
    test "Salsa with encrypted" do
      salsa_query =
        Query.new(
          @client_magic,
          @client_pk,
          @client_nonce,
          @encrypted_query,
          :xsalsa20poly1305
        )

      assert salsa_query.client_magic == @client_magic
      assert salsa_query.client_pk == @client_pk
      assert salsa_query.client_nonce == @client_nonce
      assert salsa_query.encrypted_query == @encrypted_query
      assert salsa_query.algorithm == :xsalsa20poly1305
    end

    test "Chacha with encrypted" do
      chacha_query =
        Query.new(
          @client_magic,
          @client_pk,
          @client_nonce,
          @encrypted_query,
          :xchacha20poly1305
        )

      assert chacha_query.client_magic == @client_magic
      assert chacha_query.client_pk == @client_pk
      assert chacha_query.client_nonce == @client_nonce
      assert chacha_query.encrypted_query == @encrypted_query
      assert chacha_query.algorithm == :xchacha20poly1305
    end

    test "Salsa without encrypted" do
      salsa_query =
        Query.new(
          @client_magic,
          @client_pk,
          @client_nonce,
          @encrypted_query,
          :xsalsa20poly1305
        )

      assert salsa_query.client_magic == @client_magic
      assert salsa_query.client_pk == @client_pk
      assert salsa_query.client_nonce == @client_nonce
      assert salsa_query.encrypted_query == @encrypted_query
      assert salsa_query.algorithm == :xsalsa20poly1305
    end

    test "Chacha without encrypted" do
      chacha_query =
        Query.new(
          @client_magic,
          @client_pk,
          @client_nonce,
          nil,
          :xchacha20poly1305
        )

      assert chacha_query.client_magic == @client_magic
      assert chacha_query.client_pk == @client_pk
      assert chacha_query.client_nonce == @client_nonce
      assert chacha_query.encrypted_query == nil
      assert chacha_query.algorithm == :xchacha20poly1305
    end
  end

  describe "to_binary/1" do
    test "Salsa with encrypted" do
      query =
        Query.new(
          @client_magic,
          @client_pk,
          @client_nonce,
          @encrypted_query,
          :xsalsa20poly1305
        )

      binary_data = Query.to_binary(query)
      assert byte_size(binary_data) == total_byte_size(@encrypted_query)
      assert <<@client_magic, @client_pk, @client_nonce, @encrypted_query>> == binary_data
    end

    test "Chacha with encrypted" do
      query =
        Query.new(
          @client_magic,
          @client_pk,
          @client_nonce,
          @encrypted_query,
          :xchacha20poly1305
        )

      binary_data = Query.to_binary(query)
      assert byte_size(binary_data) == total_byte_size(@encrypted_query)
      assert <<@client_magic, @client_pk, @client_nonce, @encrypted_query>> == binary_data
    end

    test "Salsa without encrypted" do
      query =
        Query.new(
          @client_magic,
          @client_pk,
          @client_nonce,
          nil,
          :xsalsa20poly1305
        )

      binary_data = Query.to_binary(query)
      assert byte_size(binary_data) == total_byte_size(nil)
      assert <<@client_magic, @client_pk, @client_nonce>> == binary_data
    end

    test "Chacha without encrypted" do
      query =
        Query.new(
          @client_magic,
          @client_pk,
          @client_nonce,
          nil,
          :xchacha20poly1305
        )

      binary_data = Query.to_binary(query)
      assert byte_size(binary_data) == total_byte_size(nil)
      assert <<@client_magic, @client_pk, @client_nonce>> == binary_data
    end
  end

  def total_byte_size(encrypted_query) do
    size_wo_encrypted =
      byte_size(@client_magic) + byte_size(@client_pk) + byte_size(@client_nonce)

    case encrypted_query do
      nil ->
        size_wo_encrypted

      _ ->
        size_wo_encrypted + byte_size(encrypted_query)
    end
  end
end

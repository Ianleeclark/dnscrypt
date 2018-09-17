defmodule DnsCryptEx.Types.Query do
  @moduledoc """
  Defines what a DNS query is to our system.
  """

  alias Salty.Secretbox.Xchacha20poly1305
  alias Salty.Secretbox.Xsalsa20poly1305

  #############
  # Constants #
  #############

  @supported_algorithms [:xsalsa20poly1305, :xchacha20poly1305]

  @xchacha_key_len Xchacha20poly1305.keybytes()
  @xsalsa_key_len Xchacha20poly1305.keybytes()

  @xchacha_nonce_len Xchacha20poly1305.keybytes()
  @xsalsa_nonce_len Xsalsa20poly1305.keybytes()

  ####################
  # Type Definitions #
  ####################

  @type algorithm :: :xsalsa20poly1305 | :xchacha20poly1305
  @type t :: %__MODULE__{}

  #####################
  # Struct Definition #
  #####################

  @required_keys [:client_magic, :client_pk, :client_nonce, :encrypted_query]
  @enforce @required_keys
  defstruct @required_keys

  ##############
  # Public API #
  ##############

  @doc """
  Converts a binary blob into a usable Query.
  """
  @spec from_binary(algorithm :: algorithm(), binary()) :: __MODULE__.t()
  def from_binary(
        :xsalsa20poly1305,
        <<magic::8, pk::size(@xsalsa_key_len), nonce::size(@xsalsa_nonce_len),
          encrypted_query::binary()>>
      )
      when algorithm in @supported_algorithms do
    %__MODULE__{
      client_magic: magic,
      client_pk: pk,
      client_nonce: nonce,
      encrypted_query: encrypted_query
    }
  end

  def from_binary(
        :xchacha20poly1305,
        <<magic::8, pk::size(@xchacha_key_len), nonce::size(@xchacha_nonce_len),
          encrypted_query::binary()>>
      )
      when algorithm in @supported_algorithms do
    %__MODULE__{
      client_magic: magic,
      client_pk: pk,
      client_nonce: nonce,
      encrypted_query: encrypted_query
    }
  end

  def from_binary(algorithm, _query) when algorithm not in @supported_algorithms do
    {:error, :invalid_algorithm}
  end

  def from_binary(_, _) do
    {:error, :invalid_data}
  end

  ##############################
  # Internal Private Functions #
  ##############################
end

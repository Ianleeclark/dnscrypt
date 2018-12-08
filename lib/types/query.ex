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
  @type t :: %__MODULE__{
          client_magic: binary(),
          client_pk: binary(),
          client_nonce: binary(),
          encrypted_query: binary(),
          algorithm: algorithm()
        }

  #####################
  # Struct Definition #
  #####################

  @required_keys [:client_magic, :client_pk, :client_nonce, :encrypted_query, :algorithm]
  @enforce @required_keys
  defstruct @required_keys

  ##############
  # Public API #
  ##############

  @doc """
  Converts query struct to binary.
  """
  @spec to_binary(__MODULE__.t()) :: binary() | {:error, :invalid_query}
  def to_binary(
        %__MODULE__{
          algorithm: :xsalsa20poly1305
        } = query
      ) do
    do_to_binary(query, @xsalsa_key_len, @xsalsa_nonce_len)
  end

  def to_binary(
        %__MODULE__{
          algorithm: :xchacha20poly1305
        } = query
      ) do
    do_to_binary(query, @xchacha_key_len, @xchacha_nonce_len)
  end

  def to_binary(_), do: {:error, :invalid_query}

  ##############################
  # Internal Private Functions #
  ##############################

  @spec do_to_binary(__MODULE__.t()) :: binary()
  def do_to_binary(
        %__MODULE__{
          client_magic: magic,
          client_pk: pk,
          client_nonce: nonce,
          encrypted_query: encrypted_query
        },
        key_len,
        nonce_len
      ) do
    <<magic::8, pk::size(key_len), nonce::size(nonce_len), encrypted_query::binary()>>
  end
end

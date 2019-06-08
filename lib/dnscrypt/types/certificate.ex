defmodule Dnscrypt.Types.Certificate do
  @moduledoc false

  alias Dnscrypt.Types.Query
  import Dnscrypt.Utils.Guards

  #############
  # Constants #
  #############

  @signature_bit_len 512
  @public_key_bit_len 256
  @client_magic_bit_len 64
  @serial_bit_len 32
  @date_bit_len 32

  ####################
  # Type Information #
  ####################

  @required_keys [
    :es_version,
    :signature,
    :public_key,
    :client_magic,
    :serial,
    :valid_from,
    :valid_until,
    :extensions
  ]
  @enforce_keys @required_keys
  defstruct @required_keys

  @type t :: %__MODULE__{
          es_version: Query.algorithm(),
          signature: binary(),
          public_key: binary(),
          client_magic: binary(),
          serial: binary(),
          valid_from: DateTime.t(),
          valid_until: DateTime.t(),
          extensions: []
        }

  ##############
  # Public API #
  ##############

  @spec new(
          es_version :: Query.algorithm(),
          signature :: binary(),
          public_key :: binary(),
          client_magic :: binary(),
          serial :: binary(),
          valid_from :: DateTime.t(),
          valid_until :: DateTime.t(),
          extensions :: list()
        ) :: %__MODULE__{}
  def new(
        es_version,
        signature,
        public_key,
        client_magic,
        serial,
        valid_from,
        valid_until,
        extensions \\ []
      )
      when is_valid_encryption_algorithm(es_version) and
             is_binary_of_octet_size(public_key, @public_key_bit_len / 8) do
    %__MODULE__{
      es_version: es_version,
      signature: signature,
      public_key: public_key,
      client_magic: client_magic,
      serial: serial,
      valid_from: valid_from,
      valid_until: valid_until,
      extensions: extensions
    }
  end

  @doc """
  Parses a certificate from a binary DNS TXT record response

  The first four bytes refer to a constant defined in the protocol. The two following magic-number pairs (<< 0, 1 >>, and << 0, 0 >>) are the algorithm version and the protocol minor version, respectively.
  """
  @spec from_binary(binary()) :: t() | {:error, :invalid_dns_certificate}
  def from_binary(
        <<68, 78, 83, 67, 0, 1, 0, 0, signature::size(@signature_bit_len),
          public_key::size(@public_key_bit_len), client_magic::size(@client_magic_bit_len),
          serial::size(@serial_bit_len), valid_from::size(@date_bit_len),
          valid_until::size(@date_bit_len), _extensions::binary()>>
      ) do
    # TODO(ian): Don't just hastily assert these
    {:ok, start_date} = DateTime.from_unix(valid_from)
    {:ok, end_date} = DateTime.from_unix(valid_until)

    new(
      :xsalsa20poly1305,
      <<signature::size(@signature_bit_len)>>,
      <<public_key::size(@public_key_bit_len)>>,
      <<client_magic::size(@client_magic_bit_len)>>,
      <<serial::size(@serial_bit_len)>>,
      start_date,
      end_date,
      []
    )
  end

  def from_binary(
        <<68, 78, 83, 67, 0, 2, 0, 0, signature::size(@signature_bit_len),
          public_key::size(@public_key_bit_len), client_magic::size(@client_magic_bit_len),
          serial::size(@serial_bit_len), valid_from::size(@date_bit_len),
          valid_until::size(@date_bit_len), _extensions::binary()>>
      ) do
    # TODO(ian): Don't just hastily assert these
    {:ok, start_date} = DateTime.from_unix(valid_from)
    {:ok, end_date} = DateTime.from_unix(valid_until)

    new(
      :xchacha20poly1305,
      <<signature::size(@signature_bit_len)>>,
      <<public_key::size(@public_key_bit_len)>>,
      <<client_magic::size(@client_magic_bit_len)>>,
      <<serial::size(@serial_bit_len)>>,
      start_date,
      end_date,
      []
    )
  end

  def from_binary(_), do: {:error, :invalid_dns_certificate}
end

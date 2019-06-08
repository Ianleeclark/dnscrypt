defmodule Dnscrypt.Utils.Guards do
  @moduledoc false

  defguard is_binary_of_octet_size(value, size)
           when is_number(size) and is_binary(value) and byte_size(value) == size

  defguard is_valid_encryption_algorithm(algo)
           when algo in [:xsalsa20poly1305, :xchacha20poly1305]
end

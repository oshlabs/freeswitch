# run as elixir sctp_client.exs [host port]

defmodule SCTPClient do
  # 4.5 minutes
  @rfc4960_timeout trunc(4.5 * 60 * 1000)
  @default_host "127.0.0.1"
  @default_port 5555

  def start(host \\ @default_host, port \\ @default_port) do
    {:ok, socket} = :gen_sctp.open(0)
    {:ok, sockaddr} = :inet.parse_address(String.to_charlist(host))
    {:ok, assoc} = :gen_sctp.connect(socket, sockaddr, port, [], @rfc4960_timeout)

    IO.puts("Connected and ready to send SCTP messages to #{host}:#{port}")
    loop(socket, assoc)
  end

  defp loop(socket, assoc) do
    msg = IO.gets("Send message: ") |> String.trim()

    if msg != "" do
      :ok = :gen_sctp.send(socket, assoc, 0, msg)

      case :gen_sctp.recv(socket) do
        {:ok, message = {_from_ip, _from_port, _opts, _data}} ->
          # ex {:ok, {{127, 0, 0, 1}, 5555, [{:sctp_sndrcvinfo, 0, 0, [], 0, 0, 0, 468363411, 0, 7}], "ok"}}
          IO.puts("Received: #{inspect(message)}")
          loop(socket, assoc)

        {:error, reason} ->
          IO.puts("Receive error: #{inspect(reason)}")
      end
    else
      loop(socket, assoc)
    end
  end
end

case System.argv() do
  [host, port] ->
    SCTPClient.start(host, String.to_integer(port))

  [] ->
    SCTPClient.start()

  _ ->
    IO.puts("Usage: elixir sctp_client.exs [host port]")
end

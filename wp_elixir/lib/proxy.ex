defmodule Proxy do
  # initialize a proxy listening on a socket
  # handle the proxify handshake
  # connect to the server
  # relay messages back and forth
  def start_proxy() do
    {:ok, proxy} = :gen_tcp.listen(8888, [:binary, active: false, reuseaddr: true])
    IO.puts("PROXY listening on port 8888")
    accept_loop(proxy)
  end

  def accept_loop(proxy) do
    {:ok, client} = :gen_tcp.accept(proxy)
    spawn(fn -> client_handler(client) end)
    accept_loop(proxy)
  end

  def client_handler(client) do
    IO.puts("")
    IO.puts("CONNECTED TO CLIENT")
    {ip, port} = do_proxify_handshake(client)
    {:ok, server} = :gen_tcp.connect(ip, port, [:binary, active: false, reuseaddr: true])
    IO.puts("")
    IO.puts("CONNECTED TO SERVER")
    do_manage_convo(client, server)

    # proxy.connect(server)
    # manage_convo(client, server, proxy)
    # client.recv |> print |> server.send
    # server.recv |> print |> client.send
  end

  def do_proxify_handshake(client) do
    {:ok, <<0x05, 0x01, 0x00>>} = :gen_tcp.recv(client, 3)
    :gen_tcp.send(client, <<0x05, 0x00>>)
    {:ok, <<0x05, 0x01, 0x00, 0x01, ip::binary-size(4), port::16>>} = :gen_tcp.recv(client, 10)
    :gen_tcp.send(client, <<0x05, 0x00, 0x00, 0x01, ip::binary, port::16>>)
    <<a, b, c, d>> = ip
    ip = {a, b, c, d}
    {ip, port}
  end

  def do_manage_convo(client, server) do
    buffer = %{"send" => %{"open" => true, "buffer" =>[]}, "recv" => %{"open" => true, "buffer" =>[]}}
    spawn(fn send_stream ->
      case :gen_tcp.recv(client, 8192) do
        {:ok, data} ->
          buffer["recv"]["buffer"] += data
          send_stream
        {:ok, ""} ->
          buffer["send"]["open"] = false
      end
    end)
    spawn(fn recv_stream ->
      case :gen_tcp.recv(server, 8192) do
        {:ok, data} ->
          buffer["recv"]["buffer"] += data
          recv_stream
        {:ok, ""} ->
          buffer["recv"]["open"] = false
      end
    end)
    spawn(fn sender ->

    end)

  def manage_stream(reader, writer) do
  end

  def read_message(reader) do
    case :gen_tcp.read(reader, 25) do
      {:ok, ""} ->
        break()
      {:ok, data} ->
        length = bytes.split(4:8) of data
        :gen_tcp.read(reader, length)
        {:ok data}
    end
  end
  end
  end

  def stream(reader, writer) do
    buffer = []
    case :gen_tcp.recv(reader, 8192) do
      {:ok, data} ->
        buffer.add(data)
        :gen_tcp.send(writer, data)
        stream(reader, writer)
      {:error, _} ->
        :gen_tcp.close(writer)
    end
  end
end

// File:    tests/RdpAudit.Web.Tests/FakeBackendServer.cs
// Module:  RdpAudit.Web.Tests
// Purpose: Minimal loopback HTTP backend for the web-UI proxy integration tests. Binds an
//          ephemeral TCP port on 127.0.0.1, answers every request with a JSON envelope that
//          echoes the request line and the Authorization header it received, and records each
//          request so tests can assert exactly what the proxy sent outbound. No URL-ACL
//          reservations and no elevation are required - only a raw loopback socket.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace RdpAudit.Web.Tests;

/// <summary>Loopback echo HTTP backend for the web-UI proxy tests.</summary>
internal sealed class FakeBackendServer : IAsyncDisposable
{
	private const int MaxHeaderBytes = 16 * 1024;
	private static readonly byte[] HeaderTerminator = Encoding.ASCII.GetBytes("\r\n\r\n");

	private readonly TcpListener _listener;
	private readonly CancellationTokenSource _lifetime = new();
	private readonly Task _acceptLoop;
	private readonly ConcurrentQueue<BackendRequestRecord> _requests = new();

	private FakeBackendServer(TcpListener listener)
	{
		_listener = listener;
		_acceptLoop = Task.Run(() => AcceptLoopAsync(_lifetime.Token));
	}

	/// <summary>Base URL the proxy should target (http://127.0.0.1:&lt;port&gt;).</summary>
	public string BaseUrl { get; private init; } = string.Empty;

	/// <summary>Requests seen so far, oldest first.</summary>
	public IReadOnlyList<BackendRequestRecord> Requests => _requests.ToArray();

	/// <summary>Binds the loopback listener on an ephemeral port and starts accepting.</summary>
	public static FakeBackendServer Start()
	{
		TcpListener listener = new(IPAddress.Loopback, 0);
		listener.Start();
		int port = ((IPEndPoint)listener.LocalEndpoint).Port;
		return new FakeBackendServer(listener)
		{
			BaseUrl = "http://127.0.0.1:" + port.ToString(CultureInfo.InvariantCulture),
		};
	}

	/// <summary>Binds 127.0.0.1, reserves a port, then immediately releases it so the address is closed.</summary>
	public static int ReserveThenClosePort()
	{
		TcpListener listener = new(IPAddress.Loopback, 0);
		listener.Start();
		int port = ((IPEndPoint)listener.LocalEndpoint).Port;
		listener.Stop();
		return port;
	}

	/// <inheritdoc />
	public async ValueTask DisposeAsync()
	{
		_lifetime.Cancel();
		try
		{
			_listener.Stop();
		}
		catch (SocketException)
		{
			// Already stopped.
		}

		try
		{
			await _acceptLoop.WaitAsync(TimeSpan.FromSeconds(5));
		}
		catch (Exception ex) when (ex is OperationCanceledException or TimeoutException)
		{
			// Accept loop is finished or the process is tearing down.
		}

		_lifetime.Dispose();
	}

	private async Task AcceptLoopAsync(CancellationToken cancellationToken)
	{
		while (!cancellationToken.IsCancellationRequested)
		{
			TcpClient client;
			try
			{
				client = await _listener.AcceptTcpClientAsync(cancellationToken);
			}
			catch (Exception ex) when (ex is OperationCanceledException or SocketException)
			{
				break; // Listener stopped or test teardown.
			}

			_ = Task.Run(() => ServeOneAsync(client, cancellationToken), CancellationToken.None);
		}
	}

	private async Task ServeOneAsync(TcpClient client, CancellationToken cancellationToken)
	{
		using (client)
		await using (NetworkStream stream = client.GetStream())
		{
			try
			{
				string requestHead = await ReadHeadersAsync(stream, cancellationToken);
				if (requestHead.Length == 0)
				{
					return;
				}

				string[] lines = requestHead.Split("\r\n", StringSplitOptions.None);
				string[] requestLine = lines[0].Split(' ');
				string method = requestLine.Length > 0 ? requestLine[0] : string.Empty;
				string path = requestLine.Length > 1 ? requestLine[1] : string.Empty;
				string authorization = string.Empty;
				foreach (string line in lines)
				{
					if (line.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
					{
						authorization = line["Authorization:".Length..].Trim();
						break;
					}
				}

				_requests.Enqueue(new BackendRequestRecord(DateTimeOffset.UtcNow, method, path, authorization));

				string payload = JsonSerializer.Serialize(new
				{
					ok = true,
					method,
					path,
					authorization,
				});

				byte[] body = Encoding.UTF8.GetBytes(payload);
				string responseHead = "HTTP/1.1 200 OK\r\n"
					+ "Content-Type: application/json\r\n"
					+ "Content-Length: " + body.Length.ToString(CultureInfo.InvariantCulture) + "\r\n"
					+ "Connection: close\r\n"
					+ "\r\n";
				await stream.WriteAsync(Encoding.ASCII.GetBytes(responseHead), cancellationToken);
				await stream.WriteAsync(body, cancellationToken);
			}
			catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
			{
				// Client closed or the test is tearing down; nothing to assert.
			}
		}
	}

	private static async Task<string> ReadHeadersAsync(Stream stream, CancellationToken cancellationToken)
	{
		byte[] head = [];
		byte[] chunk = new byte[2048];
		while (head.Length <= MaxHeaderBytes)
		{
			int read = await stream.ReadAsync(chunk, cancellationToken);
			if (read <= 0)
			{
				break;
			}

			byte[] grown = new byte[head.Length + read];
			Buffer.BlockCopy(head, 0, grown, 0, head.Length);
			Buffer.BlockCopy(chunk, 0, grown, head.Length, read);
			head = grown;

			int terminator = ((ReadOnlySpan<byte>)head).IndexOf(HeaderTerminator);
			if (terminator >= 0)
			{
				return Encoding.ASCII.GetString(head, 0, terminator + HeaderTerminator.Length);
			}
		}

		return string.Empty;
	}
}

/// <summary>One request the fake backend received.</summary>
public sealed record BackendRequestRecord(
	DateTimeOffset ReceivedUtc,
	string Method,
	string Path,
	string AuthorizationHeader);

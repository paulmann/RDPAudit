/*
 * File   : RouterOsApiClient.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Core)
 * Purpose: Self-contained RouterOS API client speaking the native binary protocol (length-prefixed
 *          "words" grouped into "sentences", terminated by an empty word) over an mTLS-secured
 *          SslStream. This is the PRODUCTION channel: it authenticates with a least-privilege service
 *          account and pins both the server (CA-validated) and the client (certificate presented for
 *          mutual TLS). No third-party RouterOS API package is used — the wire protocol is implemented
 *          here against System.Net.Sockets / System.Net.Security.
 * Depends: System.Net.Sockets.TcpClient, System.Net.Security.SslStream, X509Certificate2,
 *          Microsoft.Extensions.Logging.ILogger
 * Extends: To support a new RouterOS command, call ExecuteAsync with the command path and word list;
 *          to change TLS pinning behaviour, edit ValidateServerCertificate; to add a new reply-word
 *          parser, extend ParseSentence. Keep the wire encoding (EncodeLength / ReadLength) byte-exact.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;

namespace RdpAudit.Mikrotik.Core;

/// <summary>One parsed RouterOS API reply sentence (reply word plus attribute key/value pairs).</summary>
/// <param name="Reply">The leading reply word, e.g. "!re", "!done", "!trap", "!fatal".</param>
/// <param name="Attributes">Attribute words parsed from "=key=value" pairs.</param>
public sealed record RouterOsSentence(string Reply, IReadOnlyDictionary<string, string> Attributes)
{
	/// <summary>True for the terminal success sentence.</summary>
	public bool IsDone => string.Equals(Reply, "!done", StringComparison.Ordinal);

	/// <summary>True for an error sentence (!trap or !fatal).</summary>
	public bool IsError => string.Equals(Reply, "!trap", StringComparison.Ordinal)
		|| string.Equals(Reply, "!fatal", StringComparison.Ordinal);

	/// <summary>True for a data row sentence.</summary>
	public bool IsRow => string.Equals(Reply, "!re", StringComparison.Ordinal);
}

/// <summary>Aggregate result of one RouterOS command: the data rows plus the error message, if any.</summary>
/// <param name="Rows">Zero or more "!re" data rows.</param>
/// <param name="Succeeded">True when the command ended with "!done" and no "!trap"/"!fatal".</param>
/// <param name="ErrorMessage">Curated error text when <see cref="Succeeded"/> is false.</param>
public sealed record RouterOsResult(IReadOnlyList<IReadOnlyDictionary<string, string>> Rows, bool Succeeded, string? ErrorMessage);

/// <summary>Self-contained RouterOS API client over mutual TLS.</summary>
public sealed class RouterOsApiClient : IAsyncDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly string _host;
	private readonly int _port;
	private readonly X509Certificate2 _clientCertificate;
	private readonly X509Certificate2? _trustedCaCertificate;
	private readonly bool _validateServerCertificate;
	private readonly ILogger<RouterOsApiClient> _logger;

	private TcpClient? _tcp;
	private SslStream? _ssl;
	private bool _loggedIn;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>
	/// Creates a client for <paramref name="host"/>:<paramref name="port"/> that presents
	/// <paramref name="clientCertificate"/> for mutual TLS. When <paramref name="trustedCaCertificate"/>
	/// is supplied the server certificate must chain to it; when null the client falls back to the
	/// Windows trust store. Set <paramref name="validateServerCertificate"/> false only for lab use.
	/// </summary>
	public RouterOsApiClient(
		string host,
		int port,
		X509Certificate2 clientCertificate,
		X509Certificate2? trustedCaCertificate,
		bool validateServerCertificate,
		ILogger<RouterOsApiClient> logger)
	{
		_host = host ?? throw new ArgumentNullException(nameof(host));
		_port = port;
		_clientCertificate = clientCertificate ?? throw new ArgumentNullException(nameof(clientCertificate));
		_trustedCaCertificate = trustedCaCertificate;
		_validateServerCertificate = validateServerCertificate;
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Opens the TCP connection, performs the mutual-TLS handshake and logs in. Idempotent.</summary>
	public async Task ConnectAndLoginAsync(string username, string password, CancellationToken ct)
	{
		if (_loggedIn)
		{
			return;
		}

		_tcp = new TcpClient { NoDelay = true };
		await _tcp.ConnectAsync(_host, _port, ct).ConfigureAwait(false);

		_ssl = new SslStream(_tcp.GetStream(), leaveInnerStreamOpen: false, ValidateServerCertificate);

		SslClientAuthenticationOptions sslOptions = new()
		{
			TargetHost = _host,
			ClientCertificates = new X509CertificateCollection { _clientCertificate },
			EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
		};
		await _ssl.AuthenticateAsClientAsync(sslOptions, ct).ConfigureAwait(false);

		// RouterOS v6.43+ login: single /login sentence carrying =name= and =password= words.
		RouterOsResult login = await ExecuteAsync(
			"/login",
			new[] { "=name=" + username, "=password=" + password },
			ct).ConfigureAwait(false);

		if (!login.Succeeded)
		{
			throw new InvalidOperationException("RouterOS login failed: " + (login.ErrorMessage ?? "unknown error"));
		}

		_loggedIn = true;
		_logger.LogDebug("RouterOS API login succeeded for {Host}:{Port}.", _host, _port);
	}

	/// <summary>
	/// Sends one RouterOS command sentence (a command word followed by zero or more attribute words)
	/// and reads reply sentences until "!done" or an error. Returns the aggregated rows and outcome.
	/// </summary>
	public async Task<RouterOsResult> ExecuteAsync(string command, IReadOnlyList<string> words, CancellationToken ct)
	{
		if (_ssl is null)
		{
			throw new InvalidOperationException("RouterOS client is not connected.");
		}

		await WriteSentenceAsync(_ssl, PrependCommand(command, words), ct).ConfigureAwait(false);

		List<IReadOnlyDictionary<string, string>> rows = new();
		string? error = null;

		while (true)
		{
			RouterOsSentence sentence = await ReadSentenceAsync(_ssl, ct).ConfigureAwait(false);

			if (sentence.IsRow)
			{
				rows.Add(sentence.Attributes);
			}
			else if (sentence.IsError)
			{
				error = sentence.Attributes.TryGetValue("message", out string? message)
					? message
					: sentence.Reply;
			}
			else if (sentence.IsDone)
			{
				break;
			}
		}

		bool succeeded = error is null;
		return new RouterOsResult(rows, succeeded, error);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static string[] PrependCommand(string command, IReadOnlyList<string> words)
	{
		string[] sentence = new string[words.Count + 1];
		sentence[0] = command;
		for (int i = 0; i < words.Count; i++)
		{
			sentence[i + 1] = words[i];
		}
		return sentence;
	}

	private static async Task WriteSentenceAsync(SslStream ssl, IReadOnlyList<string> words, CancellationToken ct)
	{
		using MemoryStream buffer = new();
		foreach (string word in words)
		{
			byte[] payload = Encoding.UTF8.GetBytes(word);
			byte[] length = EncodeLength(payload.Length);
			buffer.Write(length, 0, length.Length);
			buffer.Write(payload, 0, payload.Length);
		}

		// Terminating empty word (length 0) closes the sentence.
		buffer.WriteByte(0x00);

		byte[] frame = buffer.ToArray();
		await ssl.WriteAsync(frame, ct).ConfigureAwait(false);
		await ssl.FlushAsync(ct).ConfigureAwait(false);
	}

	private static async Task<RouterOsSentence> ReadSentenceAsync(SslStream ssl, CancellationToken ct)
	{
		string reply = string.Empty;
		Dictionary<string, string> attributes = new(StringComparer.Ordinal);
		bool first = true;

		while (true)
		{
			int length = await ReadLengthAsync(ssl, ct).ConfigureAwait(false);
			if (length == 0)
			{
				break;
			}

			byte[] payload = new byte[length];
			await ReadExactAsync(ssl, payload, ct).ConfigureAwait(false);
			string word = Encoding.UTF8.GetString(payload);

			if (first)
			{
				reply = word;
				first = false;
				continue;
			}

			// Attribute words have the form "=key=value".
			if (word.Length > 0 && word[0] == '=')
			{
				int separator = word.IndexOf('=', 1);
				if (separator > 0)
				{
					string key = word.Substring(1, separator - 1);
					string value = word.Substring(separator + 1);
					attributes[key] = value;
				}
			}
		}

		return new RouterOsSentence(reply, attributes);
	}

	// ── Wire encoding ────────────────────────────────────────────────────────────

	/// <summary>Encodes a word length using the RouterOS variable-length scheme.</summary>
	internal static byte[] EncodeLength(int length)
	{
		if (length < 0x80)
		{
			return new[] { (byte)length };
		}
		if (length < 0x4000)
		{
			int value = length | 0x8000;
			return new[] { (byte)(value >> 8), (byte)(value & 0xFF) };
		}
		if (length < 0x200000)
		{
			int value = length | 0xC00000;
			return new[] { (byte)(value >> 16), (byte)((value >> 8) & 0xFF), (byte)(value & 0xFF) };
		}
		if (length < 0x10000000)
		{
			long value = length | 0xE0000000L;
			return new[] { (byte)(value >> 24), (byte)((value >> 16) & 0xFF), (byte)((value >> 8) & 0xFF), (byte)(value & 0xFF) };
		}

		return new[]
		{
			(byte)0xF0,
			(byte)((length >> 24) & 0xFF),
			(byte)((length >> 16) & 0xFF),
			(byte)((length >> 8) & 0xFF),
			(byte)(length & 0xFF),
		};
	}

	private static async Task<int> ReadLengthAsync(SslStream ssl, CancellationToken ct)
	{
		byte[] one = new byte[1];
		await ReadExactAsync(ssl, one, ct).ConfigureAwait(false);
		int c = one[0];

		if ((c & 0x80) == 0x00)
		{
			return c;
		}
		if ((c & 0xC0) == 0x80)
		{
			int b2 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
			return ((c & 0x3F) << 8) + b2;
		}
		if ((c & 0xE0) == 0xC0)
		{
			int b2 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
			int b3 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
			return ((c & 0x1F) << 16) + (b2 << 8) + b3;
		}
		if ((c & 0xF0) == 0xE0)
		{
			int b2 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
			int b3 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
			int b4 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
			return ((c & 0x0F) << 24) + (b2 << 16) + (b3 << 8) + b4;
		}

		int n2 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
		int n3 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
		int n4 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
		int n5 = await ReadByteAsync(ssl, ct).ConfigureAwait(false);
		return (n2 << 24) + (n3 << 16) + (n4 << 8) + n5;
	}

	private static async Task<int> ReadByteAsync(SslStream ssl, CancellationToken ct)
	{
		byte[] one = new byte[1];
		await ReadExactAsync(ssl, one, ct).ConfigureAwait(false);
		return one[0];
	}

	private static async Task ReadExactAsync(SslStream ssl, byte[] buffer, CancellationToken ct)
	{
		int offset = 0;
		while (offset < buffer.Length)
		{
			int read = await ssl.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct).ConfigureAwait(false);
			if (read == 0)
			{
				throw new IOException("RouterOS connection closed while reading a sentence.");
			}
			offset += read;
		}
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	private bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
	{
		if (!_validateServerCertificate)
		{
			return true;
		}

		if (errors == SslPolicyErrors.None)
		{
			return true;
		}

		// When a pinned CA is supplied, accept the server only if its chain roots to that CA even
		// though the CA is not in the machine trust store (RouterOS Local CA scenario).
		if (_trustedCaCertificate is not null && certificate is not null)
		{
			using X509Chain customChain = new();
			customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
			customChain.ChainPolicy.CustomTrustStore.Add(_trustedCaCertificate);
			customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

			using X509Certificate2 server = new(certificate);
			bool built = customChain.Build(server);
			if (built)
			{
				return true;
			}
		}

		_logger.LogWarning("RouterOS server certificate validation failed: {Errors}.", errors);
		return false;
	}

	// ── Disposal ─────────────────────────────────────────────────────────────────

	/// <summary>Closes the TLS session and underlying socket.</summary>
	public async ValueTask DisposeAsync()
	{
		try
		{
			if (_ssl is not null)
			{
				await _ssl.DisposeAsync().ConfigureAwait(false);
			}
		}
		catch (IOException)
		{
			// Best-effort teardown; the socket may already be gone.
		}
		finally
		{
			_tcp?.Dispose();
			_ssl = null;
			_tcp = null;
			_loggedIn = false;
		}
	}
}

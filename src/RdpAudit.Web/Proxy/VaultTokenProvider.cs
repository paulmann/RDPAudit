// File:    src/RdpAudit.Web/Proxy/VaultTokenProvider.cs
// Module:  RdpAudit.Web
// Purpose: Production <see cref="IWebUiTokenProvider"/> backed by the shared bearer-token vault
//          (WebTokenVault, DPAPI machine-scope file under ProgramData). The unsealed token is
//          loaded lazily ONCE per process and cached for the app lifetime; a failure to obtain
//          it is surfaced as <see cref="RdpAudit.Core.Security.SecretProtectionException"/>, which
//          the token-acquisition middleware converts into a curated 503 problem response.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Security;

namespace RdpAudit.Web.Proxy;

/// <summary>Vault-backed bearer-token provider for the web-UI proxy.</summary>
public sealed class VaultTokenProvider : IWebUiTokenProvider
{
	private readonly string _tokenFilePath;
	private readonly Func<ISecretProtector> _protectorFactory;
	private readonly Lazy<Task<string>> _cachedLoad;

	/// <summary>Creates the provider for a vault file using the Windows DPAPI protector.</summary>
	public VaultTokenProvider(string tokenFilePath)
		: this(tokenFilePath, static () => new DpapiSecretProtector())
	{
	}

	/// <summary>Creates the provider with an explicit protector factory (used by tests).</summary>
	internal VaultTokenProvider(string tokenFilePath, Func<ISecretProtector> protectorFactory)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(tokenFilePath);
		ArgumentNullException.ThrowIfNull(protectorFactory);
		_tokenFilePath = tokenFilePath;
		_protectorFactory = protectorFactory;
		_cachedLoad = new Lazy<Task<string>>(LoadOnceAsync, LazyThreadSafetyMode.ExecutionAndPublication);
	}

	/// <inheritdoc />
	public Task<string> GetTokenAsync(CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return _cachedLoad.Value;
	}

	private Task<string> LoadOnceAsync()
	{
		ISecretProtector protector = _protectorFactory();
		WebTokenVault vault = new(protector, _tokenFilePath);
		return Task.FromResult(vault.LoadToken());
	}
}

// File:    tests/RdpAudit.Service.Tests/ApiTokenResolverTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for ApiTokenResolver: constructor contract, bearer-token extraction from
//          Authorization headers, and constant-time validation that never succeeds for empty,
//          differently sized, or misspelled tokens.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using RdpAudit.Service.RestApi;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ApiTokenResolverTests
{
	private const string ExpectedToken = "rdp-api-super-secret-token";

	private static ApiTokenResolver CreateResolver() => new(ExpectedToken);

	[Fact]
	public void Constructor_WithNullToken_Throws()
	{
		ArgumentException ex = Assert.Throws<ArgumentException>(() => new ApiTokenResolver(null!));
		Assert.Equal("expectedToken", ex.ParamName);
	}

	[Fact]
	public void Constructor_WithEmptyToken_Throws()
	{
		Assert.Throws<ArgumentException>(() => new ApiTokenResolver(string.Empty));
	}

	[Fact]
	public void Constructor_WithWhitespaceToken_DoesNotThrow()
	{
		// Only null/empty are rejected here; blank tokens are refused earlier by the
		// fail-closed RestApiPlanBuilder before a resolver is ever constructed.
		ApiTokenResolver resolver = new(" \t ");
		Assert.False(resolver.IsValid(ExpectedToken));
	}

	[Fact]
	public void ExtractBearerToken_WithNullHeaders_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => ApiTokenResolver.ExtractBearerToken(null!));
	}

	[Fact]
	public void ExtractBearerToken_WithoutAuthorizationHeader_ReturnsNull()
	{
		IHeaderDictionary headers = new HeaderDictionary();

		string? token = ApiTokenResolver.ExtractBearerToken(headers);

		Assert.Null(token);
	}

	[Fact]
	public void ExtractBearerToken_WithMultipleValues_ReturnsNull()
	{
		IHeaderDictionary headers = new HeaderDictionary
		{
			[HeaderNames.Authorization] = new[] { "Bearer first", "Bearer second" },
		};

		string? token = ApiTokenResolver.ExtractBearerToken(headers);

		Assert.Null(token);
	}

	[Fact]
	public void ExtractBearerToken_WithBlankValue_ReturnsNull()
	{
		IHeaderDictionary headers = new HeaderDictionary
		{
			[HeaderNames.Authorization] = "   ",
		};

		string? token = ApiTokenResolver.ExtractBearerToken(headers);

		Assert.Null(token);
	}

	[Fact]
	public void ExtractBearerToken_WithNonBearerScheme_ReturnsNull()
	{
		IHeaderDictionary headers = new HeaderDictionary
		{
			[HeaderNames.Authorization] = "Basic dXNlcjpwYXNz",
		};

		string? token = ApiTokenResolver.ExtractBearerToken(headers);

		Assert.Null(token);
	}

	[Fact]
	public void ExtractBearerToken_WithoutSpaceSeparator_ReturnsNull()
	{
		IHeaderDictionary headers = new HeaderDictionary
		{
			[HeaderNames.Authorization] = "Bearersecret",
		};

		string? token = ApiTokenResolver.ExtractBearerToken(headers);

		Assert.Null(token);
	}

	[Fact]
	public void ExtractBearerToken_WithEmptyTokenPart_ReturnsNull()
	{
		IHeaderDictionary headers = new HeaderDictionary
		{
			[HeaderNames.Authorization] = "Bearer ",
		};

		string? token = ApiTokenResolver.ExtractBearerToken(headers);

		Assert.Null(token);
	}

	[Fact]
	public void ExtractBearerToken_WithWhitespaceOnlyTokenPart_ReturnsNull()
	{
		IHeaderDictionary headers = new HeaderDictionary
		{
			[HeaderNames.Authorization] = "Bearer   ",
		};

		string? token = ApiTokenResolver.ExtractBearerToken(headers);

		Assert.Null(token);
	}

	[Fact]
	public void ExtractBearerToken_WithMixedCaseScheme_ReturnsToken()
	{
		IHeaderDictionary headers = new HeaderDictionary
		{
			[HeaderNames.Authorization] = "bearer TOKEN-VALUE",
		};

		string? token = ApiTokenResolver.ExtractBearerToken(headers);

		Assert.Equal("TOKEN-VALUE", token);
	}

	[Fact]
	public void ExtractBearerToken_WithLeadingTrailingWhitespace_TrimsToken()
	{
		IHeaderDictionary headers = new HeaderDictionary
		{
			[HeaderNames.Authorization] = "Bearer   padded-token  ",
		};

		string? token = ApiTokenResolver.ExtractBearerToken(headers);

		Assert.Equal("padded-token", token);
	}

	[Fact]
	public void IsValid_WithNull_ReturnsFalse()
	{
		Assert.False(CreateResolver().IsValid(null));
	}

	[Fact]
	public void IsValid_WithEmpty_ReturnsFalse()
	{
		Assert.False(CreateResolver().IsValid(string.Empty));
	}

	[Fact]
	public void IsValid_WithExactToken_ReturnsTrue()
	{
		Assert.True(CreateResolver().IsValid(ExpectedToken));
	}

	[Fact]
	public void IsValid_WithWrongTokenOfSameLength_ReturnsFalse()
	{
		string wrong = new('x', ExpectedToken.Length);

		Assert.False(CreateResolver().IsValid(wrong));
	}

	[Fact]
	public void IsValid_WithWrongTokenOfDifferentLength_ReturnsFalse()
	{
		Assert.False(CreateResolver().IsValid(ExpectedToken + "-tail"));
	}

	[Fact]
	public void IsValid_WithCaseMismatch_ReturnsFalse()
	{
		Assert.False(CreateResolver().IsValid(ExpectedToken.ToUpperInvariant()));
	}
}

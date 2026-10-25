// File:    src/RdpAudit.Service/RestApi/RestApiOpenApiDocument.cs
// Module:  RdpAudit.Service.RestApi
// Purpose: Loads the committed OpenAPI 3.0 descriptor embedded into the Service assembly and
//          serves it verbatim from /openapi/v1.json. The embedded copy is the single source of
//          truth; the drift scenario test asserts that the committed docs/openapi.json matches it.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Reflection;

namespace RdpAudit.Service.RestApi;

public static class RestApiOpenApiDocument
{
	/// <summary>Logical resource name assigned in RdpAudit.Service.csproj.</summary>
	internal const string ResourceName = "RdpAudit.Service.RestApi.openapi-v1.json";

	private static readonly Lazy<string> LazyContent = new(LoadContent);

	/// <summary>The descriptor text, loaded once from the embedded resource.</summary>
	public static string Content => LazyContent.Value;

	private static string LoadContent()
	{
		Assembly assembly = typeof(RestApiOpenApiDocument).Assembly;
		using Stream? stream = assembly.GetManifestResourceStream(ResourceName);
		if (stream is null)
		{
			throw new InvalidOperationException(
				"Embedded OpenAPI descriptor was not found: " + ResourceName);
		}

		using StreamReader reader = new(stream);
		return reader.ReadToEnd();
	}
}

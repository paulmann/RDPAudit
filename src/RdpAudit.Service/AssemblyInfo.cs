// File:    src/RdpAudit.Service/AssemblyInfo.cs
// Module:  RdpAudit.Service
// Purpose: Exposes internals to the test assembly so unit tests can target builders / parsers
//          that are not part of the public surface.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("RdpAudit.Service.Tests")]

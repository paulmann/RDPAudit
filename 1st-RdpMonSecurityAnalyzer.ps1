#requires -Version 7.5
#requires -PSEdition Core

<#
.SYNOPSIS
	1st rdpmon Security Analyzer
	Advanced RDP Monitor Analyzer for Cameyo RdpMon LiteDB database with auto-installation
	Reads and analyzes RDP authentication attempts with professional reporting

.DESCRIPTION
	PowerShell module to query and analyze RDP login attempts stored in Cameyo RdpMon LiteDB database.
	Provides comprehensive filtering, multiple output formats, modern HTML reporting with auto-refresh,
	and automatic LiteDB installation from GitHub releases.

.AUTHOR
	Mikhail Deynekin [deynekin.com]
	GitHub Repository: https://github.com/paulmann/RDPAudit

.VERSION
	1.0.0

.LICENSE
	MIT License

.NOTES
	Requires PowerShell 7.5+ and LiteDB 5.0.21+ assembly
	Compatible with Windows 7+/Server 2008R2+
	Modern HTML reports use Tailwind CSS CDN for responsive design
	Features automatic LiteDB installation from GitHub releases

.PARAMETER DbPath
	Path to RdpMon LiteDB database file (.db)

.PARAMETER LiteDbPath
	Custom path to LiteDB assembly (LiteDB.dll) or installation directory

.PARAMETER LiteDbInstallPath
	Custom installation path for LiteDB auto-installation (default: $PSScriptRoot\LiteDB)

.PARAMETER AutoInstallLiteDb
	Automatically install LiteDB from GitHub if not found (requires internet)

.PARAMETER LiteDbVersion
	Specific LiteDB version to install (e.g., "4.1.4"). Default: 4.1.4 - Used in cameyo rdpmon

.PARAMETER ForceLiteDbInstall
	Force reinstallation of LiteDB even if already present

.PARAMETER SkipLiteDbInstall
	Skip automatic LiteDB installation even if not found

.PARAMETER Type
	Filter by connection type: All, Attack, Legit, Unknown

.PARAMETER MinFails
	Minimum failed attempts threshold for filtering

.PARAMETER From
	Start date/time filter (local time)

.PARAMETER To
	End date/time filter (local time)

.PARAMETER OutputFormat
	Output format: Table, List, Json, Csv, Xml, Html, Text, Yaml, Markdown, Object

.PARAMETER ExportPath
	Export results to specified file path

.PARAMETER SortBy
	Sort output by specified property

.PARAMETER Descending
	Sort in descending order

.PARAMETER Limit
	Limit number of results returned

.PARAMETER IncludeResolved
	Include DNS-resolved hostnames for IP addresses

.PARAMETER AutoRefreshInterval
	Auto-refresh interval in seconds for HTML reports (default: 30)

.PARAMETER HtmlTemplatePath
	Path to custom HTML template file

.PARAMETER DebugMode
	Enable detailed debugging output showing start, result, and end of each step

.PARAMETER NoProgress
	Disable progress bars during LiteDB installation

.PARAMETER GitHubToken
	GitHub API token for higher rate limits (optional)

.EXAMPLE
	.\1st-RdpMonSecurityAnalyzer.ps1  -DbPath 'C:\Monitoring\RdpMon.db' -AutoInstallLiteDb

.EXAMPLE
	.\1st-RdpMonSecurityAnalyzer.ps1  -DbPath 'C:\RdpMon.db' -LiteDbInstallPath 'C:\Libraries\LiteDB' -ForceLiteDbInstall

.EXAMPLE
	.\1st-RdpMonSecurityAnalyzer.ps1  -DbPath 'C:\RdpMon.db' -LiteDbVersion "5.0.21" -OutputFormat Html -ExportPath 'report.html'

.EXAMPLE
	.\1st-RdpMonSecurityAnalyzer.ps1  -DbPath 'C:\RdpMon.db' -AutoInstallLiteDb -DebugMode

.LINK
	https://github.com/cameyo/rdpmon
	https://deynekin.com
	https://github.com/mbdavid/LiteDB
#>

using namespace System.IO
using namespace System.Collections.Generic
using namespace System.Collections.Specialized
using namespace System.Net.Http
using namespace System.Text.Json
using namespace System.Text.Encodings.Web
using namespace System.Text.Json

[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
	# Path to RdpMon LiteDB database file (.db)
	[Parameter(Mandatory, Position = 0)]
	[ValidateScript({ 
			if (-not (Test-Path -Path $_ -PathType Leaf)) {
				throw "Database file not found: $_"
			}
			if ($_ -notmatch '\.db$') {
				throw "File must have .db extension: $_"
			}
			$true
		})]
	[Alias('Database', 'Path')]
	[string]$DbPath,

	# Custom path to LiteDB assembly (LiteDB.dll) or installation directory
	[Parameter()]
	[ValidateScript({
			if ($_ -and -not (Test-Path -Path $_)) {
				throw "Path not found: $_"
			}
			$true
		})]
	[string]$LiteDbPath,

	# Add these parameters after existing ones in the param() block
	[Parameter()]
	[switch]$RepairDatabase,

	[Parameter()]
	[switch]$ExportRawData,

	[Parameter()]
	[string]$RepairOutputPath,

	[Parameter()]
	[string]$RawExportPath = "RdpMon_RawExport.csv",


	# Custom installation path for LiteDB auto-installation
	[Parameter()]
	[string]$LiteDbInstallPath,

	# Automatically install LiteDB from GitHub if not found
	[Parameter()]
	[switch]$AutoInstallLiteDb,

	# Specific LiteDB version to install
	[Parameter()]
	[ValidatePattern('^(\d+\.\d+\.\d+|latest)$')]
	[string]$LiteDbVersion = 'latest',

	# Force reinstallation of LiteDB even if already present
	[Parameter()]
	[switch]$ForceLiteDbInstall,

	# Skip automatic LiteDB installation even if not found
	[Parameter()]
	[switch]$SkipLiteDbInstall,

	# Filter by connection type: All, Attack, Legit, Unknown
	[Parameter(Position = 1)]
	[ValidateSet('All', 'Attack', 'Legit', 'Unknown')]
	[string]$Type = 'All',

	# Minimum failed attempts threshold for filtering
	[Parameter()]
	[ValidateRange(0, [int]::MaxValue)]
	[int]$MinFails = 0,

        # Start date/time filter (local time)
        [Parameter()]
        [datetime]$From = [datetime]::MinValue,

        # End date/time filter (local time)
        [Parameter()]
        [datetime]$To = [datetime]::MaxValue,

        # Filter by IP address (single IPv4/IPv6 or string key in Addr._id)
        [Parameter()]
        [ValidatePattern('^[0-9a-fA-F\.:]+$')]
        [string]$IpAddress,

        # Output format: Table, List, Json, Csv, Xml, Html, Text, Yaml, Markdown, Object
        [Parameter()]
        [ValidateSet('Table', 'List', 'Json', 'Csv', 'Xml', 'Html', 'Text', 'Yaml', 'Markdown', 'Object')]
        [string]$OutputFormat = 'Table',

	# Export results to specified file path
	[Parameter()]
	[string]$ExportPath,

	# Sort output by specified property
	[Parameter()]
	[ValidateSet('IP', 'FailCount', 'SuccessCount', 'FirstLocal', 'LastLocal', 'Duration')]
	[string]$SortBy = 'LastLocal',

	# Sort in descending order
	[Parameter()]
	[switch]$Descending,

	# Limit number of results returned
	[Parameter()]
	[ValidateRange(1, 1000)]
	[int]$Limit = [int]::MaxValue,

	# Include DNS-resolved hostnames for IP addresses
	[Parameter()]
	[switch]$IncludeResolved,

	# Auto-refresh interval in seconds for HTML reports
	[Parameter()]
	[ValidateRange(5, 3600)]
	[int]$AutoRefreshInterval = 30,

	# Path to custom HTML template file
	[Parameter()]
	[string]$HtmlTemplatePath,

	# Enable detailed debugging output showing start, result, and end of each step
	[Parameter()]
	[switch]$DebugMode,

	# Disable progress bars during LiteDB installation
	[Parameter()]
	[switch]$NoProgress,

	# GitHub API token for higher rate limits
	[Parameter()]
	[string]$GitHubToken
)

#region Global Configuration
# ============================================================================
# GLOBAL CONFIGURATION SECTION
# ============================================================================

# LiteDB installation configuration
$global:LiteDbConfig = @{
	# Default installation path (relative to script directory)
	DefaultInstallPath  = Join-Path -Path $PSScriptRoot -ChildPath "LiteDB"
	
	# GitHub repository information
	GitHubRepoOwner     = "mbdavid"
	GitHubRepoName      = "LiteDB"
	
	# GitHub API configuration
	GitHubApiBaseUrl    = "https://api.github.com"
	GitHubReleasesUrl   = "https://api.github.com/repos/{0}/{1}/releases"
	GitHubRawBaseUrl    = "https://github.com"
	
	# LiteDB assembly names (in order of preference)
	AssemblyNames       = @("LiteDB.dll", "LiteDB.v5.dll", "LiteDB.NET.dll", "LiteDB.5.dll")
	
	# Asset name patterns to look for
	AssetPatterns       = @(
		"LiteDB.*.zip",          # Source code archives
		"LiteDB.*.nupkg",        # NuGet packages
		"LiteDB.*win*.zip",      # Windows binaries
		"*.zip"                  # Generic zip files
	)
	
	# Required .NET versions
	RequiredNetVersions = @("netstandard2.0", "netcoreapp3.1", "net5.0", "net6.0", "net7.0", "net8.0")
	
	# Cache directory for downloads
	CacheDirectory      = Join-Path -Path $env:TEMP -ChildPath "LiteDBCache"
}

# Script execution configuration
$global:ScriptConfig = @{
	Name                     = "1st-RdpMonSecurityAnalyzer.ps1"
	Version                  = "1.0.0"
	MinimumPowerShellVersion = [Version]"7.5.0"
	MinimumLiteDbVersion     = [Version]"4.1.4"
	Git                      = "https://github.com/paulmann/RDPAudit"
	UserAgent                = "RdpMon-PowerShell/3.0.0 (+https://github.com/paulmann/RDPAudit)"
	HTMLTemplate             = "1st-RdpMonSecurityAnalyzer.html"
	TimeoutSeconds           = 30
	RetryAttempts            = 3
	RetryDelayMs             = 1000
}

# Performance and cache configuration
$global:PerformanceConfig = @{
	EnableAssemblyCache  = $true
	MaxAssemblyCacheSize = 5
	EnableDnsCache       = $true
	MaxDnsCacheSize      = 100
	EnableDownloadCache  = $true
	MaxCacheAgeDays      = 7
}

# UI and output configuration
$global:UiConfig = @{
	ProgressStyle = 'Detailed'  # Simple, Detailed, Minimal, None
	ColorOutput   = $true
	EnableUnicode = $true
	ShowBanner    = $true
	ShowSummary   = $true
}

# Debug and logging configuration
$global:DebugConfig = @{
	Enabled     = $DebugMode
	LogLevel    = 'Verbose'  # Error, Warning, Info, Verbose, Debug
	LogToFile   = $false
	LogFilePath = Join-Path -Path $env:TEMP -ChildPath "RdpMonAnalyzer.log"
}

# Initialize global variables
$global:ScriptStartTime = Get-Date
$global:ScriptPhase = "Initialization"
$global:LiteDbAssembly = $null
$global:DatabaseConnection = $null
$global:DatabaseCollection = $null
$global:TotalRecordsProcessed = 0
$global:FilteredRecords = 0
$global:ResultsCollection = @()
$global:ResolvedHostnamesCache = @{}
$global:StepCounter = 0
$global:LastOperationStatus = "Not Started"
$global:OperationStartTime = $null

# Apply parameter overrides
if ($DebugMode) { $global:DebugConfig.Enabled = $true }
if ($NoProgress) { $global:UiConfig.ProgressStyle = 'None' }
if ($LiteDbInstallPath) { $global:LiteDbConfig.DefaultInstallPath = $LiteDbInstallPath }
#endregion

#region Core Functions
function Write-DebugStep {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$Phase,
		
		[Parameter(Mandatory)]
		[string]$Message,
		
		[Parameter()]
		[object]$Data = $null,
		
		[Parameter()]
		[ValidateSet('Start', 'Progress', 'Complete', 'Error', 'Warning', 'Info')]
		[string]$Type = 'Progress'
	)
	
	if (-not $global:DebugConfig.Enabled) {
		return
	}
	
	$global:StepCounter++
	$timestamp = Get-Date -Format "HH:mm:ss.fff"
	$stepFormatted = $global:StepCounter.ToString("D3")
	
	switch ($Type) {
		'Start' {
			$global:OperationStartTime = Get-Date
			$global:ScriptPhase = $Phase
			$global:LastOperationStatus = "Starting: $Message"
			
			Write-Host "`n[$timestamp] ┌── STEP ${stepFormatted}: $Phase" -ForegroundColor Cyan
			Write-Host "[$timestamp] │   START: $Message" -ForegroundColor Cyan
			if ($Data) {
				Write-Host "[$timestamp] │   DATA: $($Data | ConvertTo-Json -Depth 2 -Compress)" -ForegroundColor DarkCyan
			}
		}
		
		'Progress' {
			Write-Host "[$timestamp] │   INFO: $Message" -ForegroundColor Gray
			if ($Data) {
				Write-Host "[$timestamp] │   DATA: $($Data | ConvertTo-Json -Depth 2 -Compress)" -ForegroundColor DarkGray
			}
		}
		
		'Complete' {
			$duration = if ($global:OperationStartTime) {
				[math]::Round(((Get-Date) - $global:OperationStartTime).TotalMilliseconds, 2)
			}
			else { 0 }
			
			Write-Host "[$timestamp] │   COMPLETE: $Message" -ForegroundColor Green
			Write-Host "[$timestamp] │   DURATION: ${duration}ms" -ForegroundColor DarkGreen
			Write-Host "[$timestamp] └──" -ForegroundColor Cyan
			
			$global:LastOperationStatus = "Completed: $Message"
		}
		
		'Error' {
			Write-Host "[$timestamp] │   ERROR: $Message" -ForegroundColor Red
			if ($Data) {
				Write-Host "[$timestamp] │   DATA: $($Data | ConvertTo-Json -Depth 2 -Compress)" -ForegroundColor DarkRed
			}
			Write-Host "[$timestamp] └── [FAILED]" -ForegroundColor Red
			
			$global:LastOperationStatus = "Failed: $Message"
		}
		
		'Warning' {
			Write-Host "[$timestamp] │   WARNING: $Message" -ForegroundColor Yellow
			if ($Data) {
				Write-Host "[$timestamp] │   DATA: $($Data | ConvertTo-Json -Depth 2 -Compress)" -ForegroundColor DarkYellow
			}
		}
		
		'Info' {
			Write-Host "[$timestamp] │   INFO: $Message" -ForegroundColor Blue
			if ($Data) {
				Write-Host "[$timestamp] │   DATA: $($Data | ConvertTo-Json -Depth 2 -Compress)" -ForegroundColor DarkBlue
			}
		}
	}
}

#region Database Diagnostics
function Get-RdpMonDatabaseStructure {
	[CmdletBinding()]
	param()
	
	return Measure-Operation -Name "DatabaseDiagnostics" -ScriptBlock {
		Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Analyzing RdpMon database structure (safe mode)" -Type 'Start'
		
		try {
			# Get all collections using safe method
			$collectionNames = @()
			try {
				$collectionNames = $global:DatabaseConnection.GetCollectionNames()
			}
			catch {
				Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Failed to get collection names, trying alternative method" -Type 'Warning' -Data @{ Error = $_.Exception.Message }
				# Try to read directly from system collection
				$systemCollection = $global:DatabaseConnection.GetCollection("_collections")
				if ($systemCollection) {
					foreach ($col in $systemCollection.FindAll()) {
						if ($col.ContainsKey('name')) {
							$collectionNames += $col['name']
						}
					}
				}
			}
			
			if (-not $collectionNames -or $collectionNames.Count -eq 0) {
				# If still no collections, try known RdpMon collections
				$collectionNames = @("Addr", "Session", "Prop", "Process")
			}
			
			Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Collections to analyze: $($collectionNames -join ', ')" -Type 'Info'
			
			$structure = @{}
			$errors = @()
			
			foreach ($collectionName in $collectionNames) {
				Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Analyzing collection: $collectionName" -Type 'Progress'
				
				try {
					$collection = $null
					try {
						$collection = $global:DatabaseConnection.GetCollection($collectionName)
					}
					catch {
						Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Cannot access collection ${collectionName}, skipping" -Type 'Warning'
						$errors += "Cannot access collection ${collectionName}: ${_}"
						continue
					}
					
					$count = 0
					try {
						$count = $collection.Count()
					}
					catch {
						Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Cannot count collection $collectionName" -Type 'Warning'
						$count = -1
					}
					
					if ($count -gt 0) {
						# Get first record only for analysis - avoid reading damaged data
						$sampleRecords = @()
						try {
							$firstRecord = $collection.FindById(1)  # Try by ID first
							if (-not $firstRecord) {
								# Try to get any record
								$enumerator = $collection.FindAll().GetEnumerator()
								if ($enumerator.MoveNext()) {
									$firstRecord = $enumerator.Current
								}
							}
							
							if ($firstRecord) {
								$recordAnalysis = @{}
								foreach ($key in $firstRecord.Keys) {
									if ($key -ne 'RawRecord' -and $key -ne '_raw') {
										# Avoid circular references
										$value = $firstRecord[$key]
										$recordAnalysis[$key] = @{
											Type   = if ($value) { $value.GetType().Name } else { 'Null' }
											Value  = if ($value) { $value.ToString().Substring(0, [math]::Min(50, $value.ToString().Length)) } else { 'null' }
											IsNull = $value -eq $null
										}
									}
								}
								$sampleRecords += $recordAnalysis
							}
						}
						catch {
							Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Cannot read sample from ${collectionName}" -Type 'Warning'
							$sampleRecords = @()
						}
						
						$structure[$collectionName] = @{
							Count  = $count
							Sample = $sampleRecords
							Fields = if ($sampleRecords.Count -gt 0) { ($sampleRecords[0].Keys | Sort-Object) -join ', ' } else { "Cannot read fields" }
							Status = "OK"
						}
					}
					elseif ($count -eq 0) {
						$structure[$collectionName] = @{
							Count  = 0
							Sample = @()
							Fields = "Empty collection"
							Status = "Empty"
						}
					}
					else {
						$structure[$collectionName] = @{
							Count  = -1
							Sample = @()
							Fields = "Cannot count"
							Status = "Error"
						}
					}
				}
				catch {
					Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Failed to analyze collection ${collectionName}" -Type 'Error' -Data @{ Error = $_.Exception.Message }
					$structure[$collectionName] = @{
						Count  = -1
						Sample = @()
						Fields = "Error"
						Status = "Failed: $_"
					}
					$errors += "Collection ${collectionName}: ${_}"
				}
			}
			
			Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Database structure analysis completed (with errors)" -Type 'Complete' -Data @{
				Collections = $collectionNames
				Structure   = $structure
				ErrorCount  = $errors.Count
			}
			
			if ($errors.Count -gt 0) {
				Write-Host "WARNING: Database has $($errors.Count) errors. Some data may be corrupted." -ForegroundColor Yellow
				foreach ($error in $errors) {
					Write-Host "  - $error" -ForegroundColor DarkYellow
				}
			}
			
			return @{
				Collections = $collectionNames
				Structure   = $structure
				Errors      = $errors
				IsCorrupted = ($errors.Count -gt 0)
			}
		}
		catch {
			Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Failed to analyze database structure completely" -Type 'Error' -Data @{ Error = $_.Exception.Message }
			
			# Return minimal structure
			return @{
				Collections = @("Addr", "Session", "Prop", "Process")
				Structure   = @{}
				Errors      = @("Complete analysis failed: $_")
				IsCorrupted = $true
			}
		}
	}
}
#endregion


function Measure-Operation {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$Name,
		
		[Parameter(Mandatory)]
		[ScriptBlock]$ScriptBlock,
		
		[Parameter()]
		[object[]]$ArgumentList = @(),
		
		[Parameter()]
		[switch]$SuppressDebug
	)
	
	if (-not $SuppressDebug) {
		Write-DebugStep -Phase $Name -Message "Starting operation" -Type 'Start'
	}
	
	try {
		$result = & $ScriptBlock @ArgumentList
		
		if (-not $SuppressDebug) {
			Write-DebugStep -Phase $Name -Message "Operation completed successfully" -Type 'Complete'
		}
		
		return $result
	}
	catch {
		if (-not $SuppressDebug) {
			Write-DebugStep -Phase $Name -Message "Operation failed: $_" -Type 'Error' -Data @{ Error = $_.Exception.Message }
		}
		throw
	}
}

function Show-Progress {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$Activity,
		
		[Parameter()]
		[string]$Status,
		
		[Parameter()]
		[int]$PercentComplete = -1,
		
		[Parameter()]
		[int]$SecondsRemaining = -1,
		
		[Parameter()]
		[switch]$Completed
	)
	
	if ($global:UiConfig.ProgressStyle -eq 'None') {
		return
	}
	
	switch ($global:UiConfig.ProgressStyle) {
		'Detailed' {
			if ($Completed) {
				Write-Progress -Activity $Activity -Completed
			}
			else {
				$params = @{
					Activity = $Activity
					Status   = $Status
				}
				
				if ($PercentComplete -ge 0) {
					$params.PercentComplete = $PercentComplete
				}
				
				if ($SecondsRemaining -ge 0) {
					$params.SecondsRemaining = $SecondsRemaining
				}
				
				Write-Progress @params
			}
		}
		
		'Simple' {
			if (-not $Completed) {
				Write-Host "[$(Get-Date -Format 'HH:mm:ss')] ${Activity}: ${Status}" -ForegroundColor Gray
			}
		}
		
		'Minimal' {
			if (-not $Completed) {
				Write-Host "." -NoNewline -ForegroundColor Gray
			}
			else {
				Write-Host ""
			}
		}
	}
}
#endregion

#region LiteDB Installation Functions
function Install-LiteDbAutomatically {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string]$InstallPath = $global:LiteDbConfig.DefaultInstallPath,
		
		[Parameter()]
		[string]$Version = 'latest',
		
		[Parameter()]
		[switch]$Force,
		
		[Parameter()]
		[switch]$NoProgress
	)
	
	return Measure-Operation -Name "AutoInstallLiteDb" -ScriptBlock {
		Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Starting automatic LiteDB installation" -Type 'Start' -Data @{
			InstallPath = $InstallPath
			Version     = $Version
			Force       = $Force
		}
		
		# Check if already installed
		$existingInstall = Test-LiteDbInstallation -InstallPath $InstallPath
		if ($existingInstall.Installed -and -not $Force) {
			Write-DebugStep -Phase "AutoInstallLiteDb" -Message "LiteDB already installed, skipping installation" -Type 'Info' -Data @{
				Version = $existingInstall.Version
				Path    = $existingInstall.AssemblyPath
			}
			return $existingInstall.AssemblyPath
		}
		
		# Ensure install directory exists
		if (-not (Test-Path -Path $InstallPath)) {
			Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Creating installation directory" -Type 'Progress' -Data @{ Path = $InstallPath }
			New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
		}
		
		# Step 1: Get release information from GitHub
		Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Fetching LiteDB release information from GitHub" -Type 'Progress'
		$releaseInfo = Get-LiteDbGitHubRelease -Version $Version
		
		if (-not $releaseInfo) {
			throw "Failed to get LiteDB release information from GitHub"
		}
		
		Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Found release: $($releaseInfo.TagName)" -Type 'Info' -Data @{
			Version = $releaseInfo.TagName
			Assets  = $releaseInfo.Assets.Count
		}
		
		# Step 2: Download and extract the release
		Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Downloading and extracting LiteDB release" -Type 'Progress'
		$extractedPath = Install-LiteDbFromGitHubRelease -Release $releaseInfo -InstallPath $InstallPath -NoProgress:$NoProgress
		
		if (-not $extractedPath -or -not (Test-Path -Path $extractedPath)) {
			throw "Failed to download and extract LiteDB release"
		}
		
		# Step 3: Find and verify LiteDB assembly
		Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Locating LiteDB assembly in extracted files" -Type 'Progress'
		$assemblyPath = Find-LiteDbAssembly -SearchPath $extractedPath
		
		if (-not $assemblyPath) {
			throw "Could not find LiteDB assembly in the downloaded release"
		}
		
		# Step 4: Copy assembly to install directory
		Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Copying LiteDB assembly to installation directory" -Type 'Progress' -Data @{
			Source      = $assemblyPath
			Destination = $InstallPath
		}
		
		$targetAssemblyPath = Join-Path -Path $InstallPath -ChildPath (Split-Path -Leaf $assemblyPath)
		Copy-Item -Path $assemblyPath -Destination $targetAssemblyPath -Force
		
		# Step 5: Verify the assembly can be loaded
		Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Verifying assembly can be loaded" -Type 'Progress'
		try {
			$assembly = Add-Type -Path $targetAssemblyPath -ErrorAction Stop -PassThru
			Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Assembly loaded successfully" -Type 'Info' -Data @{
				FullName = $assembly.FullName
				Location = $assembly.Location
			}
		}
		catch {
			Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Failed to load assembly" -Type 'Warning' -Data @{ Error = $_.Exception.Message }
			# Try to load via reflection as fallback
			$assemblyBytes = [System.IO.File]::ReadAllBytes($targetAssemblyPath)
			[System.Reflection.Assembly]::Load($assemblyBytes) | Out-Null
			Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Assembly loaded via reflection" -Type 'Info'
		}
		
		# Step 6: Create version file
		$versionFile = Join-Path -Path $InstallPath -ChildPath "version.txt"
		Set-Content -Path $versionFile -Value $releaseInfo.TagName -Encoding UTF8
		
		Write-DebugStep -Phase "AutoInstallLiteDb" -Message "LiteDB installation completed successfully" -Type 'Complete' -Data @{
			Version      = $releaseInfo.TagName
			InstallPath  = $InstallPath
			AssemblyPath = $targetAssemblyPath
		}
		
		return $targetAssemblyPath
	}
}

function Get-LiteDbGitHubRelease {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string]$Version = 'latest'
	)
	
	return Measure-Operation -Name "GetGitHubRelease" -ScriptBlock {
		$owner = $global:LiteDbConfig.GitHubRepoOwner
		$repo = $global:LiteDbConfig.GitHubRepoName
		
		Write-DebugStep -Phase "GetGitHubRelease" -Message "Fetching LiteDB release from GitHub" -Type 'Progress' -Data @{
			Owner   = $owner
			Repo    = $repo
			Version = $Version
		}
		
		# Build GitHub API URL
		$apiUrl = if ($Version -eq 'latest') {
			"$($global:LiteDbConfig.GitHubApiBaseUrl)/repos/$owner/$repo/releases/latest"
		}
		else {
			"$($global:LiteDbConfig.GitHubApiBaseUrl)/repos/$owner/$repo/releases/tags/$Version"
		}
		
		# Prepare headers
		$headers = @{
			'Accept'               = 'application/vnd.github+json'
			'User-Agent'           = $global:ScriptConfig.UserAgent
			'X-GitHub-Api-Version' = '2022-11-28'
		}
		
		# Add token if provided
		if ($GitHubToken) {
			$headers.Authorization = "Bearer $GitHubToken"
		}
		
		try {
			Show-Progress -Activity "Fetching LiteDB Release" -Status "Connecting to GitHub API..." -PercentComplete 25
			
			# Make API request with retry logic
			$maxRetries = $global:ScriptConfig.RetryAttempts
			$retryCount = 0
			
			while ($true) {
				try {
					$response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -TimeoutSec $global:ScriptConfig.TimeoutSeconds
					break
				}
				catch {
					$retryCount++
					if ($retryCount -ge $maxRetries) {
						throw "Failed to fetch GitHub release after $maxRetries attempts: $_"
					}
					
					Write-DebugStep -Phase "GetGitHubRelease" -Message "Request failed, retrying ($retryCount/$maxRetries)" -Type 'Warning' -Data @{ Error = $_.Exception.Message }
					Start-Sleep -Milliseconds ($global:ScriptConfig.RetryDelayMs * $retryCount)
				}
			}
			
			Show-Progress -Activity "Fetching LiteDB Release" -Status "Processing release data..." -PercentComplete 75
			
			# Parse response
			$releaseInfo = @{
				TagName      = $response.tag_name
				Name         = $response.name
				PublishedAt  = $response.published_at
				Assets       = $response.assets
				Body         = $response.body
				Url          = $response.html_url
				IsPrerelease = $response.prerelease
				AssetsCount  = $response.assets.Count
			}
			
			Show-Progress -Activity "Fetching LiteDB Release" -Status "Completed" -PercentComplete 100 -Completed
			
			Write-DebugStep -Phase "GetGitHubRelease" -Message "Successfully fetched release information" -Type 'Progress' -Data @{
				TagName     = $releaseInfo.TagName
				AssetsCount = $releaseInfo.AssetsCount
			}
			
			return $releaseInfo
		}
		catch {
			Show-Progress -Activity "Fetching LiteDB Release" -Status "Failed" -Completed
			
			# Fallback: Try to get releases list and find the latest
			if ($Version -eq 'latest') {
				Write-DebugStep -Phase "GetGitHubRelease" -Message "Trying fallback method to get latest release" -Type 'Warning'
				
				try {
					$releasesUrl = "$($global:LiteDbConfig.GitHubApiBaseUrl)/repos/$owner/$repo/releases"
					$allReleases = Invoke-RestMethod -Uri $releasesUrl -Method Get -Headers $headers -TimeoutSec $global:ScriptConfig.TimeoutSeconds
					
					$latestRelease = $allReleases | Where-Object { -not $_.prerelease } | Select-Object -First 1
					
					if ($latestRelease) {
						$releaseInfo = @{
							TagName      = $latestRelease.tag_name
							Name         = $latestRelease.name
							PublishedAt  = $latestRelease.published_at
							Assets       = $latestRelease.assets
							Body         = $latestRelease.body
							Url          = $latestRelease.html_url
							IsPrerelease = $latestRelease.prerelease
							AssetsCount  = $latestRelease.assets.Count
						}
						
						return $releaseInfo
					}
				}
				catch {
					# If all fails, throw the original error
					throw "Failed to fetch LiteDB release from GitHub: $_"
				}
			}
			
			throw "Failed to fetch LiteDB release from GitHub: $_"
		}
	}
}

function Install-LiteDbFromGitHubRelease {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[hashtable]$Release,
		
		[Parameter()]
		[string]$InstallPath,
		
		[Parameter()]
		[switch]$NoProgress
	)
	
	return Measure-Operation -Name "InstallFromGitHub" -ScriptBlock {
		Write-DebugStep -Phase "InstallFromGitHub" -Message "Installing LiteDB from GitHub release" -Type 'Progress' -Data @{
			Release     = $Release.TagName
			InstallPath = $InstallPath
		}
		
		# Step 1: Find appropriate asset
		$asset = Find-SuitableAsset -Assets $Release.Assets
		
		if (-not $asset) {
			throw "No suitable asset found in the release. Available assets: $($Release.Assets | ForEach-Object { $_.name })"
		}
		
		Write-DebugStep -Phase "InstallFromGitHub" -Message "Selected asset for download" -Type 'Info' -Data @{
			AssetName   = $asset.name
			Size        = "$([math]::Round($asset.size / 1MB, 2)) MB"
			DownloadUrl = $asset.browser_download_url
		}
		
		# Step 2: Download the asset
		$downloadPath = Download-GitHubAsset -Asset $asset -CacheDir $global:LiteDbConfig.CacheDirectory -NoProgress:$NoProgress
		
		if (-not $downloadPath -or -not (Test-Path -Path $downloadPath)) {
			throw "Failed to download asset: $($asset.name)"
		}
		
		# Step 3: Extract the asset
		$extractPath = Extract-Asset -AssetPath $downloadPath -ExtractPath $InstallPath -AssetName $asset.name
		
		if (-not $extractPath -or -not (Test-Path -Path $extractPath)) {
			throw "Failed to extract asset: $($asset.name)"
		}
		
		Write-DebugStep -Phase "InstallFromGitHub" -Message "Asset extracted successfully" -Type 'Progress' -Data @{ ExtractPath = $extractPath }
		
		return $extractPath
	}
}

function Find-SuitableAsset {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[object[]]$Assets
	)
	
	Write-DebugStep -Phase "FindSuitableAsset" -Message "Finding suitable asset from release" -Type 'Progress' -Data @{ AssetCount = $Assets.Count }
	
	# Define asset preferences in order of priority
	$preferredPatterns = @(
		# Windows binaries (prefer ZIP archives)
		'*win-x64*.zip',
		'*win-x86*.zip',
		'*windows*.zip',
		'*win*.zip',
		
		# Platform-independent binaries
		'*.zip',
		'*.nupkg',
		
		# Source code (fallback)
		'*.tar.gz',
		'*.tgz'
	)
	
	foreach ($pattern in $preferredPatterns) {
		$matchingAssets = $Assets | Where-Object { $_.name -like $pattern }
		
		if ($matchingAssets) {
			# Prefer smaller files (they're more likely to be binaries than source)
			$selectedAsset = $matchingAssets | Sort-Object size | Select-Object -First 1
			
			Write-DebugStep -Phase "FindSuitableAsset" -Message "Found asset matching pattern: $pattern" -Type 'Progress' -Data @{
				AssetName = $selectedAsset.name
				Pattern   = $pattern
			}
			
			return $selectedAsset
		}
	}
	
	# If no assets match our patterns, return the first asset
	if ($Assets) {
		Write-DebugStep -Phase "FindSuitableAsset" -Message "No preferred asset found, using first available" -Type 'Warning'
		return $Assets[0]
	}
	
	return $null
}

function Download-GitHubAsset {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[object]$Asset,
		
		[Parameter()]
		[string]$CacheDir = $global:LiteDbConfig.CacheDirectory,
		
		[Parameter()]
		[switch]$NoProgress
	)
	
	return Measure-Operation -Name "DownloadAsset" -ScriptBlock {
		# Create cache directory if it doesn't exist
		if (-not (Test-Path -Path $CacheDir)) {
			New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
		}
		
		# Generate cache key based on asset URL and size
		$cacheKey = "$($Asset.browser_download_url)_$($Asset.size)"
		$cacheHash = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($cacheKey))
		$cacheHashHex = [BitConverter]::ToString($cacheHash).Replace('-', '')
		$cachedFile = Join-Path -Path $CacheDir -ChildPath "$cacheHashHex$( [System.IO.Path]::GetExtension($Asset.name) )"
		
		# Check if file exists in cache and is not too old
		if ($global:PerformanceConfig.EnableDownloadCache -and (Test-Path -Path $cachedFile)) {
			$fileInfo = Get-Item -Path $cachedFile
			$maxAge = (Get-Date).AddDays(-$global:PerformanceConfig.MaxCacheAgeDays)
			
			if ($fileInfo.LastWriteTime -gt $maxAge) {
				Write-DebugStep -Phase "DownloadAsset" -Message "Using cached asset" -Type 'Progress' -Data @{
					CacheFile = $cachedFile
					Age       = ((Get-Date) - $fileInfo.LastWriteTime).Days
				}
				return $cachedFile
			}
		}
		
		Write-DebugStep -Phase "DownloadAsset" -Message "Downloading asset from GitHub" -Type 'Progress' -Data @{
			Url       = $Asset.browser_download_url
			Size      = "$([math]::Round($Asset.size / 1MB, 2)) MB"
			CacheFile = $cachedFile
		}
		
		# Prepare headers
		$headers = @{
			'User-Agent' = $global:ScriptConfig.UserAgent
			'Accept'     = 'application/octet-stream'
		}
		
		# Add token if provided
		if ($GitHubToken) {
			$headers.Authorization = "Bearer $GitHubToken"
		}
		
		try {
			if (-not $NoProgress) {
				Show-Progress -Activity "Downloading LiteDB" -Status "Starting download..." -PercentComplete 0
			}
			
			# Download with progress tracking
			$client = [System.Net.Http.HttpClient]::new()
			$client.DefaultRequestHeaders.UserAgent.ParseAdd($global:ScriptConfig.UserAgent)
			
			if ($GitHubToken) {
				$client.DefaultRequestHeaders.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $GitHubToken)
			}
			
			$response = $client.GetAsync($Asset.browser_download_url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
			
			if ($response.IsSuccessStatusCode) {
				$totalBytes = [long]$response.Content.Headers.ContentLength
				$stream = $response.Content.ReadAsStreamAsync().Result
				$fileStream = [System.IO.File]::Create($cachedFile)
				
				$buffer = New-Object byte[] 8192
				$totalRead = 0
				$read = 0
				
				do {
					$read = $stream.Read($buffer, 0, $buffer.Length)
					$fileStream.Write($buffer, 0, $read)
					$totalRead += $read
					
					if (-not $NoProgress -and $totalBytes -gt 0) {
						$percentComplete = [math]::Min(100, [math]::Round(($totalRead / $totalBytes) * 100))
						Show-Progress -Activity "Downloading LiteDB" -Status "Downloading..." -PercentComplete $percentComplete
					}
				} while ($read -gt 0)
				
				$fileStream.Close()
				$stream.Close()
				
				if (-not $NoProgress) {
					Show-Progress -Activity "Downloading LiteDB" -Status "Download completed" -PercentComplete 100 -Completed
				}
				
				Write-DebugStep -Phase "DownloadAsset" -Message "Asset downloaded successfully" -Type 'Progress' -Data @{
					FileSize  = "$([math]::Round((Get-Item $cachedFile).Length / 1MB, 2)) MB"
					CachePath = $cachedFile
				}
				
				return $cachedFile
			}
			else {
				throw "HTTP error: $($response.StatusCode) - $($response.ReasonPhrase)"
			}
		}
		catch {
			if (-not $NoProgress) {
				Show-Progress -Activity "Downloading LiteDB" -Status "Download failed" -Completed
			}
			
			# Clean up failed download
			if (Test-Path -Path $cachedFile) {
				Remove-Item -Path $cachedFile -Force
			}
			
			throw "Failed to download asset: $_"
		}
		finally {
			if ($client) {
				$client.Dispose()
			}
		}
	}
}

function Add-TestRdpMonData {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$DbPath
	)
	
	# Load LiteDB assembly
	Add-Type -Path "C:\AMD\1stRDP\LiteDB\LiteDB.dll"
	
	# Open database
	$connectionString = "Filename=$DbPath"
	$db = [LiteDB.LiteDatabase]::new($connectionString)
	
	# Get Addr collection
	$addrCollection = $db.GetCollection("Addr")
	
	# Add test data
	$testData = @(
		@{
			_id          = "192.168.1.100"
			FailCount    = 5
			SuccessCount = 0
			First        = [DateTime]::Now.AddDays(-10)
			Last         = [DateTime]::Now.AddDays(-1)
			UserNames    = @("admin", "test")
		},
		@{
			_id          = "10.0.0.50"
			FailCount    = 0
			SuccessCount = 3
			First        = [DateTime]::Now.AddDays(-5)
			Last         = [DateTime]::Now
			UserNames    = @("user1")
		},
		@{
			_id          = "172.16.0.25"
			FailCount    = 2
			SuccessCount = 1
			First        = [DateTime]::Now.AddDays(-3)
			Last         = [DateTime]::Now.AddHours(-2)
			UserNames    = @("admin", "user2")
		}
	)
	
	foreach ($data in $testData) {
		$doc = [LiteDB.BsonDocument]::new()
		foreach ($key in $data.Keys) {
			$doc[$key] = $data[$key]
		}
		$addrCollection.Insert($doc) | Out-Null
	}
	
	$db.Dispose()
	Write-Host "Added $($testData.Count) test records to RdpMon database" -ForegroundColor Green
}

function Extract-Asset {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$AssetPath,
		
		[Parameter(Mandatory)]
		[string]$ExtractPath,
		
		[Parameter(Mandatory)]
		[string]$AssetName
	)
	
	return Measure-Operation -Name "ExtractAsset" -ScriptBlock {
		Write-DebugStep -Phase "ExtractAsset" -Message "Extracting asset" -Type 'Progress' -Data @{
			AssetPath   = $AssetPath
			ExtractPath = $ExtractPath
			AssetName   = $AssetName
		}
		
		# Create extraction directory
		$extractDir = Join-Path -Path $ExtractPath -ChildPath "extracted"
		if (Test-Path -Path $extractDir) {
			Remove-Item -Path $extractDir -Recurse -Force
		}
		
		New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
		
		Show-Progress -Activity "Extracting LiteDB" -Status "Starting extraction..." -PercentComplete 0
		
		try {
			# Determine extraction method based on file extension
			$extension = [System.IO.Path]::GetExtension($AssetName).ToLower()
			
			switch ($extension) {
				'.zip' {
					Write-DebugStep -Phase "ExtractAsset" -Message "Extracting ZIP archive" -Type 'Progress'
					Expand-Archive -Path $AssetPath -DestinationPath $extractDir -Force
				}
				
				'.nupkg' {
					Write-DebugStep -Phase "ExtractAsset" -Message "Extracting NuGet package" -Type 'Progress'
					# NuGet packages are just ZIP files
					Expand-Archive -Path $AssetPath -DestinationPath $extractDir -Force
				}
				
				'.tar.gz' {
					Write-DebugStep -Phase "ExtractAsset" -Message "Extracting TAR.GZ archive" -Type 'Progress'
					# Requires PowerShell 7+ or external tools
					tar -xzf $AssetPath -C $extractDir
				}
				
				'.tgz' {
					Write-DebugStep -Phase "ExtractAsset" -Message "Extracting TGZ archive" -Type 'Progress'
					tar -xzf $AssetPath -C $extractDir
				}
				
				default {
					throw "Unsupported archive format: $extension"
				}
			}
			
			Show-Progress -Activity "Extracting LiteDB" -Status "Extraction completed" -PercentComplete 100 -Completed
			
			Write-DebugStep -Phase "ExtractAsset" -Message "Asset extracted successfully" -Type 'Progress' -Data @{ ExtractDir = $extractDir }
			
			return $extractDir
		}
		catch {
			Show-Progress -Activity "Extracting LiteDB" -Status "Extraction failed" -Completed
			throw "Failed to extract asset: $_"
		}
	}
}

function Find-LiteDbAssembly {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$SearchPath
	)
	
	return Measure-Operation -Name "FindAssembly" -ScriptBlock {
		Write-DebugStep -Phase "FindAssembly" -Message "Searching for LiteDB assembly" -Type 'Progress' -Data @{ SearchPath = $SearchPath }
		
		# Search patterns in order of preference
		$searchPatterns = @(
			# Direct DLL files
			"LiteDB.dll",
			"LiteDB.v5.dll",
			"LiteDB.NET.dll",
			"LiteDB.5.dll",
			
			# DLLs in lib folders (NuGet structure)
			"lib\**\LiteDB.dll",
			"lib\**\LiteDB.v5.dll",
			
			# Any DLL with LiteDB in name
			"*LiteDB*.dll"
		)
		
		foreach ($pattern in $searchPatterns) {
			$foundFiles = Get-ChildItem -Path $SearchPath -Filter $pattern -Recurse -ErrorAction SilentlyContinue | 
			Where-Object { $_.Extension -eq '.dll' }
			
			if ($foundFiles) {
				# Prefer files in lib/netstandard* or lib/netcore* directories
				$preferredFiles = $foundFiles | Where-Object { 
					$_.FullName -match 'lib\\(netstandard|netcore|net[0-9])' 
				}
				
				if ($preferredFiles) {
					$selectedFile = $preferredFiles | Select-Object -First 1
				}
				else {
					$selectedFile = $foundFiles | Select-Object -First 1
				}
				
				Write-DebugStep -Phase "FindAssembly" -Message "Found LiteDB assembly" -Type 'Progress' -Data @{
					Pattern      = $pattern
					AssemblyPath = $selectedFile.FullName
					Size         = "$([math]::Round($selectedFile.Length / 1KB, 2)) KB"
				}
				
				return $selectedFile.FullName
			}
		}
		
		Write-DebugStep -Phase "FindAssembly" -Message "No LiteDB assembly found" -Type 'Warning'
		return $null
	}
}

function Test-LiteDbInstallation {
	[CmdletBinding()]
	param(
		[Parameter()]
		[string]$InstallPath = $global:LiteDbConfig.DefaultInstallPath
	)
	
	return Measure-Operation -Name "TestInstallation" -ScriptBlock -SuppressDebug {
		$result = @{
			Installed    = $false
			Version      = $null
			AssemblyPath = $null
			IsValid      = $false
			Error        = $null
		}
		
		# Check if installation directory exists
		if (-not (Test-Path -Path $InstallPath)) {
			$result.Error = "Installation directory not found: $InstallPath"
			return $result
		}
		
		# Look for version file
		$versionFile = Join-Path -Path $InstallPath -ChildPath "version.txt"
		if (Test-Path -Path $versionFile) {
			$result.Version = Get-Content -Path $versionFile -Raw -ErrorAction SilentlyContinue
		}
		
		# Look for LiteDB assembly
		$assemblyFiles = Get-ChildItem -Path $InstallPath -Filter "LiteDB*.dll" -ErrorAction SilentlyContinue
		
		foreach ($assemblyFile in $assemblyFiles) {
			try {
				# Try to load the assembly to verify it's valid
				$testAssembly = Add-Type -Path $assemblyFile.FullName -ErrorAction Stop -PassThru
				
				$result.Installed = $true
				$result.AssemblyPath = $assemblyFile.FullName
				$result.IsValid = $true
				
				# If no version from file, try to get from assembly
				if (-not $result.Version) {
					$fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($assemblyFile.FullName)
					$result.Version = $fileVersion.FileVersion
				}
				
				break
			}
			catch {
				# Continue to next file
				continue
			}
		}
		
		if (-not $result.Installed) {
			$result.Error = "No valid LiteDB assembly found in: $InstallPath"
		}
		
		return $result
	}
}
#endregion

#region Enhanced Import-LiteDbAssembly Function
function Import-LiteDbAssembly {
	[CmdletBinding()]
	param()
	
	return Measure-Operation -Name "LoadLiteDbAssembly" -ScriptBlock {
		# Check if already loaded
		$loadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies() | 
		Where-Object { $_.FullName -like 'LiteDB*' }
		
		if ($loadedAssemblies) {
			Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "LiteDB assembly already loaded" -Type 'Progress'
			$global:LiteDbAssembly = $loadedAssemblies[0]
			return $loadedAssemblies[0]
		}
		
		# Initialize search paths list
		$searchPaths = [System.Collections.Generic.List[string]]::new()
		
		# Helper function to add paths safely
		function Add-PathGroup {
			param([string[]]$Paths)
			
			foreach ($path in $Paths) {
				if ($path -and -not $searchPaths.Contains($path)) {
					$searchPaths.Add($path)
				}
			}
		}
		
		Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Building LiteDB assembly search paths" -Type 'Progress'
		
		# 1. User-specified path (file or directory)
		if ($LiteDbPath) {
			if (Test-Path -Path $LiteDbPath -PathType Leaf) {
				Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Adding specified LiteDB file path" -Type 'Progress' -Data @{ Path = $LiteDbPath }
				Add-PathGroup -Paths @($LiteDbPath)
			}
			elseif (Test-Path -Path $LiteDbPath -PathType Container) {
				Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Searching specified directory for LiteDB" -Type 'Progress' -Data @{ Path = $LiteDbPath }
				foreach ($assemblyName in $global:LiteDbConfig.AssemblyNames) {
					Add-PathGroup -Paths @(Join-Path -Path $LiteDbPath -ChildPath $assemblyName)
				}
			}
		}
		
		# 2. Check existing installation
		$installPath = $global:LiteDbConfig.DefaultInstallPath
		
		# Local function for testing installation
		function Test-LiteDbInstallationLocal {
			$result = @{
				Installed    = $false
				Version      = $null
				AssemblyPath = $null
				IsValid      = $false
				Error        = $null
			}
			
			# Check if installation directory exists
			if (-not (Test-Path -Path $installPath)) {
				$result.Error = "Installation directory not found: $installPath"
				return $result
			}
			
			# Look for version file
			$versionFile = Join-Path -Path $installPath -ChildPath "version.txt"
			if (Test-Path -Path $versionFile) {
				$result.Version = Get-Content -Path $versionFile -Raw -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() }
			}
			
			# Look for LiteDB assembly - search in root first, then recursively
			$rootAssembly = Get-ChildItem -Path $installPath -Filter "LiteDB*.dll" -Depth 0 -ErrorAction SilentlyContinue
			if (-not $rootAssembly) {
				$assemblyFiles = Get-ChildItem -Path $installPath -Filter "LiteDB*.dll" -Recurse -ErrorAction SilentlyContinue
			}
			else {
				$assemblyFiles = $rootAssembly
			}
			
			foreach ($assemblyFile in $assemblyFiles) {
				try {
					# Try to load the assembly to verify it's valid
					$null = Add-Type -Path $assemblyFile.FullName -ErrorAction Stop
					
					# Get the loaded assembly
					$loadedAssembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | 
					Where-Object { $_.Location -eq $assemblyFile.FullName } | 
					Select-Object -First 1
					
					$result.Installed = $true
					$result.AssemblyPath = $assemblyFile.FullName
					$result.IsValid = $true
					
					# Get version from assembly
					if ($loadedAssembly) {
						try {
							$result.Version = $loadedAssembly.GetName().Version.ToString()
						}
						catch {
							# Try alternative method
							try {
								$fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($assemblyFile.FullName)
								$result.Version = $fileVersion.FileVersion
							}
							catch {
								$result.Version = "Unknown"
							}
						}
					}
					
					break
				}
				catch {
					continue
				}
			}
			
			if (-not $result.Installed) {
				$result.Error = "No valid LiteDB assembly found in: $installPath (searched $($assemblyFiles.Count) files)"
			}
			
			return $result
		}
		
		$installationTest = Test-LiteDbInstallationLocal
		
		if ($installationTest.Installed -and $installationTest.IsValid) {
			Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Found existing LiteDB installation" -Type 'Progress' -Data @{
				Version       = $installationTest.Version
				Path          = $installationTest.AssemblyPath
				SearchedFiles = ($installationTest.AssemblyPath -split "\\")[-1]
			}
			Add-PathGroup -Paths @($installationTest.AssemblyPath)
		}
		
		# 3. Standard search paths
		Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Searching standard locations" -Type 'Progress'
		
		# Script directory
		if ($PSScriptRoot) { 
			foreach ($assemblyName in $global:LiteDbConfig.AssemblyNames) {
				Add-PathGroup -Paths @(Join-Path -Path $PSScriptRoot -ChildPath $assemblyName)
			}
		}
		
		# Database directory
		$dbDir = Split-Path -Path $global:DbPath -Parent
		if ($dbDir) {
			foreach ($assemblyName in $global:LiteDbConfig.AssemblyNames) {
				Add-PathGroup -Paths @(Join-Path -Path $dbDir -ChildPath $assemblyName)
			}
		}
		
		# Current directory
		$currentDir = (Get-Location).Path
		foreach ($assemblyName in $global:LiteDbConfig.AssemblyNames) {
			Add-PathGroup -Paths @(Join-Path -Path $currentDir -ChildPath $assemblyName)
		}
		
		# Program Files directories
		$programFilesPaths = @(
			[Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'LiteDB')
			[Path]::Combine([Environment]::GetFolderPath('ProgramFilesX86'), 'LiteDB')
		)
		
		foreach ($programPath in $programFilesPaths) {
			if (Test-Path -Path $programPath -PathType Container) {
				foreach ($assemblyName in $global:LiteDbConfig.AssemblyNames) {
					Add-PathGroup -Paths @(Join-Path -Path $programPath -ChildPath $assemblyName)
				}
			}
		}
		
		# 4. PATH environment directories
		Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Searching PATH environment directories" -Type 'Progress'
		$pathDirs = $env:PATH -split ';' | Where-Object { $_ -and (Test-Path -Path $_ -PathType Container) } | Select-Object -Unique
		foreach ($pathDir in $pathDirs) {
			foreach ($assemblyName in $global:LiteDbConfig.AssemblyNames) {
				Add-PathGroup -Paths @(Join-Path -Path $pathDir -ChildPath $assemblyName)
			}
		}
		
		Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Searching in $($searchPaths.Count) locations for LiteDB assembly" -Type 'Progress' -Data @{ SearchPathCount = $searchPaths.Count }
		
		# Search for assembly
		$foundAssembly = $null
		$attemptCount = 0
		
		foreach ($assemblyPath in $searchPaths) {
			$attemptCount++
			if (Test-Path -Path $assemblyPath -PathType Leaf) {
				try {
					Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Attempt ${attemptCount}: Found at: ${assemblyPath}" -Type 'Progress'
					
					# Check file signature/size
					$fileInfo = Get-Item -Path $assemblyPath -ErrorAction SilentlyContinue
					if ($fileInfo.Length -lt 1024) {
						Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "File too small, skipping" -Type 'Progress'
						continue
					}
					
					# Load assembly
					Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Loading assembly..." -Type 'Progress'
					
					# Load the assembly and get the assembly object
					$null = Add-Type -Path $assemblyPath -ErrorAction Stop
					$assembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | 
					Where-Object { $_.Location -eq $assemblyPath } | 
					Select-Object -First 1
					
					if (-not $assembly) {
						# If not found by location, try by name
						$assemblyName = [System.IO.Path]::GetFileNameWithoutExtension($assemblyPath)
						$assembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | 
						Where-Object { $_.GetName().Name -eq $assemblyName } | 
						Select-Object -First 1
					}
					
					if ($assembly) {
						$global:LiteDbAssembly = $assembly
						
						# Try to get version info
						try {
							$versionInfo = $assembly.GetName().Version.ToString()
						}
						catch {
							try {
								$fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($assemblyPath)
								$versionInfo = $fileVersion.FileVersion
							}
							catch {
								$versionInfo = "Unknown"
							}
						}
						
						Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Assembly loaded successfully" -Type 'Progress' -Data @{
							Name    = $assembly.FullName
							Version = $versionInfo
						}
						
						$foundAssembly = $assembly
						break
					}
					else {
						throw "Assembly loaded but not found in current domain"
					}
				}
				catch [System.BadImageFormatException] {
					Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Bad image format (wrong architecture)" -Type 'Warning'
					continue
				}
				catch {
					Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Failed to load assembly" -Type 'Warning' -Data @{ 
						Error = $_.Exception.Message
						Path  = $assemblyPath
					}
					continue
				}
			}
		}
		
		# 5. Auto-installation if enabled and assembly not found
		if (-not $foundAssembly -and $AutoInstallLiteDb -and -not $SkipLiteDbInstall) {
			Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Attempting automatic LiteDB installation" -Type 'Info'
			
			try {
				# Simple auto-installation function
				$installResult = Measure-Operation -Name "AutoInstallLiteDb" -ScriptBlock {
					Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Starting automatic LiteDB installation" -Type 'Start' -Data @{
						InstallPath = $installPath
						Version     = $LiteDbVersion
						Force       = $ForceLiteDbInstall
					}
					
					# Ensure install directory exists
					if (-not (Test-Path -Path $installPath)) {
						Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Creating installation directory" -Type 'Progress' -Data @{ Path = $installPath }
						New-Item -ItemType Directory -Path $installPath -Force | Out-Null
					}
					
					# RdpMon requires older LiteDB version (4.x), not 5.x
					# Using version 4.1.4 which is compatible with RdpMon
					Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Downloading LiteDB v4.1.4 for RdpMon compatibility" -Type 'Progress'
					
					# Download DLL directly
					$dllUrl = "https://github.com/mbdavid/LiteDB/releases/download/v4.1.4/LiteDB.dll"
					$dllPath = Join-Path -Path $installPath -ChildPath "LiteDB.dll"
					
					Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Downloading DLL directly: $dllUrl" -Type 'Progress'
					
					try {
						Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UserAgent "PowerShell" -UseBasicParsing
					}
					catch {
						# Alternative URL
						$dllUrl = "https://www.nuget.org/api/v2/package/LiteDB/4.1.4"
						$tempFile = Join-Path -Path $env:TEMP -ChildPath "LiteDB.4.1.4.nupkg"
						Invoke-WebRequest -Uri $dllUrl -OutFile $tempFile -UserAgent "PowerShell" -UseBasicParsing
						
						# Extract nupkg
						$extractDir = Join-Path -Path $installPath -ChildPath "extracted"
						if (Test-Path -Path $extractDir) {
							Remove-Item -Path $extractDir -Recurse -Force
						}
						New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
						
						Expand-Archive -Path $tempFile -DestinationPath $extractDir -Force
						
						# Find LiteDB.dll
						$dllFile = Get-ChildItem -Path $extractDir -Filter "LiteDB.dll" -Recurse -File | Select-Object -First 1
						if ($dllFile) {
							Copy-Item -Path $dllFile.FullName -Destination $dllPath -Force
						}
						else {
							throw "LiteDB.dll not found in NuGet package"
						}
					}
					
					if (Test-Path -Path $dllPath) {
						# Create version.txt
						$versionFile = Join-Path -Path $installPath -ChildPath "version.txt"
						Set-Content -Path $versionFile -Value "4.1.4" -Encoding UTF8
						
						Write-DebugStep -Phase "AutoInstallLiteDb" -Message "Direct DLL download successful" -Type 'Complete'
						return $dllPath
					}
					else {
						throw "Failed to download LiteDB.dll"
					}
				}
				
				if ($installResult -and (Test-Path -Path $installResult)) {
					Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Trying to load newly installed assembly" -Type 'Progress'
					
					# Try to load the newly installed assembly
					$null = Add-Type -Path $installResult -ErrorAction Stop
					$assembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | 
					Where-Object { $_.Location -eq $installResult } | 
					Select-Object -First 1
					
					if ($assembly) {
						$global:LiteDbAssembly = $assembly
						$foundAssembly = $assembly
						
						Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Newly installed assembly loaded successfully" -Type 'Progress' -Data @{
							Name        = $assembly.FullName
							InstallPath = $installResult
							Version     = $assembly.GetName().Version
						}
					}
					else {
						throw "Failed to get assembly object after loading"
					}
				}
			}
			catch {
				Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Auto-installation failed" -Type 'Warning' -Data @{ Error = $_.Exception.Message }
				# Continue to error handling below
			}
		}
		
		if ($foundAssembly) {
			# Check that version is compatible (4.x for RdpMon)
			try {
				$assemblyVersion = $foundAssembly.GetName().Version
				if ($assemblyVersion.Major -ge 5) {
					Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Warning: LiteDB v$assemblyVersion may not be compatible with RdpMon (needs v4.x)" -Type 'Warning'
					Write-Host "WARNING: LiteDB version $assemblyVersion may not be compatible with RdpMon database format." -ForegroundColor Yellow
					Write-Host "RdpMon requires LiteDB version 4.x. Version 5.x uses a different database format." -ForegroundColor Yellow
				}
			}
			catch {
				# Ignore version check errors
			}
			
			return $foundAssembly
		}
		
		# 6. Try to manually find already extracted files
		Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Manually searching in installation directory" -Type 'Progress'
		
		# Check if already installed files exist
		if (Test-Path -Path $installPath) {
			# Recursively search for all DLL files
			$dllFiles = Get-ChildItem -Path $installPath -Filter "*.dll" -Recurse -File
			
			Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Found $($dllFiles.Count) DLL files in installation directory" -Type 'Progress'
			
			foreach ($dllFile in $dllFiles) {
				# Check if it's LiteDB
				if ($dllFile.Name -like '*LiteDB*') {
					try {
						Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Trying to load: $($dllFile.FullName)" -Type 'Progress'
						$null = Add-Type -Path $dllFile.FullName -ErrorAction Stop
						$assembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | 
						Where-Object { $_.Location -eq $dllFile.FullName } | 
						Select-Object -First 1
						
						if ($assembly) {
							$global:LiteDbAssembly = $assembly
							$foundAssembly = $assembly
							
							Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "Found and loaded existing LiteDB assembly" -Type 'Progress' -Data @{
								Path    = $dllFile.FullName
								Name    = $assembly.FullName
								Version = $assembly.GetName().Version
							}
							break
						}
					}
					catch {
						# Continue search
						continue
					}
				}
			}
		}
		
		if ($foundAssembly) {
			return $foundAssembly
		}
		
		# 7. Comprehensive error message with installation options
		Write-DebugStep -Phase "LoadLiteDbAssembly" -Message "LiteDB assembly not found in any search location" -Type 'Error' -Data @{
			SearchLocations    = $searchPaths.Count
			AutoInstallEnabled = $AutoInstallLiteDb
			SkipInstall        = $SkipLiteDbInstall
			InstallPathExists  = Test-Path -Path $installPath
		}
		
		$errorGuidance = @"

LITEDB ASSEMBLY NOT FOUND
==========================

Search Summary:
- Total locations searched: $($searchPaths.Count)
- Script directory: $PSScriptRoot
- Database directory: $(Split-Path -Path $global:DbPath -Parent)
- Auto-installation enabled: $AutoInstallLiteDb
- Auto-installation skipped: $SkipLiteDbInstall
- Installation path exists: $(Test-Path -Path $installPath)

IMPORTANT: RdpMon requires LiteDB version 4.x (not 5.x!)

INSTALLATION OPTIONS:

1. AUTO-INSTALL COMPATIBLE VERSION:
   Run with: -AutoInstallLiteDb -ForceLiteDbInstall
   This will install LiteDB v4.1.4 which is compatible with RdpMon.

2. MANUAL INSTALLATION:
   Download LiteDB v4.1.4 from: https://github.com/mbdavid/LiteDB/releases/tag/v4.1.4
   Save LiteDB.dll to: $PSScriptRoot\LiteDB.dll
   Then run: .\$($global:ScriptConfig.Name)  -DbPath '$global:DbPath' -LiteDbPath "$PSScriptRoot\LiteDB.dll"

3. USE EXISTING v4.x INSTALLATION:
   -LiteDbPath "C:\Path\To\LiteDB.v4.dll"

4. FORCE REINSTALLATION (if current version is 5.x):
   .\$($global:ScriptConfig.Name)  -DbPath '$global:DbPath' -AutoInstallLiteDb -ForceLiteDbInstall

TROUBLESHOOTING:
- Current LiteDB installation: $installPath
- Check for version.txt in installation folder
- Make sure you have write permissions to: $installPath

For more help: $($global:ScriptConfig.Git)
"@
		
		throw $errorGuidance
	}
}
#endregion

#region Enhanced Data Processing Functions
function Get-CompleteRdpMonData {
	[CmdletBinding()]
	param()
	
	return Measure-Operation -Name "GetCompleteRdpMonData" -ScriptBlock {
		Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Querying all RdpMon database collections" -Type 'Start'
		
		# Get all collections
		$collectionNames = $global:DatabaseConnection.GetCollectionNames()
		Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Available collections: $($collectionNames -join ', ')" -Type 'Info' -Data @{ Collections = $collectionNames }
		
		$result = @{
			AddrData    = [System.Collections.ArrayList]::new()
			SessionData = [System.Collections.ArrayList]::new()
			PropData    = [System.Collections.ArrayList]::new()
			ProcessData = [System.Collections.ArrayList]::new()
		}
		
		# Process Addr collection (main)
		if ($collectionNames -contains "Addr") {
			Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Processing Addr collection" -Type 'Progress'
			$collection = $global:DatabaseConnection.GetCollection("Addr")
			$totalCount = $collection.Count()
			
			if ($totalCount -gt 0) {
				foreach ($record in $collection.FindAll()) {
					$psRecord = Convert-BsonToPSObject -BsonDocument $record
					[void]$result.AddrData.Add($psRecord)
				}
				Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Retrieved $($result.AddrData.Count) records from Addr collection" -Type 'Progress'
			}
		}
		
		# Process Session collection (detailed sessions)
		if ($collectionNames -contains "Session") {
			Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Processing Session collection" -Type 'Progress'
			$collection = $global:DatabaseConnection.GetCollection("Session")
			$totalCount = $collection.Count()
			
			if ($totalCount -gt 0) {
				foreach ($record in $collection.FindAll()) {
					$psRecord = Convert-BsonToPSObject -BsonDocument $record
					[void]$result.SessionData.Add($psRecord)
				}
				Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Retrieved $($result.SessionData.Count) records from Session collection" -Type 'Progress'
			}
		}
		
		# Process Prop collection (metadata)
		if ($collectionNames -contains "Prop") {
			Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Processing Prop collection" -Type 'Progress'
			$collection = $global:DatabaseConnection.GetCollection("Prop")
			
			foreach ($record in $collection.FindAll()) {
				$psRecord = Convert-BsonToPSObject -BsonDocument $record
				[void]$result.PropData.Add($psRecord)
			}
			Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Retrieved $($result.PropData.Count) records from Prop collection" -Type 'Progress'
		}
		
		# Try to process Process collection (if available and not corrupted)
		if ($collectionNames -contains "Process") {
			try {
				Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Attempting to process Process collection" -Type 'Progress'
				$collection = $global:DatabaseConnection.GetCollection("Process")
				$totalCount = $collection.Count()
				
				if ($totalCount -gt 0) {
					# Try to get first few records only
					$counter = 0
					foreach ($record in $collection.FindAll()) {
						if ($counter -lt 10) {
							# Limit to prevent issues with corrupted data
							$psRecord = Convert-BsonToPSObject -BsonDocument $record
							[void]$result.ProcessData.Add($psRecord)
							$counter++
						}
						else {
							break
						}
					}
					Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Retrieved $($result.ProcessData.Count) records from Process collection" -Type 'Progress'
				}
			}
			catch {
				Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Process collection might be corrupted or unreadable: $_" -Type 'Warning'
			}
		}
		
		Write-DebugStep -Phase "GetCompleteRdpMonData" -Message "Data retrieval completed" -Type 'Complete' -Data @{
			AddrRecords    = $result.AddrData.Count
			SessionRecords = $result.SessionData.Count
			PropRecords    = $result.PropData.Count
			ProcessRecords = $result.ProcessData.Count
		}
		
		return $result
	}
}

function Convert-BsonToPSObject {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[LiteDB.BsonDocument]$BsonDocument
	)
	
	$psObject = @{}
	
	foreach ($key in $BsonDocument.Keys) {
		$value = $BsonDocument[$key]
		
		if ($value -is [LiteDB.BsonValue]) {
			if ($value.IsString) {
				$psObject[$key] = $value.AsString
			}
			elseif ($value.IsDateTime) {
				$psObject[$key] = $value.AsDateTime
			}
			elseif ($value.IsInt32) {
				$psObject[$key] = $value.AsInt32
			}
			elseif ($value.IsInt64) {
				$psObject[$key] = $value.AsInt64
			}
			elseif ($value.IsBoolean) {
				$psObject[$key] = $value.AsBoolean
			}
			elseif ($value.IsArray) {
				$arrayValue = @()
				foreach ($item in $value.AsArray) {
					if ($item.IsString) {
						$arrayValue += $item.AsString
					}
					else {
						$arrayValue += $item.ToString()
					}
				}
				$psObject[$key] = $arrayValue
			}
			elseif ($value.IsNull) {
				$psObject[$key] = $null
			}
			else {
				$psObject[$key] = $value.ToString()
			}
		}
		else {
			$psObject[$key] = $value
		}
	}
	
	return [PSCustomObject]$psObject
}

function Process-CompleteRdpMonData {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[hashtable]$Data
	)
	
	return Measure-Operation -Name "ProcessCompleteData" -ScriptBlock {
		Write-DebugStep -Phase "ProcessCompleteData" -Message "Processing all RdpMon collections" -Type 'Start' -Data @{
			AddrCount    = $Data.AddrData.Count
			SessionCount = $Data.SessionData.Count
			PropCount    = $Data.PropData.Count
		}
		
		# Process Addr data
		$addrResults = @()
		if ($Data.AddrData.Count -gt 0) {
			Write-DebugStep -Phase "ProcessCompleteData" -Message "Processing Addr data" -Type 'Progress'
			$addrResults = Process-RdpMonAddrData -Data $Data.AddrData
		}
		else {
			Write-DebugStep -Phase "ProcessCompleteData" -Message "No Addr data to process" -Type 'Warning'
		}
		
		# Process Session data
		$sessionResults = @()
		if ($Data.SessionData.Count -gt 0) {
			Write-DebugStep -Phase "ProcessCompleteData" -Message "Processing Session data" -Type 'Progress'
			$sessionResults = Process-RdpMonSessionData -Data $Data.SessionData
		}
		
		# Process Prop data (metadata)
		$propResults = @()
		if ($Data.PropData.Count -gt 0) {
			Write-DebugStep -Phase "ProcessCompleteData" -Message "Processing Prop data" -Type 'Progress'
			foreach ($record in $Data.PropData) {
				$propResults += [PSCustomObject]@{
					Property = $record._id
					Value    = $record.Val
				}
			}
		}
		
		$result = @{
			AddrResults    = $addrResults
			SessionResults = $sessionResults
			PropResults    = $propResults
			DatabaseStats  = @{
				LastAddrChange      = ($propResults | Where-Object { $_.Property -eq "LastAddrChange" }).Value
				LastSessionChange   = ($propResults | Where-Object { $_.Property -eq "LastSessionChange" }).Value
				LastProcessChange   = ($propResults | Where-Object { $_.Property -eq "LastProcessChange" }).Value
				TotalAddrRecords    = $addrResults.Count
				TotalSessionRecords = $sessionResults.Count
			}
		}
		
		Write-DebugStep -Phase "ProcessCompleteData" -Message "Complete data processing finished" -Type 'Complete' -Data @{
			ProcessedAddr     = $addrResults.Count
			ProcessedSessions = $sessionResults.Count
			ProcessedProps    = $propResults.Count
		}
		
		return $result
	}
}

function Process-RdpMonAddrData {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[array]$Data
	)
	
	return Measure-Operation -Name "ProcessAddrData" -ScriptBlock {
		Write-DebugStep -Phase "ProcessAddrData" -Message "Processing RdpMon Addr collection data" -Type 'Start' -Data @{ 
			InputCount     = $Data.Count
			TypeFilter     = $Type
			MinFailsFilter = $MinFails
			FromFilter     = if ($From -ne [DateTime]::MinValue) { $From.ToString('yyyy-MM-dd HH:mm:ss') } else { "Not set" }
			ToFilter       = if ($To -ne [DateTime]::MaxValue) { $To.ToString('yyyy-MM-dd HH:mm:ss') } else { "Not set" }
		}
		
		if ($Data.Count -eq 0) {
			Write-DebugStep -Phase "ProcessAddrData" -Message "No data to process" -Type 'Warning'
			return @()
		}
		
		$processedResults = @()
		$filteredCount = 0
		$skippedNoIP = 0
		
		$recordIndex = 0
		
		foreach ($record in $Data) {
			$recordIndex++
			
            # Skip records with null IP immediately
            if ([string]::IsNullOrEmpty($record.IP)) {
                $skippedNoIP++
                if ($skippedNoIP -le 5) {
                    Write-DebugStep -Phase "ProcessAddrData" -Message "Skipping record with null IP" -Type 'Progress' -Data @{
                        Index  = $recordIndex
                        Record = $record
                    }
                }
                continue
            }
            
            # Raw IP from record 
            $rawIp = $record.IP
            $ip    = ($rawIp -as [string]).Trim('"').Trim()

            if ($IpAddress) {
                Write-DebugStep -Phase "ProcessAddrData" -Message "IP filter check for record $recordIndex" -Type 'Info' -Data @{
                    IpAddressParam = $IpAddress
                    RawRecordIP    = $rawIp
                    NormalizedIP   = $ip
                }

                $pattern = "*$IpAddress*"

                if ($ip -notlike $pattern) {
                    $filteredCount++
                    Write-DebugStep -Phase "ProcessAddrData" -Message "Record $recordIndex skipped by IP filter" -Type 'Progress' -Data @{
                        IpAddressParam = $IpAddress
                        RawRecordIP    = $rawIp
                        NormalizedIP   = $ip
                        Pattern        = $pattern
                    }
                    continue
                }

                Write-DebugStep -Phase "ProcessAddrData" -Message "Record $recordIndex PASSED IP filter" -Type 'Progress' -Data @{
                    IpAddressParam = $IpAddress
                    RawRecordIP    = $rawIp
                    NormalizedIP   = $ip
                    Pattern        = $pattern
                }
            }

			# Log first few valid records for debugging
			if ($recordIndex -le 3) {
				Write-DebugStep -Phase "ProcessAddrData" -Message "Processing valid record $recordIndex" -Type 'Progress' -Data @{
					IP             = $ip
					FailCount      = $record.FailCount
					SuccessCount   = $record.SuccessCount
					FirstLocal     = if ($record.FirstLocal) { $record.FirstLocal.ToString('yyyy-MM-dd HH:mm:ss') } else { "null" }
					LastLocal      = if ($record.LastLocal) { $record.LastLocal.ToString('yyyy-MM-dd HH:mm:ss') } else { "null" }
					ConnectionType = $record.ConnectionType
				}
			}
			
			# Use data already extracted in Get-EnhancedRdpMonData
			$failCount = $record.FailCount
			$successCount = $record.SuccessCount
			$firstLocal = if ($record.FirstLocal) { [DateTime]$record.FirstLocal } else { [DateTime]::MinValue }
			$lastLocal = if ($record.LastLocal) { [DateTime]$record.LastLocal } else { [DateTime]::MinValue }
			$userNames = $record.UserNames
			$connectionType = $record.ConnectionType
			$duration = if ($record.Duration) { 
				[TimeSpan]::new($record.Duration.Days, $record.Duration.Hours, $record.Duration.Minutes, $record.Duration.Seconds)
			}
			else { 
				[TimeSpan]::Zero 
			}       

			# Apply MinFails filter
			if ($MinFails -gt 0 -and $failCount -lt $MinFails) {
				$filteredCount++
				continue
			}
			
			# Apply date filters
			if ($From -ne [DateTime]::MinValue -and $lastLocal -lt $From) {
				$filteredCount++
				continue
			}
			
			if ($To -ne [DateTime]::MaxValue -and $firstLocal -gt $To) {
				$filteredCount++
				continue
			}
			
			# Extract usernames from UserNames array
			$userNames = @()
			if ($record.UserNames -ne $null -and $record.UserNames -is [array]) {
				$userNames = $record.UserNames
			}
			
			# Resolve hostname if requested
			$hostname = $null
			if ($IncludeResolved -and $ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
				try {
					if ($global:ResolvedHostnamesCache.ContainsKey($ip)) {
						$hostname = $global:ResolvedHostnamesCache[$ip]
					}
					else {
						# Use synchronous DNS resolution (async might fail in some environments)
						$hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
						$global:ResolvedHostnamesCache[$ip] = $hostname
					}
				}
				catch {
					$hostname = "Unresolved"
				}
			}
			
			# Create processed object
			$processedObject = [PSCustomObject]@{
				IP             = $ip
				Hostname       = $hostname
				FailCount      = $failCount
				SuccessCount   = $successCount
				TotalAttempts  = $failCount + $successCount
				FirstLocal     = $firstLocal
				LastLocal      = $lastLocal
				Duration       = $duration
				ConnectionType = $connectionType
				RawRecords     = 1
				UserNames      = $userNames
				IsOngoing      = $false
			}
			
			$processedResults += $processedObject
		}
		
		$global:FilteredRecords = $filteredCount
		
		Write-DebugStep -Phase "ProcessAddrData" -Message "Processed $($processedResults.Count) IP addresses (filtered out: $filteredCount)" -Type 'Complete' -Data @{
			ProcessedCount = $processedResults.Count
			FilteredCount  = $filteredCount
		}
		
		return $processedResults
	}
}

function Process-RdpMonSessionData {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[array]$Data
	)
	
	return Measure-Operation -Name "ProcessSessionData" -ScriptBlock {
		Write-DebugStep -Phase "ProcessSessionData" -Message "Processing Session data" -Type 'Start' -Data @{ InputCount = $Data.Count }
		
		if ($Data.Count -eq 0) {
			Write-DebugStep -Phase "ProcessSessionData" -Message "No Session data to process" -Type 'Warning'
			return @()
		}
		
		$sessionResults = @()
		
		foreach ($record in $Data) {
			# Calculate session duration
			$duration = [TimeSpan]::Zero
			if ($record.Start -and $record.End) {
				try {
					$startTime = [datetime]$record.Start
					$endTime = [datetime]$record.End
					$duration = $endTime - $startTime
				}
				catch {
					$duration = [TimeSpan]::Zero
				}
			}
			
			# Determine session type based on duration and other factors
			$sessionType = "Unknown"
			if ($duration.TotalMinutes -gt 60) {
				$sessionType = "Long"
			}
			elseif ($duration.TotalMinutes -lt 5) {
				$sessionType = "Short"
			}
			elseif ($record.User -and $record.Addr) {
				$sessionType = "Remote"
			}
			elseif ($record.User -and -not $record.Addr) {
				$sessionType = "Local"
			}
			
			$sessionResults += [PSCustomObject]@{
				SessionId    = $record._id
				IP           = $record.Addr
				User         = $record.User
				StartTime    = $record.Start
				EndTime      = $record.End
				Duration     = $duration
				SessionType  = $sessionType
				Flags        = $record.Flags
				WtsSessionId = $record.WtsSessionId
			}
		}
		
		Write-DebugStep -Phase "ProcessSessionData" -Message "Processed $($sessionResults.Count) sessions" -Type 'Complete'
		
		return $sessionResults
	}
}
#endregion

#region Enhanced Data Processing for Modern HTML Interface
function Get-EnhancedRdpMonData {
	[CmdletBinding()]
	param()
	
	return Measure-Operation -Name "GetEnhancedRdpMonData" -ScriptBlock {
		Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "Querying enhanced RdpMon data for modern interface" -Type 'Start'
		
		try {
			$result = @{
				AddrData     = [System.Collections.ArrayList]::new()
				SessionData  = [System.Collections.ArrayList]::new()
				PropData     = [System.Collections.ArrayList]::new()
				DatabaseInfo = @{}
				SummaryStats = @{}
			}
			
			# First, run diagnostics to understand the structure
			$dbStructure = Get-RdpMonDatabaseStructure
			
			# Get database statistics
			$collectionNames = $global:DatabaseConnection.GetCollectionNames()
			$result.DatabaseInfo.Collections = $collectionNames
			$result.DatabaseInfo.TotalCollections = $collectionNames.Count
			
			# Process Addr collection - FIXED FOR RDPMON STRUCTURE
			if ($collectionNames -contains "Addr") {
				Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "Processing Addr collection with REAL RdpMon structure" -Type 'Progress'
				$collection = $global:DatabaseConnection.GetCollection("Addr")
				$addrCount = $collection.Count()
				
				if ($addrCount -gt 0) {
					$progress = 0
					$total = $addrCount
					
					foreach ($record in $collection.FindAll()) {
						$progress++
						if ($progress % 10 -eq 0) {
							Show-Progress -Activity "Processing Address Data" -Status "Processing record $progress of $total" -PercentComplete (($progress / $total) * 100)
						}
						
						# DEBUG: Log first record structure
						if ($progress -eq 1) {
							Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "First Addr record structure" -Type 'Info' -Data @{
								RecordKeys = $record.Keys
								FullRecord = $record.ToString()
							}
						}
						
						# RDPMON SPECIFIC: Extract data from correct fields
						# In RdpMon, IP is stored in _id field, but let's check all possibilities
						$ipAddress = $null
						
						# Try different IP field names
						if ($record.ContainsKey('_id') -and -not [string]::IsNullOrEmpty($record['_id'])) {
							$ipAddress = $record['_id'].ToString()
						}
						elseif ($record.ContainsKey('Addr') -and -not [string]::IsNullOrEmpty($record['Addr'])) {
							$ipAddress = $record['Addr'].ToString()
						}
						elseif ($record.ContainsKey('IP') -and -not [string]::IsNullOrEmpty($record['IP'])) {
							$ipAddress = $record['IP'].ToString()
						}
						elseif ($record.ContainsKey('Address') -and -not [string]::IsNullOrEmpty($record['Address'])) {
							$ipAddress = $record['Address'].ToString()
						}
						
						# Extract counts - RdpMon uses specific field names
						$failCount = 0
						$successCount = 0
						
						if ($record.ContainsKey('FailCount')) {
							try { $failCount = [int]$record['FailCount'] } catch { $failCount = 0 }
						}
						elseif ($record.ContainsKey('Fails')) {
							try { $failCount = [int]$record['Fails'] } catch { $failCount = 0 }
						}
						elseif ($record.ContainsKey('Failed')) {
							try { $failCount = [int]$record['Failed'] } catch { $failCount = 0 }
						}
						
						if ($record.ContainsKey('SuccessCount')) {
							try { $successCount = [int]$record['SuccessCount'] } catch { $successCount = 0 }
						}
						elseif ($record.ContainsKey('Success')) {
							try { $successCount = [int]$record['Success'] } catch { $successCount = 0 }
						}
						elseif ($record.ContainsKey('Successful')) {
							try { $successCount = [int]$record['Successful'] } catch { $successCount = 0 }
						}
						
						# Extract timestamps
						$firstDate = $null
						$lastDate = $null
						
						if ($record.ContainsKey('First')) {
							try { $firstDate = [DateTime]$record['First'] } catch { $firstDate = $null }
						}
						elseif ($record.ContainsKey('FirstSeen')) {
							try { $firstDate = [DateTime]$record['FirstSeen'] } catch { $firstDate = $null }
						}
						elseif ($record.ContainsKey('FirstLocal')) {
							try { $firstDate = [DateTime]$record['FirstLocal'] } catch { $firstDate = $null }
						}
						
						if ($record.ContainsKey('Last')) {
							try { $lastDate = [DateTime]$record['Last'] } catch { $lastDate = $null }
						}
						elseif ($record.ContainsKey('LastSeen')) {
							try { $lastDate = [DateTime]$record['LastSeen'] } catch { $lastDate = $null }
						}
						elseif ($record.ContainsKey('LastLocal')) {
							try { $lastDate = [DateTime]$record['LastLocal'] } catch { $lastDate = $null }
						}
						
						# Extract usernames
						$userNames = @()
						if ($record.ContainsKey('UserNames')) {
							try {
								$userNamesValue = $record['UserNames']
								if ($userNamesValue -is [array]) {
									$userNames = $userNamesValue
								}
								elseif ($userNamesValue -is [LiteDB.BsonArray]) {
									foreach ($item in $userNamesValue) {
										$userNames += $item.AsString
									}
								}
								elseif (-not [string]::IsNullOrEmpty($userNamesValue)) {
									$userNames = @($userNamesValue.ToString())
								}
							}
							catch {
								$userNames = @()
							}
						}
						
						# Determine connection type
						$connectionType = "Unknown"
						if ($failCount -gt 0 -and $successCount -eq 0) {
							$connectionType = "Attack"
						}
						elseif ($successCount -gt 0 -and $failCount -eq 0) {
							$connectionType = "Legit"
						}
						elseif ($failCount -gt 0 -and $successCount -gt 0) {
							$connectionType = "Mixed"
						}
						
						# Calculate duration
						$duration = $null
						if ($firstDate -and $lastDate) {
							try {
								$durationSpan = $lastDate - $firstDate
								$duration = @{
									Days       = $durationSpan.Days
									Hours      = $durationSpan.Hours
									Minutes    = $durationSpan.Minutes
									Seconds    = $durationSpan.Seconds
									TotalDays  = $durationSpan.TotalDays
									TotalHours = $durationSpan.TotalHours
								}
							}
							catch {
								$duration = $null
							}
						}
						
						# Create enhanced record object
						$psRecord = [PSCustomObject]@{
							IP             = $ipAddress
							FailCount      = $failCount
							SuccessCount   = $successCount
							FirstLocal     = $firstDate
							LastLocal      = $lastDate
							UserNames      = $userNames
							ConnectionType = $connectionType
							Hostname       = $null  # Will be resolved later if requested
							Duration       = $duration
							RawRecord      = $record  # Keep raw record for debugging
						}
						
						[void]$result.AddrData.Add($psRecord)
					}
					
					Show-Progress -Activity "Processing Address Data" -Status "Completed" -Completed
					Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "Processed $($result.AddrData.Count) Addr records" -Type 'Progress' -Data @{
						RecordsWithIP       = ($result.AddrData | Where-Object { -not [string]::IsNullOrEmpty($_.IP) }).Count
						RecordsWithFailures = ($result.AddrData | Where-Object { $_.FailCount -gt 0 }).Count
						RecordsWithSuccess  = ($result.AddrData | Where-Object { $_.SuccessCount -gt 0 }).Count
					}
				}
				else {
					Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "Addr collection is empty" -Type 'Warning'
				}
			}
			
			# Process Session collection
			if ($collectionNames -contains "Session") {
				Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "Processing Session collection" -Type 'Progress'
				$collection = $global:DatabaseConnection.GetCollection("Session")
				
				foreach ($record in $collection.FindAll()) {
					$psRecord = Convert-BsonToPSObject -BsonDocument $record
					[void]$result.SessionData.Add($psRecord)
				}
				
				Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "Processed $($result.SessionData.Count) Session records" -Type 'Progress'
			}
			
			# Process Prop collection for metadata
			if ($collectionNames -contains "Prop") {
				Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "Processing Prop collection" -Type 'Progress'
				$collection = $global:DatabaseConnection.GetCollection("Prop")
				
				foreach ($record in $collection.FindAll()) {
					$psRecord = Convert-BsonToPSObject -BsonDocument $record
					[void]$result.PropData.Add($psRecord)
				}
				
				# Extract database statistics from Prop data
				$result.DatabaseInfo.LastAddrChange = ($result.PropData | Where-Object { $_.Property -eq "LastAddrChange" }).Value
				$result.DatabaseInfo.LastSessionChange = ($result.PropData | Where-Object { $_.Property -eq "LastSessionChange" }).Value
				$result.DatabaseInfo.LastProcessChange = ($result.PropData | Where-Object { $_.Property -eq "LastProcessChange" }).Value
			}
			
			# Calculate summary statistics
			$result.SummaryStats.TotalAddrRecords = $result.AddrData.Count
			$result.SummaryStats.TotalSessionRecords = $result.SessionData.Count
			
			# Count records with valid IPs
			$recordsWithIp = $result.AddrData | Where-Object { -not [string]::IsNullOrEmpty($_.IP) }
			$result.SummaryStats.UniqueIPs = ($recordsWithIp.IP | Select-Object -Unique).Count
			
			# Calculate type distribution
			$result.SummaryStats.AttackCount = ($recordsWithIp | Where-Object { $_.ConnectionType -eq "Attack" }).Count
			$result.SummaryStats.LegitCount = ($recordsWithIp | Where-Object { $_.ConnectionType -eq "Legit" }).Count
			$result.SummaryStats.MixedCount = ($recordsWithIp | Where-Object { $_.ConnectionType -eq "Mixed" }).Count
			$result.SummaryStats.UnknownCount = ($recordsWithIp | Where-Object { $_.ConnectionType -eq "Unknown" }).Count
			
			# Calculate timeline data for charts
			$result.SummaryStats.TimelineData = @{
				Last30Days = @{
					Labels      = @()
					FailData    = @()
					SuccessData = @()
				}
			}
			
			# Generate timeline data for last 30 days (only for records with valid dates)
			$today = Get-Date
			for ($i = 29; $i -ge 0; $i--) {
				$date = $today.AddDays(-$i)
				$dateStr = $date.ToString("yyyy-MM-dd")
				$result.SummaryStats.TimelineData.Last30Days.Labels += $date.ToString("MMM dd")
				
				# Count events for this day
				$dayFailCount = 0
				$daySuccessCount = 0
				
				foreach ($addr in $recordsWithIp) {
					if ($addr.LastLocal) {
						try {
							$lastDate = [DateTime]$addr.LastLocal
							if ($lastDate.ToString("yyyy-MM-dd") -eq $dateStr) {
								$dayFailCount += $addr.FailCount
								$daySuccessCount += $addr.SuccessCount
							}
						}
						catch {
							# Skip invalid dates
						}
					}
				}
				
				$result.SummaryStats.TimelineData.Last30Days.FailData += $dayFailCount
				$result.SummaryStats.TimelineData.Last30Days.SuccessData += $daySuccessCount
			}
			
			Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "Enhanced data retrieval completed" -Type 'Complete' -Data @{
				AddrRecords       = $result.AddrData.Count
				ValidIPRecords    = $result.SummaryStats.UniqueIPs
				AttackCount       = $result.SummaryStats.AttackCount
				LegitCount        = $result.SummaryStats.LegitCount
				DatabaseStructure = $dbStructure
			}
			
			return $result
		}
		catch {
			Write-DebugStep -Phase "GetEnhancedRdpMonData" -Message "Error retrieving enhanced data" -Type 'Error' -Data @{ Error = $_.Exception.Message }
			throw
		}
	}
}

function Process-EnhancedRdpMonData {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[hashtable]$Data
	)
	
	return Measure-Operation -Name "ProcessEnhancedData" -ScriptBlock {
		Write-DebugStep -Phase "ProcessEnhancedData" -Message "Processing enhanced RdpMon data for HTML interface" -Type 'Start' -Data @{
			AddrCount    = $Data.AddrData.Count
			SessionCount = $Data.SessionData.Count
		}
		
		# Process Addr data with filters
		$addrResults = @()
		if ($Data.AddrData.Count -gt 0) {
			Write-DebugStep -Phase "ProcessEnhancedData" -Message "Processing Addr data with filters" -Type 'Progress'
			$addrResults = Process-RdpMonAddrData -Data $Data.AddrData
		}
		else {
			Write-DebugStep -Phase "ProcessEnhancedData" -Message "No Addr data to process" -Type 'Warning'
		}
		
		# Process Session data
		$sessionResults = @()
		if ($Data.SessionData.Count -gt 0) {
			Write-DebugStep -Phase "ProcessEnhancedData" -Message "Processing Session data" -Type 'Progress'
			$sessionResults = Process-RdpMonSessionData -Data $Data.SessionData
		}
		
		# Process Prop data (metadata)
		$propResults = @()
		if ($Data.PropData.Count -gt 0) {
			Write-DebugStep -Phase "ProcessEnhancedData" -Message "Processing Prop data" -Type 'Progress'
			foreach ($record in $Data.PropData) {
				$propResults += [PSCustomObject]@{
					Property = $record._id
					Value    = $record.Val
				}
			}
		}
		
		# Prepare enhanced result structure for HTML interface
		$result = @{
			AddrResults    = $addrResults
			SessionResults = $sessionResults
			PropResults    = $propResults
			DatabaseStats  = $Data.DatabaseInfo
			SummaryStats   = $Data.SummaryStats
			EnhancedData   = @{
				ChartData  = @{
					Timeline     = $Data.SummaryStats.TimelineData.Last30Days
					Distribution = @{
						Labels = @("Attack", "Legit", "Mixed", "Unknown")
						Data   = @(
							$Data.SummaryStats.AttackCount,
							$Data.SummaryStats.LegitCount,
							$Data.SummaryStats.MixedCount,
							$Data.SummaryStats.UnknownCount
						)
					}
				}
				Statistics = @{
					TotalRecords     = $Data.AddrData.Count
					UniqueIPs        = $Data.SummaryStats.UniqueIPs
					AttackPercentage = if ($Data.AddrData.Count -gt 0) {
						[math]::Round(($Data.SummaryStats.AttackCount / $Data.AddrData.Count) * 100, 1)
					}
					else { 0 }
					LegitPercentage  = if ($Data.AddrData.Count -gt 0) {
						[math]::Round(($Data.SummaryStats.LegitCount / $Data.AddrData.Count) * 100, 1)
					}
					else { 0 }
				}
			}
		}
		
		Write-DebugStep -Phase "ProcessEnhancedData" -Message "Enhanced data processing finished" -Type 'Complete' -Data @{
			ProcessedAddr     = $addrResults.Count
			ProcessedSessions = $sessionResults.Count
			ChartDataPoints   = $result.EnhancedData.ChartData.Timeline.Labels.Count
		}
		
		return $result
	}
}
#endregion

#region Data Processing Functions
function Get-RdpMonData {
	[CmdletBinding()]
	param()
	
	return Measure-Operation -Name "GetRdpMonData" -ScriptBlock {
		Write-DebugStep -Phase "GetRdpMonData" -Message "Querying RdpMon database" -Type 'Start'
		
		# Get all collections
		Write-DebugStep -Phase "GetRdpMonData" -Message "Listing all collections in database" -Type 'Progress'
		$collectionNames = $global:DatabaseConnection.GetCollectionNames()
		Write-DebugStep -Phase "GetRdpMonData" -Message "Available collections: $($collectionNames -join ', ')" -Type 'Info' -Data @{ Collections = $collectionNames }
		
		# Use Addr collection as primary data source (main collection for RdpMon)
		if ($collectionNames -contains "Addr") {
			$collection = $global:DatabaseConnection.GetCollection("Addr")
			Write-DebugStep -Phase "GetRdpMonData" -Message "Using Addr collection (main data source for RDP attempts)" -Type 'Progress'
		}
		else {
			throw "Addr collection not found in the database. Available collections: $($collectionNames -join ', ')"
		}
		
		$totalCount = $collection.Count()
		Write-DebugStep -Phase "GetRdpMonData" -Message "Total records in Addr collection: $totalCount" -Type 'Progress'
		
		if ($totalCount -eq 0) {
			Write-DebugStep -Phase "GetRdpMonData" -Message "Addr collection is empty" -Type 'Warning'
			return @()
		}
		
		# Query all records from Addr collection
		$query = $collection.FindAll()
		$results = @()
		$recordCount = 0
		
		# Show first few records for debugging
		$sampleRecords = @()
		$maxSample = 3
		
		foreach ($record in $query) {
			$recordCount++
			$global:TotalRecordsProcessed = $recordCount
			
			# Convert BsonDocument to PowerShell object
			$psRecord = @{}
			
			foreach ($key in $record.Keys) {
				$value = $record[$key]
				
				# Handle different BSON types
				if ($value -is [LiteDB.BsonValue]) {
					if ($value.IsString) {
						$psRecord[$key] = $value.AsString
					}
					elseif ($value.IsDateTime) {
						$psRecord[$key] = $value.AsDateTime
					}
					elseif ($value.IsInt32) {
						$psRecord[$key] = $value.AsInt32
					}
					elseif ($value.IsInt64) {
						$psRecord[$key] = $value.AsInt64
					}
					elseif ($value.IsBoolean) {
						$psRecord[$key] = $value.AsBoolean
					}
					elseif ($value.IsArray) {
						# Handle arrays (like UserNames in Addr collection)
						$arrayValue = @()
						foreach ($item in $value.AsArray) {
							if ($item.IsString) {
								$arrayValue += $item.AsString
							}
							else {
								$arrayValue += $item.ToString()
							}
						}
						$psRecord[$key] = $arrayValue
					}
					elseif ($value.IsNull) {
						$psRecord[$key] = $null
					}
					else {
						$psRecord[$key] = $value.ToString()
					}
				}
				else {
					$psRecord[$key] = $value
				}
			}
			
			# Collect sample records for debugging
			if ($recordCount -le $maxSample) {
				$sampleRecords += $psRecord
			}
			
			$results += [PSCustomObject]$psRecord
		}
		
		# Show sample records for debugging
		if ($sampleRecords.Count -gt 0) {
			Write-DebugStep -Phase "GetRdpMonData" -Message "Sample records from Addr collection (first $maxSample):" -Type 'Info' -Data @{ SampleRecords = $sampleRecords }
		}
		
		Write-DebugStep -Phase "GetRdpMonData" -Message "Retrieved $recordCount records from Addr collection" -Type 'Complete' -Data @{ 
			RecordCount = $recordCount 
			Collection  = "Addr"
		}
		
		return $results
	}
}

function Sort-AndLimit-Results {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[array]$Data
	)
	
	return Measure-Operation -Name "SortAndLimit" -ScriptBlock {
		Write-DebugStep -Phase "SortAndLimit" -Message "Sorting and limiting results" -Type 'Start' -Data @{ InputCount = $Data.Count }
		
		if ($Data.Count -eq 0) {
			return $Data
		}
		
		# Sort the data
		$sortedData = if ($Descending) {
			$Data | Sort-Object -Property $SortBy -Descending
		}
		else {
			$Data | Sort-Object -Property $SortBy
		}
		
		# Apply limit
		$limitedData = if ($Limit -lt $sortedData.Count -and $Limit -ne [int]::MaxValue) {
			$sortedData | Select-Object -First $Limit
		}
		else {
			$sortedData
		}
		
		Write-DebugStep -Phase "SortAndLimit" -Message "Sorted and limited to $($limitedData.Count) records" -Type 'Complete' -Data @{ OutputCount = $limitedData.Count }
		
		return $limitedData
	}
}
#endregion

#region Output Format Functions
function ConvertTo-HtmlReport {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[array]$Data,
		
		[Parameter()]
		[string]$Title = "RDP Monitor Report",
		
		[Parameter()]
		[int]$AutoRefreshInterval = 30,
		
		[Parameter()]
		[string]$CustomTemplatePath
	)
	
	return Measure-Operation -Name "GenerateHtmlReport" -ScriptBlock {
		Write-DebugStep -Phase "GenerateHtmlReport" -Message "Generating HTML report" -Type 'Start' -Data @{ 
			RecordCount  = $Data.Count 
			AutoRefresh  = $AutoRefreshInterval
			TemplatePath = $CustomTemplatePath
		}
		
		# Determine template path
		$templatePath = $CustomTemplatePath
		if ([string]::IsNullOrEmpty($templatePath)) {
			# Check for default template in script directory
			$defaultTemplate = Join-Path -Path $PSScriptRoot -ChildPath $global:ScriptConfig.HTMLTemplate
			if (Test-Path -Path $defaultTemplate -PathType Leaf) {
				$templatePath = $defaultTemplate
				Write-DebugStep -Phase "GenerateHtmlReport" -Message "Using default template from script directory" -Type 'Progress'
			}
			else {
				# Use built-in template
				$templatePath = $null
				Write-DebugStep -Phase "GenerateHtmlReport" -Message "No template found, using built-in template" -Type 'Warning'
			}
		}
		
		# Load template
		if ($templatePath -and (Test-Path -Path $templatePath)) {
			Write-DebugStep -Phase "GenerateHtmlReport" -Message "Loading template from: $templatePath" -Type 'Progress'
			$htmlTemplate = Get-Content -Path $templatePath -Raw -Encoding UTF8
		}
		else {
			# Fallback to built-in template (simplified version)
			Write-DebugStep -Phase "GenerateHtmlReport" -Message "Creating fallback HTML template" -Type 'Progress'
			$htmlTemplate = @"
<!DOCTYPE html>
<html>
<head>
	<title>RDP Monitor Report</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; }
		table { border-collapse: collapse; width: 100%; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
		th { background-color: #f2f2f2; }
		.attack { background-color: #ffcccc; }
		.legit { background-color: #ccffcc; }
	</style>
</head>
<body>
	<h1>RDP Monitor Report</h1>
	<p>Generated: {{GENERATION_TIME}}</p>
	<p>Database: {{DATABASE_PATH}}</p>
	<p>Records: {{TOTAL_RECORDS}}</p>
	<table>
		<thead>
			<tr>
				<th>IP Address</th>
				<th>Type</th>
				<th>Failed</th>
				<th>Success</th>
				<th>Total</th>
				<th>First Attempt</th>
				<th>Last Attempt</th>
			</tr>
		</thead>
		<tbody>
			{{TABLE_ROWS}}
		</tbody>
	</table>
	<script>
		// Simple auto-refresh
		setTimeout(function() {
			location.reload();
		}, {{AUTO_REFRESH_INTERVAL}} * 1000);
	</script>
</body>
</html>
"@
		}
		
		# Calculate statistics for the report
		$uniqueIps = $Data.Count
		$attackCount = ($Data | Where-Object { $_.ConnectionType -eq "Attack" }).Count
		$legitCount = ($Data | Where-Object { $_.ConnectionType -eq "Legit" }).Count
		$mixedCount = ($Data | Where-Object { $_.ConnectionType -eq "Mixed" }).Count
		
		# Generate table rows
		$tableRows = ""
		foreach ($item in $Data) {
			$rowClass = ""
			switch ($item.ConnectionType) {
				"Attack" { $rowClass = "class='attack'" }
				"Legit" { $rowClass = "class='legit'" }
			}
			
			$tableRows += @"
<tr $rowClass>
	<td>$($item.IP)</td>
	<td>$($item.ConnectionType)</td>
	<td>$($item.FailCount)</td>
	<td>$($item.SuccessCount)</td>
	<td>$($item.TotalAttempts)</td>
	<td>$($item.FirstLocal.ToString('yyyy-MM-dd HH:mm:ss'))</td>
	<td>$($item.LastLocal.ToString('yyyy-MM-dd HH:mm:ss'))</td>
</tr>
"@
		}
		
		# If using the advanced template, prepare JSON data
		if ($htmlTemplate -match '\{\{DATA_JSON\}\}') {
			Write-DebugStep -Phase "GenerateHtmlReport" -Message "Preparing JSON data for advanced template" -Type 'Progress'
			
			# Prepare data for JSON serialization
			$jsonData = @()
			foreach ($item in $Data) {
				$jsonData += @{
					IP             = $item.IP
					Hostname       = $item.Hostname
					ConnectionType = $item.ConnectionType
					FailCount      = $item.FailCount
					SuccessCount   = $item.SuccessCount
					TotalAttempts  = $item.TotalAttempts
					FirstLocal     = $item.FirstLocal.ToString('o')
					LastLocal      = $item.LastLocal.ToString('o')
					UserNames      = $item.UserNames
					IsOngoing      = $item.IsOngoing
					Duration       = @{
						Days       = $item.Duration.Days
						Hours      = $item.Duration.Hours
						Minutes    = $item.Duration.Minutes
						Seconds    = $item.Duration.Seconds
						TotalDays  = $item.Duration.TotalDays
						TotalHours = $item.Duration.TotalHours
					}
				}
			}
			
			$jsonString = $jsonData | ConvertTo-Json -Depth 5 -Compress
			Write-DebugStep -Phase "GenerateHtmlReport" -Message "JSON data prepared ($($jsonString.Length) bytes)" -Type 'Progress'
		}
		
		# Replace placeholders in template
		$htmlContent = $htmlTemplate -replace '\{\{GENERATION_TIME\}\}', (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
		$htmlContent = $htmlContent -replace '\{\{DATABASE_PATH\}\}', $global:DbPath
		$htmlContent = $htmlContent -replace '\{\{TOTAL_RECORDS\}\}', $uniqueIps
		$htmlContent = $htmlContent -replace '\{\{AUTO_REFRESH_INTERVAL\}\}', $AutoRefreshInterval
		
		if ($htmlTemplate -match '\{\{TABLE_ROWS\}\}') {
			$htmlContent = $htmlContent -replace '\{\{TABLE_ROWS\}\}', $tableRows
		}
		
		if ($htmlTemplate -match '\{\{DATA_JSON\}\}' -and $jsonString) {
			$htmlContent = $htmlContent -replace '\{\{DATA_JSON\}\}', $jsonString
		}
		
		Write-DebugStep -Phase "GenerateHtmlReport" -Message "HTML report generated successfully" -Type 'Complete' -Data @{
			UniqueIPs    = $uniqueIps
			AttackCount  = $attackCount
			LegitCount   = $legitCount
			MixedCount   = $mixedCount
			TemplateType = if ($templatePath) { "External" } else { "Built-in" }
		}
		
		return $htmlContent
	}
}

function ConvertTo-EnhancedHtmlReport {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[hashtable]$Data,
		
		[Parameter()]
		[string]$Title = "RDP Security Monitor",
		
		[Parameter()]
		[int]$AutoRefreshInterval = 30,
		
		[Parameter()]
		[string]$CustomTemplatePath
	)
	
	return Measure-Operation -Name "GenerateEnhancedHtmlReport" -ScriptBlock {
		Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Generating enhanced HTML report for modern interface" -Type 'Start' -Data @{
			AddrCount    = $Data.AddrResults.Count
			SessionCount = $Data.SessionResults.Count
			AutoRefresh  = $AutoRefreshInterval
		}
		
		# Load template
		$templatePath = $CustomTemplatePath
		if ([string]::IsNullOrEmpty($templatePath)) {
			$templatePath = Join-Path -Path $PSScriptRoot -ChildPath $global:ScriptConfig.HTMLTemplate
		}
		
		if (-not (Test-Path -Path $templatePath)) {
			throw "HTML template not found: $templatePath. Please ensure $($global:ScriptConfig.HTMLTemplate) exists in the script directory."
		}
		
		Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Loading template from: $templatePath" -Type 'Progress'
		$htmlTemplate = Get-Content -Path $templatePath -Raw -Encoding UTF8
		
		# Prepare enhanced JSON data structure for modern HTML interface
		$jsonData = @{
			AddrData      = @()
			SessionData   = @()
			PropData      = @()
			DatabaseStats = $Data.DatabaseStats
			SummaryStats  = $Data.SummaryStats
			EnhancedData  = $Data.EnhancedData
			ReportInfo    = @{
				GenerationTime      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
				DatabasePath        = $global:DbPath
				TotalRecords        = $Data.AddrResults.Count
				AutoRefreshInterval = $AutoRefreshInterval
				ReportId            = "RDPMON-" + (Get-Date -Format "yyyyMMddHHmmss")
			}
		}
		
		# Prepare Addr data with all required fields for charts and interface
		Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Preparing enhanced Addr data for JSON" -Type 'Progress'
		$progress = 0
		$total = $Data.AddrResults.Count
		
		foreach ($item in $Data.AddrResults) {
			$progress++
			if ($progress % 100 -eq 0) {
				Show-Progress -Activity "Preparing Enhanced Data" -Status "Processing item $progress of $total" -PercentComplete (($progress / $total) * 100)
			}
			
			$jsonData.AddrData += @{
				IP             = $item.IP
				Hostname       = $item.Hostname
				ConnectionType = $item.ConnectionType
				FailCount      = $item.FailCount
				SuccessCount   = $item.SuccessCount
				TotalAttempts  = $item.TotalAttempts
				FirstLocal     = if ($item.FirstLocal -ne [DateTime]::MinValue) { $item.FirstLocal.ToString('o') } else { $null }
				LastLocal      = if ($item.LastLocal -ne [DateTime]::MinValue) { $item.LastLocal.ToString('o') } else { $null }
				UserNames      = $item.UserNames
				IsOngoing      = $item.IsOngoing
				Duration       = $item.Duration
			}
		}
		
		Show-Progress -Activity "Preparing Enhanced Data" -Status "Completed" -Completed
		
		# Prepare Session data
		Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Preparing Session data for JSON" -Type 'Progress'
		foreach ($item in $Data.SessionResults) {
			$jsonData.SessionData += @{
				SessionId    = $item.SessionId
				IP           = $item.IP
				User         = $item.User
				StartTime    = if ($item.StartTime) { $item.StartTime.ToString('o') } else { $null }
				EndTime      = if ($item.EndTime) { $item.EndTime.ToString('o') } else { $null }
				Duration     = $item.Duration
				SessionType  = $item.SessionType
				Flags        = $item.Flags
				WtsSessionId = $item.WtsSessionId
			}
		}
		
		# Prepare Prop data
		Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Preparing Prop data for JSON" -Type 'Progress'
		foreach ($item in $Data.PropResults) {
			$jsonData.PropData += @{
				Property = $item.Property
				Value    = if ($item.Value) { $item.Value.ToString('o') } else { $item.Value }
			}
		}
		
		# Convert to JSON with proper formatting
		Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Converting enhanced data to JSON" -Type 'Progress'
		$jsonString = $jsonData | ConvertTo-Json -Depth 10 -Compress
		
		# Replace placeholders in template
		Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Replacing template placeholders" -Type 'Progress'
		$htmlContent = $htmlTemplate -replace '\{\{GENERATION_TIME\}\}', $jsonData.ReportInfo.GenerationTime
		$htmlContent = $htmlContent -replace '\{\{DATABASE_PATH\}\}', $global:DbPath
		$htmlContent = $htmlContent -replace '\{\{TOTAL_RECORDS\}\}', $Data.AddrResults.Count
		$htmlContent = $htmlContent -replace '\{\{AUTO_REFRESH_INTERVAL\}\}', $AutoRefreshInterval
		$htmlContent = $htmlContent -replace '\{\{REPORT_ID\}\}', $jsonData.ReportInfo.ReportId
		
		# Replace JSON data placeholder with properly escaped content
		if ($htmlTemplate -match '\{\{DATA_JSON\}\}') {
			try {
				$encoder = [JavaScriptEncoder]::UnsafeRelaxedJsonEscaping
				$jsonOptions = [JsonSerializerOptions]::new()
				$jsonOptions.Encoder = $encoder
				$jsonOptions.WriteIndented = $false
		
				$jsonBytes = [JsonSerializer]::SerializeToUtf8Bytes($jsonData, $jsonOptions)
				$jsonString = [Text.Encoding]::UTF8.GetString($jsonBytes)
		
				$escapedJson = $jsonString -replace '\\', '\\\\' -replace '"', '\"' -replace "'", "\'"
		
				Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Used System.Text.Json for escaping" -Type 'Progress'
			}
			catch {
				Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Using manual escaping fallback" -Type 'Warning'
				$escapedJson = $jsonString -replace '\\', '\\\\' -replace '"', '\"' -replace "'", "\'"
			}
	
			$htmlContent = $htmlContent -replace '\{\{DATA_JSON\}\}', $escapedJson
		}
		else {
			Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Warning: Template does not contain {{DATA_JSON}} placeholder" -Type 'Warning'
		}
		
		Write-DebugStep -Phase "GenerateEnhancedHtmlReport" -Message "Enhanced HTML report generated successfully" -Type 'Complete' -Data @{
			AddrRecords     = $Data.AddrResults.Count
			SessionRecords  = $Data.SessionResults.Count
			TemplatePath    = $templatePath
			JsonSize        = "$([math]::Round($jsonString.Length / 1KB, 2)) KB"
			ChartDataPoints = $jsonData.EnhancedData.ChartData.Timeline.Labels.Count
		}
		
		return $htmlContent
	}
}

function Export-Results {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[object]$Data,
		
		[Parameter(Mandatory)]
		[string]$Format,
		
		[Parameter()]
		[string]$FilePath
	)
	
	return Measure-Operation -Name "ExportResults" -ScriptBlock {
		Write-DebugStep -Phase "ExportResults" -Message "Exporting results in $Format format" -Type 'Start' -Data @{
			Format   = $Format
			FilePath = $FilePath
			DataType = $Data.GetType().Name
		}
		
		$output = $null
		
		switch ($Format) {
			'Table' {
				# Handle both array and hashtable
				if ($Data -is [array]) {
					$output = $Data | Format-Table -AutoSize | Out-String
				}
				elseif ($Data -is [hashtable] -and $Data.ContainsKey('AddrResults')) {
					$output = $Data.AddrResults | Format-Table -AutoSize | Out-String
				}
				
				if ($FilePath) {
					$output | Out-File -FilePath $FilePath -Encoding UTF8 -Force
				}
			}
			
			'List' {
				if ($Data -is [array]) {
					$output = $Data | Format-List | Out-String
				}
				elseif ($Data -is [hashtable] -and $Data.ContainsKey('AddrResults')) {
					$output = $Data.AddrResults | Format-List | Out-String
				}
				
				if ($FilePath) {
					$output | Out-File -FilePath $FilePath -Encoding UTF8 -Force
				}
			}
			
			'Json' {
				$output = $Data | ConvertTo-Json -Depth 10
				if ($FilePath) {
					$output | Out-File -FilePath $FilePath -Encoding UTF8 -Force
				}
			}
			
			'Csv' {
				if ($FilePath) {
					if ($Data -is [array]) {
						$Data | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -Force
					}
					elseif ($Data -is [hashtable] -and $Data.ContainsKey('AddrResults')) {
						$Data.AddrResults | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8 -Force
					}
					$output = "CSV exported to: $FilePath"
				}
				else {
					if ($Data -is [array]) {
						$output = $Data | ConvertTo-Csv -NoTypeInformation | Out-String
					}
					elseif ($Data -is [hashtable] -and $Data.ContainsKey('AddrResults')) {
						$output = $Data.AddrResults | ConvertTo-Csv -NoTypeInformation | Out-String
					}
				}
			}
			
			'Xml' {
				$output = $Data | ConvertTo-Xml -NoTypeInformation -Depth 5 | Out-String
				if ($FilePath) {
					$output | Out-File -FilePath $FilePath -Encoding UTF8 -Force
				}
			}
			
			'Html' {
				Write-DebugStep -Phase "ExportResults" -Message "Generating HTML report" -Type 'Progress'
				
				if ($Data -is [hashtable]) {
					# Use enhanced HTML report for modern interface
					$output = ConvertTo-EnhancedHtmlReport -Data $Data -Title "RDP Security Monitor - Complete Report" -AutoRefreshInterval $AutoRefreshInterval -CustomTemplatePath $HtmlTemplatePath
				}
				else {
					$output = ConvertTo-HtmlReport -Data $Data -Title "RDP Monitor Report" -AutoRefreshInterval $AutoRefreshInterval -CustomTemplatePath $HtmlTemplatePath
				}
				
				if ($FilePath) {
					# Resolve to absolute path — handles plain filenames like 'report.html'
					# passed from the current working directory
					$absolutePath = if ([System.IO.Path]::IsPathRooted($FilePath)) {
						$FilePath
					} else {
						Join-Path -Path (Get-Location).Path -ChildPath $FilePath
					}

					Write-DebugStep -Phase 'ExportResults' -Message "Saving HTML report to: $absolutePath" -Type 'Progress' -Data @{
						TargetPath = $absolutePath
						Directory  = Split-Path -Path $absolutePath -Parent
						FileName   = Split-Path -Path $absolutePath -Leaf
					}

					# Create parent directory if it doesn't exist yet
					# (safely skipped when writing to an existing or root-level path)
					$targetDir = Split-Path -Path $absolutePath -Parent
					if (-not [string]::IsNullOrWhiteSpace($targetDir) -and
						-not (Test-Path -Path $targetDir -PathType Container)) {
						Write-DebugStep -Phase 'ExportResults' -Message "Creating output directory: $targetDir" -Type 'Progress'
						New-Item -ItemType Directory -Path $targetDir -Force -ErrorAction Stop | Out-Null
					}

					# Write the generated HTML to disk
					Write-DebugStep -Phase 'ExportResults' -Message 'Writing HTML content to file' -Type 'Progress'
					$output | Out-File -FilePath $absolutePath -Encoding UTF8 -Force -ErrorAction Stop

					# Verify the file was actually created and report its size
					if (Test-Path -Path $absolutePath -PathType Leaf) {
						$fileInfo = Get-Item -Path $absolutePath
						Write-DebugStep -Phase 'ExportResults' -Message 'HTML report saved successfully' -Type 'Complete' -Data @{
							FileSize = "$([math]::Round($fileInfo.Length / 1KB, 2)) KB"
							FullPath = $fileInfo.FullName
						}
					} else {
						# Should not normally reach here given -ErrorAction Stop above,
						# but kept as a defensive guard
						Write-DebugStep -Phase 'ExportResults' -Message 'WARNING: File not found after write — check permissions' -Type 'Warning' -Data @{
							ExpectedPath = $absolutePath
						}
						throw "HTML report was not created at: $absolutePath"
					}
				}
			}
			
			'Text' {
				if ($Data -is [array]) {
					$output = "RDP Monitor Report`n"
					$output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
					$output += "Database: $global:DbPath`n"
					$output += "=" * 80 + "`n`n"
					
					foreach ($item in $Data) {
						$output += "IP: $($item.IP)`n"
						if ($item.Hostname) { $output += "Hostname: $($item.Hostname)`n" }
						$output += "Type: $($item.ConnectionType)`n"
						$output += "Failed attempts: $($item.FailCount)`n"
						$output += "Successful logins: $($item.SuccessCount)`n"
						$output += "Total attempts: $($item.TotalAttempts)`n"
						$output += "First attempt: $($item.FirstLocal.ToString('yyyy-MM-dd HH:mm:ss'))`n"
						$output += "Last attempt: $($item.LastLocal.ToString('yyyy-MM-dd HH:mm:ss'))`n"
						$output += "Duration: $($item.Duration.Days)d $($item.Duration.Hours)h $($item.Duration.Minutes)m`n"
						$output += "-" * 40 + "`n"
					}
				}
				
				if ($FilePath) {
					$output | Out-File -FilePath $FilePath -Encoding UTF8 -Force
				}
			}
			
			'Yaml' {
				# Simple YAML conversion
				$yamlOutput = ""
				$index = 0
				
				if ($Data -is [array]) {
					foreach ($item in $Data) {
						$index++
						$yamlOutput += "entry_$($index):`n"
						$yamlOutput += "  ip: $($item.IP)`n"
						if ($item.Hostname) { $yamlOutput += "  hostname: $($item.Hostname)`n" }
						$yamlOutput += "  type: $($item.ConnectionType)`n"
						$yamlOutput += "  failed_attempts: $($item.FailCount)`n"
						$yamlOutput += "  successful_logins: $($item.SuccessCount)`n"
						$yamlOutput += "  total_attempts: $($item.TotalAttempts)`n"
						$yamlOutput += "  first_attempt: $($item.FirstLocal.ToString('yyyy-MM-dd HH:mm:ss'))`n"
						$yamlOutput += "  last_attempt: $($item.LastLocal.ToString('yyyy-MM-dd HH:mm:ss'))`n"
						$yamlOutput += "  duration_days: $($item.Duration.Days)`n"
						$yamlOutput += "  duration_hours: $($item.Duration.Hours)`n"
						$yamlOutput += "  duration_minutes: $($item.Duration.Minutes)`n"
						$yamlOutput += "`n"
					}
				}
				
				$output = $yamlOutput
				if ($FilePath) {
					$output | Out-File -FilePath $FilePath -Encoding UTF8 -Force
				}
			}
			
			'Markdown' {
				if ($Data -is [array]) {
					$output = "# RDP Monitor Report`n`n"
					$output += "**Generated**: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  `n"
					$output += "**Database**: $global:DbPath  `n`n"
					
					# Summary table
					$uniqueIps = $Data.Count
					$attackCount = ($Data | Where-Object { $_.ConnectionType -eq "Attack" }).Count
					$legitCount = ($Data | Where-Object { $_.ConnectionType -eq "Legit" }).Count
					
					$output += "## Summary`n"
					$output += "| Metric | Value |`n"
					$output += "|--------|-------|`n"
					$output += "| Unique IPs | $uniqueIps |`n"
					$output += "| Attack Attempts | $attackCount |`n"
					$output += "| Legitimate Logins | $legitCount |`n`n"
					
					# Detailed table
					$output += "## Connection Details`n"
					$output += "| IP Address | Type | Failed | Success | Total | First Attempt | Last Attempt | Duration |`n"
					$output += "|------------|------|--------|---------|-------|---------------|--------------|----------|`n"
					
					foreach ($item in $Data) {
						$durationFormatted = if ($item.Duration.Days -gt 0) {
							"$($item.Duration.Days)d $($item.Duration.Hours)h"
						}
						elseif ($item.Duration.Hours -gt 0) {
							"$($item.Duration.Hours)h $($item.Duration.Minutes)m"
						}
						else {
							"$($item.Duration.Minutes)m"
						}
						
						$output += "| $($item.IP) | $($item.ConnectionType) | $($item.FailCount) | $($item.SuccessCount) | $($item.TotalAttempts) | $($item.FirstLocal.ToString('yyyy-MM-dd HH:mm')) | $($item.LastLocal.ToString('yyyy-MM-dd HH:mm')) | $durationFormatted |`n"
					}
				}
				
				if ($FilePath) {
					$output | Out-File -FilePath $FilePath -Encoding UTF8 -Force
				}
			}
			
			'Object' {
				# Return the data objects directly
				$output = $Data
			}
		}
		
		Write-DebugStep -Phase "ExportResults" -Message "Export completed successfully" -Type 'Complete' -Data @{ Format = $Format }
		
		return $output
	}
}
#endregion

#region Database Recovery Functions
function Export-RdpMonDataToCsv {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$DbPath,
		
		[Parameter(Mandatory)]
		[string]$ExportPath
	)
	
	Write-Host "Starting emergency export of RdpMon data..." -ForegroundColor Cyan
	Write-Host "Database: $DbPath" -ForegroundColor Yellow
	Write-Host "Export to: $ExportPath" -ForegroundColor Yellow
	
	try {
		# Load LiteDB
		$liteDbPath = Join-Path -Path $PSScriptRoot -ChildPath "LiteDB\LiteDB.dll"
		if (-not (Test-Path -Path $liteDbPath)) {
			throw "LiteDB not found at: $liteDbPath"
		}
		Add-Type -Path $liteDbPath
		
		# Open database in read-only mode
		$connectionString = "Filename=$DbPath;ReadOnly=true"
		$db = [LiteDB.LiteDatabase]::new($connectionString)
		
		$exportData = @()
		$successCount = 0
		$errorCount = 0
		
		# Try to export Addr collection
		Write-Host "Exporting Addr collection..." -ForegroundColor Cyan
		try {
			$addrCollection = $db.GetCollection("Addr")
			$addrCount = $addrCollection.Count()
			Write-Host "Found $addrCount Addr records" -ForegroundColor Green
			
			$recordNum = 0
			foreach ($record in $addrCollection.FindAll()) {
				$recordNum++
				try {
					$exportRecord = [ordered]@{}
					
					# Extract fields carefully
					foreach ($key in @('_id', 'Addr', 'IP', 'Address', 'FailCount', 'SuccessCount', 'First', 'Last', 'UserNames')) {
						if ($record.ContainsKey($key)) {
							$value = $record[$key]
							if ($value -ne $null) {
								$exportRecord[$key] = $value.ToString()
							}
						}
					}
					
					if ($exportRecord.Count -gt 0) {
						$exportData += [PSCustomObject]$exportRecord
						$successCount++
					}
					
					if ($recordNum % 10 -eq 0) {
						Write-Host "Processed ${recordNum} records..." -ForegroundColor Gray
					}
				}
				catch {
					$errorCount++
					Write-Host "Error processing record ${recordNum}: ${_}" -ForegroundColor DarkYellow
				}
			}
		}
		catch {
			Write-Host "Cannot read Addr collection: ${_}" -ForegroundColor Red
		}
		
		# Try to export Session collection
		Write-Host "`nExporting Session collection..." -ForegroundColor Cyan
		try {
			$sessionCollection = $db.GetCollection("Session")
			$sessionCount = $sessionCollection.Count()
			Write-Host "Found $sessionCount Session records" -ForegroundColor Green
			
			$sessionData = @()
			$recordNum = 0
			foreach ($record in $sessionCollection.FindAll()) {
				$recordNum++
				try {
					$sessionRecord = [ordered]@{}
					foreach ($key in @('_id', 'Addr', 'User', 'Start', 'End', 'Flags', 'WtsSessionId')) {
						if ($record.ContainsKey($key)) {
							$value = $record[$key]
							if ($value -ne $null) {
								$sessionRecord[$key] = $value.ToString()
							}
						}
					}
					
					if ($sessionRecord.Count -gt 0) {
						$sessionData += [PSCustomObject]$sessionRecord
						$successCount++
					}
				}
				catch {
					$errorCount++
				}
				
				if ($recordNum % 10 -eq 0) {
					Write-Host "Processed $recordNum session records..." -ForegroundColor Gray
				}
			}
			
			# Export session data to separate file
			if ($sessionData.Count -gt 0) {
				$sessionExportPath = [System.IO.Path]::ChangeExtension($ExportPath, ".sessions.csv")
				$sessionData | Export-Csv -Path $sessionExportPath -NoTypeInformation -Encoding UTF8
				Write-Host "Session data exported to: $sessionExportPath" -ForegroundColor Green
			}
		}
		catch {
			Write-Host "Cannot read Session collection: $_" -ForegroundColor Red
		}
		
		# Export main data
		if ($exportData.Count -gt 0) {
			$exportData | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
			Write-Host "`nSUCCESS: Exported ${successCount} records to ${ExportPath}" -ForegroundColor Green
			Write-Host "Errors encountered: ${errorCount}" -ForegroundColor $(if ($errorCount -gt 0) { "Yellow" } else { "Green" })
			
			# Show sample data
			Write-Host "`nSample of exported data:" -ForegroundColor Cyan
			$exportData | Select-Object -First 5 | Format-Table -AutoSize
		}
		else {
			Write-Host "ERROR: No data could be exported." -ForegroundColor Red
		}
		
		$db.Dispose()
	}
	catch {
		Write-Host "FATAL ERROR: Cannot export data: $_" -ForegroundColor Red
	}
}

function Repair-RdpMonDatabase {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[string]$DbPath,
		
		[Parameter()]
		[string]$BackupPath = "$env:TEMP\RdpMon_Repaired.db"
	)
	
	Write-Host "Attempting to repair RdpMon database..." -ForegroundColor Cyan
	
	# Method 1: Try to open and re-save database
	try {
		$liteDbPath = Join-Path -Path $PSScriptRoot -ChildPath "LiteDB\LiteDB.dll"
		Add-Type -Path $liteDbPath
		
		# Open source database
		$sourceDb = [LiteDB.LiteDatabase]::new("Filename=$DbPath;ReadOnly=true")
		
		# Create new database
		$newDb = [LiteDB.LiteDatabase]::new("Filename=$BackupPath")
		
		# Copy collections
		$collections = $sourceDb.GetCollectionNames()
		foreach ($collectionName in $collections) {
			Write-Host "Copying collection: ${collectionName}" -ForegroundColor Gray
			try {
				$sourceCollection = $sourceDb.GetCollection($collectionName)
				$newCollection = $newDb.GetCollection($collectionName)
				
				foreach ($record in $sourceCollection.FindAll()) {
					try {
						$newCollection.Insert($record) | Out-Null
					}
					catch {
						Write-Host "  Skipping damaged record in ${collectionName}" -ForegroundColor DarkYellow
					}
				}
				
				Write-Host "  Copied $($newCollection.Count()) records" -ForegroundColor Green
			}
			catch {
				Write-Host "  Cannot copy collection ${collectionName}: ${_}" -ForegroundColor Red
			}
		}
		
		$sourceDb.Dispose()
		$newDb.Dispose()
		
		Write-Host "`nSUCCESS: Repaired database saved to: ${BackupPath}" -ForegroundColor Green
		Write-Host "You can now use the repaired database with the analyzer." -ForegroundColor Cyan
		
		return $BackupPath
	}
	catch {
		Write-Host "Repair failed: $_" -ForegroundColor Red
		return $null
	}
}
#endregion


#region Main Script Logic
# Enhanced parameter debugging
Write-DebugStep -Phase "ScriptInitialization" -Message "Initializing RDP Monitor Analyzer v$($global:ScriptConfig.Version)" -Type 'Start' -Data @{
	Parameters        = @{
		DbPath              = $DbPath
		Type                = $Type
		MinFails            = $MinFails
		From                = if ($From -eq [DateTime]::MinValue) { "Not set" } else { $From.ToString('yyyy-MM-dd HH:mm:ss') }
		To                  = if ($To -eq [DateTime]::MaxValue) { "Not set" } else { $To.ToString('yyyy-MM-dd HH:mm:ss') }
		OutputFormat        = $OutputFormat
		ExportPath          = $ExportPath
		SortBy              = $SortBy
		Descending          = $Descending
		Limit               = if ($Limit -eq [int]::MaxValue) { "No limit" } else { $Limit }
		IncludeResolved     = $IncludeResolved
		AutoRefreshInterval = $AutoRefreshInterval
		HtmlTemplatePath    = $HtmlTemplatePath
		DebugMode           = $DebugMode
		NoProgress          = $NoProgress
		LiteDbPath          = $LiteDbPath
		AutoInstallLiteDb   = $AutoInstallLiteDb
		LiteDbVersion       = $LiteDbVersion
		ForceLiteDbInstall  = $ForceLiteDbInstall
		SkipLiteDbInstall   = $SkipLiteDbInstall
		GitHubToken         = if ($GitHubToken) { "Provided" } else { "Not provided" }
	}
	PowerShellVersion = $PSVersionTable.PSVersion
	OS                = "$([Environment]::OSVersion.VersionString) ($([Environment]::OSVersion.Platform))"
	CurrentDirectory  = (Get-Location).Path
	ScriptDirectory   = $PSScriptRoot
	TempDirectory     = $env:TEMP
}

$ErrorActionPreference = 'Stop'

try {
	#region Initialize Global Variables
	Write-DebugStep -Phase "Initialization" -Message "Initializing global variables and configuration" -Type 'Progress'
	
	$global:DbPath = $DbPath
	$global:DebugConfig.Enabled = $DebugMode
	
	# Display banner if enabled
	if ($global:UiConfig.ShowBanner) {

		$accent = $PSStyle.Foreground.BrightCyan
		$muted = $PSStyle.Foreground.BrightBlack
		$highlight = $PSStyle.Foreground.BrightYellow
		$reset = $PSStyle.Reset

		$version = $global:ScriptConfig.Version
		$scriptName = "RDP Session Analyzer Pro"
		$tagline = "Advanced RDP Monitoring and Analysis Tool"
		$author = "Author : Mikhail Deynekin (deynekin.com)"
		$git = "Git    : $($global:ScriptConfig.Git)"

		Write-Host ""
		Write-Host ("".PadRight(80, "─")) -ForegroundColor DarkCyan

		Write-Host ("  $accent$scriptName$reset") 
		Write-Host ("  $muted$tagline$reset")
		Write-Host ""
		Write-Host ("  $highlight Version$reset : $version")
		Write-Host ("  $highlight $author$reset")
		Write-Host ("  $highlight $git$reset")

		Write-Host ("".PadRight(80, "─")) -ForegroundColor DarkCyan
		Write-Host ""

	}
	#endregion

	#region Database Connection
	Write-DebugStep -Phase "DatabaseSetup" -Message "Setting up database connection" -Type 'Start'
	
	Write-DebugStep -Phase "DatabaseSetup" -Message "Loading LiteDB assembly" -Type 'Progress'
	Import-LiteDbAssembly | Out-Null
	
	Write-DebugStep -Phase "DatabaseSetup" -Message "Connecting to database" -Type 'Progress' -Data @{ DbPath = $global:DbPath }
	$connectionString = "Filename=$($global:DbPath);ReadOnly=true;Utc=true"
	$global:DatabaseConnection = [LiteDB.LiteDatabase]::new($connectionString)
	
	Write-DebugStep -Phase "DatabaseSetup" -Message "Database connection established" -Type 'Complete'
	#endregion

	#region Database Diagnostics (Safe)
	Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Running safe database diagnostics" -Type 'Progress'
	
	try {
		$dbDiagnostics = Get-RdpMonDatabaseStructure
		
		# Log summary without trying to access potentially corrupted data
		Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Database diagnostics summary" -Type 'Info' -Data @{
			CollectionCount = $dbDiagnostics.Collections.Count
			ErrorCount      = $dbDiagnostics.Errors.Count
			IsCorrupted     = $dbDiagnostics.IsCorrupted
		}
		
		if ($dbDiagnostics.IsCorrupted) {
			Write-Host "WARNING: Database appears to be corrupted or partially damaged." -ForegroundColor Yellow
			Write-Host "The script will attempt to recover readable data, but some information may be lost." -ForegroundColor Yellow
			Write-Host "Errors: $($dbDiagnostics.Errors.Count)" -ForegroundColor Yellow
			
			# Continue anyway - we'll try to read what we can
			Write-Host "Attempting to continue with data recovery..." -ForegroundColor Cyan
		}
	}
	catch {
		Write-DebugStep -Phase "DatabaseDiagnostics" -Message "Database diagnostics failed completely" -Type 'Error' -Data @{ Error = $_.Exception.Message }
		Write-Host "ERROR: Cannot analyze database structure. Attempting to read data anyway..." -ForegroundColor Red
		# Continue and try to read data with extra error handling
	}
	#endregion

	#region Database Recovery Options
	if ($RepairDatabase) {
		Write-DebugStep -Phase "DatabaseRecovery" -Message "Starting database repair" -Type 'Start'
		
		$repairPath = if ($RepairOutputPath) { $RepairOutputPath } else { 
			Join-Path -Path (Split-Path -Path $global:DbPath -Parent) -ChildPath "RdpMon_Repaired.db" 
		}
		
		$repairedDb = Repair-RdpMonDatabase -DbPath $global:DbPath -BackupPath $repairPath
		
		if ($repairedDb -and (Test-Path -Path $repairedDb)) {
			Write-Host "Database repaired successfully!" -ForegroundColor Green
			Write-Host "Repaired database: $repairedDb" -ForegroundColor Cyan
			Write-Host "You can now run the analyzer on the repaired database:" -ForegroundColor Yellow
			Write-Host ".\$($global:ScriptConfig.Name)  -DbPath '$repairedDb' -OutputFormat Html -ExportPath 'report.html'" -ForegroundColor White
			exit 0
		}
		else {
			Write-Error "Database repair failed"
			exit 1
		}
	}
	
	if ($ExportRawData) {
		Write-DebugStep -Phase "DataExport" -Message "Starting raw data export" -Type 'Start'
		
		$exportPath = if ($RawExportPath) { $RawExportPath } else {
			Join-Path -Path (Split-Path -Path $global:DbPath -Parent) -ChildPath "RdpMon_RawData.csv"
		}
		
		Export-RdpMonDataToCsv -DbPath $global:DbPath -ExportPath $exportPath
		exit 0
	}
	#endregion

	#region Data Processing
	Write-DebugStep -Phase "DataProcessing" -Message "Starting data processing pipeline" -Type 'Start'

	# Step 1: Get enhanced data from all collections with chart data
	Write-DebugStep -Phase "DataProcessing" -Message "Retrieving enhanced data from all collections" -Type 'Progress'
	$completeData = Get-EnhancedRdpMonData

	# Step 2: Process enhanced data for modern HTML interface
	Write-DebugStep -Phase "DataProcessing" -Message "Processing enhanced data for modern interface" -Type 'Progress'
	$processedData = Process-EnhancedRdpMonData -Data $completeData

	if ($processedData.AddrResults.Count -eq 0) {
		Write-Warning "No data found in the RdpMon Addr collection."
		Write-DebugStep -Phase "DataProcessing" -Message "No data found in Addr collection" -Type 'Warning'
		
		# Still create empty report if requested
		if ($OutputFormat -eq 'Html' -and $ExportPath) {
			Write-DebugStep -Phase "DataProcessing" -Message "Creating empty HTML report as requested" -Type 'Progress'
			$emptyData = @{ 
				AddrResults    = @(); 
				SessionResults = @(); 
				PropResults    = @(); 
				DatabaseStats  = @{}; 
				SummaryStats   = @{};
				EnhancedData   = @{
					ChartData  = @{
						Timeline     = @{
							Labels      = @()
							FailData    = @()
							SuccessData = @()
						}
						Distribution = @{
							Labels = @()
							Data   = @()
						}
					}
					Statistics = @{}
				}
			}
			$output = Export-Results -Data $emptyData -Format $OutputFormat -FilePath $ExportPath
			
			if ($ExportPath) {
				Write-Host "Empty report created at: $ExportPath" -ForegroundColor Yellow
			}
		}
	}
	else {
		# Step 3: Sort and limit results for Addr data
		Write-DebugStep -Phase "DataProcessing" -Message "Applying sorting and limits to Addr data" -Type 'Progress'
		$finalAddrData = Sort-AndLimit-Results -Data $processedData.AddrResults
		
		# Update processed data with sorted Addr results
		$processedData.AddrResults = $finalAddrData
		
		# Store results globally
		$global:ResultsCollection = $finalAddrData
		
		# Step 4: Generate output
		Write-DebugStep -Phase "DataProcessing" -Message "Generating output in $OutputFormat format" -Type 'Progress'
		$output = Export-Results -Data $processedData -Format $OutputFormat -FilePath $ExportPath
		
		# Display output if not exporting to file or if format is not Object
		if ($OutputFormat -ne 'Object' -and -not $ExportPath) {
			Write-Output $output
		}
		elseif ($OutputFormat -eq 'Object') {
			# For Object format, output the processed data directly
			Write-Output $processedData
		}
		
		if ($ExportPath) {
			Write-Host "Results exported to: $ExportPath" -ForegroundColor Green
			Write-DebugStep -Phase "DataProcessing" -Message "Results exported to file: $ExportPath" -Type 'Info' -Data @{ FilePath = $ExportPath }
		}
	}

	Write-DebugStep -Phase "DataProcessing" -Message "Data processing completed" -Type 'Complete' -Data @{
		RawRecords      = $global:TotalRecordsProcessed
		FilteredRecords = $global:FilteredRecords
		FinalResults    = $global:ResultsCollection.Count
		SessionResults  = $processedData.SessionResults.Count
		PropResults     = $processedData.PropResults.Count
		ChartDataPoints = $processedData.EnhancedData.ChartData.Timeline.Labels.Count
	}
	#endregion

}
catch {
	Write-DebugStep -Phase "ScriptExecution" -Message "Script execution failed" -Type 'Error' -Data @{
		Error  = $_.Exception.Message
		Phase  = $global:ScriptPhase
		Status = $global:LastOperationStatus
		Line   = $_.InvocationInfo.ScriptLineNumber
		Offset = $_.InvocationInfo.OffsetInLine
	}
	
	Write-Error "Script execution failed: $_"
	Write-Error "Error details: $($_.Exception.Message)"
	Write-Error "Phase: $global:ScriptPhase"
	Write-Error "Last operation: $global:LastOperationStatus"
	
	if ($global:DebugConfig.Enabled) {
		Write-Error "Stack trace: $($_.ScriptStackTrace)"
		Write-Error "Line: $($_.InvocationInfo.ScriptLineNumber), Offset: $($_.InvocationInfo.OffsetInLine)"
		Write-Error "Command: $($_.InvocationInfo.Line)"
	}
	
	throw
}
finally {
	Write-DebugStep -Phase "Cleanup" -Message "Performing cleanup" -Type 'Start'
	
	# Cleanup
	if ($global:DatabaseConnection) {
		Write-DebugStep -Phase "Cleanup" -Message "Closing database connection" -Type 'Progress'
		$global:DatabaseConnection.Dispose()
		$global:DatabaseConnection = $null
	}
	
	Write-DebugStep -Phase "Cleanup" -Message "Cleanup completed" -Type 'Complete'
}

$endTime = Get-Date
$duration = $endTime - $global:ScriptStartTime

if ($global:UiConfig.ShowSummary) {

	$accent = $PSStyle.Foreground.BrightCyan
	$muted = $PSStyle.Foreground.BrightBlack
	$highlight = $PSStyle.Foreground.BrightYellow
	$reset = $PSStyle.Reset

	$liteDBName = if ($global:LiteDbAssembly) { $global:LiteDbAssembly.FullName.Split(',')[0] } else { "Not loaded" }
	$liteDBVer = if ($global:LiteDbAssembly) { $global:LiteDbAssembly.GetName().Version } else { "Unknown" }

	Write-Host ""

	Write-Host ("".PadRight(80, "─")) -ForegroundColor DarkCyan

	Write-Host ("  $accent EXECUTION SUMMARY | DB: $liteDBName $liteDBVer$reset")
	Write-Host ("  $muted Advanced RDP Analysis Results$reset")
	Write-Host ""

	Write-Host ("  $highlight Duration$reset      : $([math]::Round($duration.TotalSeconds, 2))s")
	Write-Host ("  $highlight Total Records$reset : $($global:TotalRecordsProcessed)")
	Write-Host ("  $highlight Filtered$reset      : $($global:FilteredRecords)")
	Write-Host ("  $highlight Results$reset       : $($global:ResultsCollection.Count)")
	Write-Host ("  $highlight Sessions$reset      : $(if ($processedData -and $processedData.SessionResults) { $processedData.SessionResults.Count } else { 0 })")
	Write-Host ("  $highlight Unique IPs$reset    : $(if ($processedData -and $processedData.SummaryStats) { $processedData.SummaryStats.UniqueIPs } else { 0 })")
	Write-Host ("  $highlight Attack Count$reset  : $(if ($processedData -and $processedData.SummaryStats) { $processedData.SummaryStats.AttackCount } else { 0 })")
	Write-Host ("  $highlight Legit Count$reset   : $(if ($processedData -and $processedData.SummaryStats) { $processedData.SummaryStats.LegitCount } else { 0 })")

	Write-Host ("".PadRight(80, "─")) -ForegroundColor DarkCyan
	Write-Host ""


}

Write-DebugStep -Phase "ScriptCompletion" -Message "Script execution completed" -Type 'Complete' -Data @{
	TotalDuration   = $duration.TotalSeconds
	TotalRecords    = $global:TotalRecordsProcessed
	FilteredRecords = $global:FilteredRecords
	OutputRecords   = $global:ResultsCollection.Count
	OutputFormat    = $OutputFormat
	ExportPath      = $ExportPath
	FileCreated     = if ($ExportPath) { Test-Path -Path $ExportPath } else { $null }
	EnhancedData    = if ($processedData -and $processedData.EnhancedData) { 
		@{
			ChartDataPoints = $processedData.EnhancedData.ChartData.Timeline.Labels.Count
			Statistics      = $processedData.EnhancedData.Statistics
		}
	}
	else { $null }
}

# If running interactively, show completion message
if ([Environment]::UserInteractive -and $global:UiConfig.ShowSummary) {
	Write-Host "RDP Monitor analysis completed successfully!" -ForegroundColor Green
	Write-Host "Duration: $([math]::Round($duration.TotalSeconds, 2)) seconds" -ForegroundColor Cyan
	
	if ($global:DebugConfig.Enabled) {
		Write-Host "Debug mode was enabled. Check above for detailed step-by-step output." -ForegroundColor Yellow
	}
	
	if ($AutoInstallLiteDb -and $global:LiteDbAssembly) {
		Write-Host "LiteDB was automatically installed to: $($global:LiteDbConfig.DefaultInstallPath)" -ForegroundColor Magenta
	}
	
	if ($ExportPath -and (Test-Path -Path $ExportPath)) {
		$fileInfo = Get-Item -Path $ExportPath
		Write-Host "Report saved to: $($fileInfo.FullName)" -ForegroundColor Green
		Write-Host "File size: $([math]::Round($fileInfo.Length / 1KB, 2)) KB" -ForegroundColor Cyan
		
		if ($OutputFormat -eq 'Html') {
			Write-Host "Open the report in your browser to view interactive charts and statistics." -ForegroundColor Magenta
		}
	}
	elseif ($ExportPath) {
		Write-Host "WARNING: Report was not created at: $ExportPath" -ForegroundColor Red
		Write-Host "Check if you have write permissions to the directory." -ForegroundColor Yellow
	}
}
#endregion

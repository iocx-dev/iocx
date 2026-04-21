# ============================================
# IOCX Adversarial PE Generator + Auto Builder
# Creates MSVC .vcxproj files using literal
# here-strings so MSBuild variables remain intact.
# Copies source files into project folders.
# Builds automatically.
# ============================================

function New-Vcxproj {
    param(
        [string]$ProjectName,
        [string]$SourceFile
    )

    # Ensure project folder exists
    New-Item -ItemType Directory -Force -Path $ProjectName | Out-Null

    # Copy the source file into the project folder
    Copy-Item -Path $SourceFile -Destination "$ProjectName\" -Force

    # Use literal here-string so MSBuild variables are preserved
    $proj = @'
<Project DefaultTargets="Build" ToolsVersion="17.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>

  <PropertyGroup Label="Globals">
    <ProjectGuid>{REPLACE-GUID}</ProjectGuid>
    <Keyword>Win32Proj</Keyword>
    <Platform>x64</Platform>
    <ProjectName>REPLACE-NAME</ProjectName>
  </PropertyGroup>

  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />

  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <WholeProgramOptimization>false</WholeProgramOptimization>
  </PropertyGroup>

  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />

  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>false</FunctionLevelLinking>
      <IntrinsicFunctions>false</IntrinsicFunctions>
      <BufferSecurityCheck>false</BufferSecurityCheck>
      <BasicRuntimeChecks>Default</BasicRuntimeChecks>
      <SDLCheck>false</SDLCheck>
      <PreprocessorDefinitions>NDEBUG;_WINDOWS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
    </ClCompile>

    <Link>
      <SubSystem>Windows</SubSystem>
      <GenerateDebugInformation>false</GenerateDebugInformation>
      <EntryPointSymbol>WinMainCRTStartup</EntryPointSymbol>
      <RandomizedBaseAddress>false</RandomizedBaseAddress>
      <DataExecutionPrevention>false</DataExecutionPrevention>
      <ImageHasSafeExceptionHandlers>false</ImageHasSafeExceptionHandlers>
    </Link>
  </ItemDefinitionGroup>

  <ItemGroup>
    <ClCompile Include="REPLACE-SOURCE" />
  </ItemGroup>

  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
'@

    # Replace placeholders
    $proj = $proj.Replace("REPLACE-GUID", ([guid]::NewGuid().ToString().ToUpper()))
    $proj = $proj.Replace("REPLACE-NAME", $ProjectName)
    $proj = $proj.Replace("REPLACE-SOURCE", $SourceFile)

    # Write project file
    $projPath = "$ProjectName\$ProjectName.vcxproj"
    Set-Content -Path $projPath -Value $proj -Encoding UTF8

    Write-Host "Generated: $projPath"
}

# ============================================
# Generate adversarial malformed PE projects
# ============================================

$projects = @(
    @{ Name="crypto_entropy_payload.full"; Src="crypto_entropy_payload.full.c" },
    @{ Name="string_obfuscation_tricks.full"; Src="string_obfuscation_tricks.full.c" },
    @{ Name="malformed_import_table.full"; Src="malformed_import_table.full.c" },
    @{ Name="invalid_section_alignment.full"; Src="invalid_section_alignment.full.c" },
    @{ Name="corrupted_data_directories.full"; Src="corrupted_data_directories.full.c" },
    @{ Name="truncated_rich_header.full"; Src="truncated_rich_header.full.c" },
    @{ Name="franken_malformed_pe.full"; Src="franken_malformed_pe.full.c" }
)

foreach ($p in $projects) {
    New-Vcxproj -ProjectName $p.Name -SourceFile $p.Src
}

Write-Host "`nBuilding adversarial malformed PE projects..."

foreach ($p in $projects) {
    msbuild "$($p.Name)\$($p.Name).vcxproj" /p:Configuration=Release /p:Platform=x64
}

Write-Host "`nAll malformed PE projects built successfully."

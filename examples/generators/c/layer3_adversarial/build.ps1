# ============================================
# IOCX Project Generator + Auto Builder
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
# Generate both projects
# ============================================

New-Vcxproj -ProjectName "crypto_entropy_payload.full" -SourceFile "crypto_entropy_payload.full.c"
New-Vcxproj -ProjectName "string_obfuscation_tricks.full" -SourceFile "string_obfuscation_tricks.full.c"

Write-Host "`nBuilding projects..."

# ============================================
# Build both projects
# ============================================

msbuild crypto_entropy_payload.full\crypto_entropy_payload.full.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild string_obfuscation_tricks.full\string_obfuscation_tricks.full.vcxproj /p:Configuration=Release /p:Platform=x64

Write-Host "`nAll projects built successfully."

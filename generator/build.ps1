param(
    [string]$PfInstallDir = 'C:\development\pingfed\pingfederate\12.3.3'
)
$ErrorActionPreference = 'Stop'
$lib = Join-Path $PfInstallDir 'server/default/lib'
$servlet = Join-Path $PfInstallDir 'sdk/lib/servlet-api.jar'
if (!(Test-Path (Join-Path $lib 'pingfederate-sdk.jar'))) { throw 'PF SDK installation not found' }
$target = Join-Path $PSScriptRoot 'target'
$classes = Join-Path $target 'classes'
$testClasses = Join-Path $target 'test-classes'
# No server files are modified. Build outputs stay under this project.
New-Item -ItemType Directory -Force $classes,$testClasses | Out-Null
$sources = @(Get-ChildItem (Join-Path $PSScriptRoot 'src/main/java') -Recurse -Filter '*.java' | ForEach-Object FullName)
& javac --release 11 -encoding UTF-8 -cp "$lib/*;$servlet" -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw 'Java compilation failed' }
Copy-Item (Join-Path $PSScriptRoot 'src/main/resources/PF-INF') $classes -Recurse -Force
$jar = Join-Path $target 'xaa-id-jag-generator.jar'
& jar --create --file $jar -C $classes .
if ($LASTEXITCODE -ne 0) { throw 'JAR packaging failed' }
$testSources = @(Get-ChildItem (Join-Path $PSScriptRoot 'src/proof/java') -Recurse -Filter '*.java' | ForEach-Object FullName)
& javac --release 11 -encoding UTF-8 -cp "$classes;$lib/*;$servlet" -d $testClasses @testSources
if ($LASTEXITCODE -ne 0) { throw 'Test compilation failed' }
& java -cp "$testClasses;$classes;$lib/*;$servlet" com.darkedges.pingfederate.xaa.GeneratorProof
if ($LASTEXITCODE -ne 0) { throw 'Generator proof failed' }
Write-Output "Built: $jar"

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $root 'NetGhost.ps1'
$source = Get-Content -Raw -LiteralPath $sourcePath

function Assert-True([bool]$condition, [string]$message) {
    if (-not $condition) { throw "FAIL: $message" }
}

# Static check: the complete script must remain parseable without loading WPF.
$tokens = $null; $errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$errors) | Out-Null
Assert-True ($errors.Count -eq 0) 'NetGhost.ps1 tiene errores de parseo'
Assert-True ($source -match 'Group-Object IP') 'La detección de duplicados debe agrupar entradas ARP'
Assert-True ($source -match 'Get-IPv4NetworkInfo') 'La autodetección debe usar cálculo CIDR'

# Load only the pure functions from the script, not its WPF startup code.
$ast = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
foreach ($name in @('Get-IPv4NetworkInfo', 'Test-ScanConfiguration', 'Find-Conflicts')) {
    $function = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    Invoke-Expression $function.Extent.Text
}

$network = Get-IPv4NetworkInfo -IPAddress '192.168.1.200' -PrefixLength 25
Assert-True ($network.NetworkAddress -eq '192.168.1.128' -and $network.Broadcast -eq '192.168.1.255') '/25 calcula red y broadcast incorrectos'
Assert-True ($network.RangeStart -eq 129 -and $network.RangeEnd -eq 254) '/25 calcula rango de hosts incorrecto'
$wide = Get-IPv4NetworkInfo -IPAddress '10.20.30.40' -PrefixLength 16
Assert-True ($wide.NetworkAddress -eq '10.20.0.0' -and $wide.Subnet -eq '10.20.0') '/16 calcula red incorrecta'
Assert-True (Test-ScanConfiguration '192.168.1' 1 254) 'Configuración válida rechazada'
Assert-True (-not (Test-ScanConfiguration '192.168.999' 1 254)) 'Octeto IPv4 inválido aceptado'

$results = [System.Collections.ObjectModel.ObservableCollection[PSObject]]::new()
$arp = @(
    '  192.168.1.10    aa-bb-cc-dd-ee-01     dynamic',
    '  192.168.1.10    aa-bb-cc-dd-ee-02     dynamic'
)
$conflicts = @(Find-Conflicts -Results $results -ArpLines $arp)
Assert-True (@($conflicts | Where-Object Tipo -eq 'IP Duplicada').Count -eq 1) 'No detecta dos MAC para la misma IP'
Write-Output 'PASS: NetGhost.Tests.ps1'

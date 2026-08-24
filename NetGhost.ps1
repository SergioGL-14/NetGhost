#Requires -Version 5.1
##############################################################
# NETGHOST – Red Scan & Conflict Hunter
# Version: 1.1
# Autor:   NetGhost Project
# Description: Scanning, diagnostics and conflict-detection
#              tool for Windows corporate networks.
# Changes in v1.1:
#   - Active network autodetection at startup
#   - "Detectar Red" button for manual refresh
#   - Virtual/VPN adapter filtering
##############################################################

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

##############################################################
# BLOCK 0 – GLOBAL CONFIGURATION
##############################################################

$Global:AppVersion        = "1.1.0"
$Global:ScanResults       = [System.Collections.ObjectModel.ObservableCollection[PSObject]]::new()
$Global:ConflictResults   = [System.Collections.ObjectModel.ObservableCollection[PSObject]]::new()
$Global:LogLines          = [System.Collections.Generic.List[string]]::new()
$Global:IsScanning        = $false

##############################################################
# BLOCK 1 – AUTOMATIC NETWORK DETECTION
##############################################################

function Get-IPv4NetworkInfo {
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [Parameter(Mandatory)][int]$PrefixLength
    )

    $address = $null
    if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$address) -or
        $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $PrefixLength -lt 0 -or $PrefixLength -gt 32) {
        throw "IPv4 o prefijo CIDR inválido: $IPAddress/$PrefixLength"
    }

    $bytes = $address.GetAddressBytes()
    [uint32]$ip = ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor
        ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]
    [uint32]$mask = if ($PrefixLength -eq 0) { 0 } else { [uint32]::MaxValue -shl (32 - $PrefixLength) }
    [uint32]$network = $ip -band $mask
    [uint32]$broadcast = $network -bor ([uint32]::MaxValue -bxor $mask)

    $networkBytes = [BitConverter]::GetBytes($network)
    [array]::Reverse($networkBytes)
    $networkAddress = ($networkBytes | ForEach-Object { $_ }) -join '.'
    $networkParts = $networkAddress.Split('.')
    $hostCount = [uint64]$broadcast - [uint64]$network - 1
    $usableStart = if ($PrefixLength -ge 31) { $null } else { [uint64]$network + 1 }
    $usableEnd = if ($PrefixLength -ge 31) { $null } else { [uint64]$broadcast - 1 }

    [PSCustomObject]@{
        NetworkAddress = $networkAddress
        Broadcast      = $(
            $broadcastBytes = [BitConverter]::GetBytes($broadcast)
            [array]::Reverse($broadcastBytes)
            ($broadcastBytes | ForEach-Object { $_ }) -join '.'
        )
        Prefix         = $PrefixLength
        Subnet         = "$($networkParts[0]).$($networkParts[1]).$($networkParts[2])"
        HostCount      = $hostCount
        RangeStart     = if ($null -eq $usableStart) { 0 } else { [int][math]::Max(1, $usableStart - ($network -band 0xFFFFFF00)) }
        RangeEnd       = if ($null -eq $usableEnd) { 0 } else { [int][math]::Min(254, $usableEnd - ($network -band 0xFFFFFF00)) }
    }
}

function Test-ScanConfiguration {
    param([string]$Subnet, [int]$RangeStart, [int]$RangeEnd)
    return ($Subnet -match '^(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)$' -and
        $RangeStart -ge 1 -and $RangeStart -le 254 -and
        $RangeEnd -ge $RangeStart -and $RangeEnd -le 254)
}

function Get-ActiveSubnet {
    # Active physical adapters with a gateway defined, virtual ones discarded
    $candidates = Get-NetIPConfiguration | Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -eq 'Up' -and
        $_.NetAdapter.InterfaceDescription -notmatch 'Hyper-V|VMware|VirtualBox|Loopback|Teredo|isatap|Bluetooth|TAP|Tunnel|WAN Miniport|Microsoft Wi-Fi Direct|Kernel Debug'
    }

    if (-not $candidates) {
        # Fallback: any active adapter with a valid IP
        $candidates = Get-NetIPConfiguration | Where-Object {
            $_.IPv4Address -ne $null -and
            $_.NetAdapter.Status -eq 'Up' -and
            $_.NetAdapter.InterfaceDescription -notmatch 'Hyper-V|VMware|VirtualBox|Loopback|Teredo'
        }
    }

    if (-not $candidates) { return $null }

    # Prioritize by route metric (lower = preferred by the OS)
    $selected = $candidates | Sort-Object {
        $gw = $_.IPv4DefaultGateway
        if ($gw) { $gw.RouteMetric + $gw.InterfaceMetric } else { 9999 }
    } | Select-Object -First 1

    if ($selected -and $selected.IPv4Address) {
        $ip     = $selected.IPv4Address[0].IPAddress
        $prefix = $selected.IPv4Address[0].PrefixLength

        try { $network = Get-IPv4NetworkInfo -IPAddress $ip -PrefixLength $prefix } catch { return $null }

        return [PSCustomObject]@{
             Subnet     = $network.Subnet
             RangeStart = $network.RangeStart
             RangeEnd   = $network.RangeEnd
             Network    = $network.NetworkAddress
             Broadcast  = $network.Broadcast
            LocalIP    = $ip
            Prefix     = $prefix
            Interface  = $selected.InterfaceAlias
            Gateway    = if ($selected.IPv4DefaultGateway) { $selected.IPv4DefaultGateway.NextHop } else { "N/A" }
        }
    }
    return $null
}

##############################################################
# BLOCK 2 – LOCAL NETWORK SCAN
##############################################################

function Get-ArpTable {
    $arpRaw  = arp -a 2>$null
    $entries = @()
    foreach ($line in $arpRaw) {
        if ($line -match '^\s+([\d\.]+)\s+([\w\-]+)\s+(\w+)') {
            $ip   = $Matches[1]
            $mac  = $Matches[2].ToUpper()
            $type = $Matches[3]
            if ($ip -notmatch '^(224\.|239\.|255\.|169\.254)') {
                $entries += [PSCustomObject]@{ IP = $ip; MAC = $mac; Type = $type }
            }
        }
    }
    return $entries
}

function Get-MACVendor {
    param([string]$MAC)
    $prefix = $MAC.Replace("-","").Replace(":","").Substring(0,6).ToUpper()
    $vendors = @{
        "001422" = "Realtek";       "00155D" = "Microsoft (Hyper-V)";
        "0016EA" = "HP";            "001A2B" = "Cisco";
        "001B63" = "Apple";         "001C42" = "Parallels";
        "00215A" = "Intel";         "002248" = "Intel";
        "0050F2" = "Microsoft";     "00E04C" = "Realtek";
        "080027" = "VirtualBox";    "000C29" = "VMware";
        "005056" = "VMware";        "B827EB" = "Raspberry Pi";
        "DC4F22" = "Raspberry Pi";  "E45F01" = "Raspberry Pi";
        "F0DEF1" = "HP";            "3C970E" = "HP";
        "00236C" = "Apple";         "001124" = "Dell";
        "001A4B" = "Dell"
    }
    if ($vendors.ContainsKey($prefix)) { return $vendors[$prefix] }
    return "Desconocido"
}

function Start-NetworkScan {
    param([string]$Subnet, [int]$RangeStart, [int]$RangeEnd)

    $Global:ScanQueue        = [System.Collections.Concurrent.ConcurrentQueue[PSObject]]::new()
    $Global:ScanDone         = $false
    $Global:ScanTotal        = $RangeEnd - $RangeStart + 1
    $Global:ScanDoneCount    = 0

    $scanScript = {
        param($Subnet, $RangeStart, $RangeEnd, $Queue, $DoneRef, $DoneCountRef)

        function Resolve-NBName {
            param([string]$IP)
            try {
                $r = nbtstat -A $IP 2>$null
                foreach ($l in $r) {
                    if ($l -match '^\s+(\S+)\s+<00>\s+UNIQUE') { return $Matches[1].Trim() }
                }
            } catch {}
            try { return ([System.Net.Dns]::GetHostEntry($IP)).HostName.Split('.')[0] } catch {}
            return "?"
        }

        function Get-Vendor {
            param([string]$MAC)
            $p = $MAC.Replace("-","").Replace(":","")
            if ($p.Length -lt 6) { return "Desconocido" }
            $p = $p.Substring(0,6).ToUpper()
            $v = @{
                "001422"="Realtek";"00155D"="Microsoft/Hyper-V";"0016EA"="HP";
                "001A2B"="Cisco";"001B63"="Apple";"001C42"="Parallels";
                "00215A"="Intel";"002248"="Intel";"0050F2"="Microsoft";
                "00E04C"="Realtek";"080027"="VirtualBox";"000C29"="VMware";
                "005056"="VMware";"B827EB"="Raspberry Pi";"DC4F22"="Raspberry Pi";
                "001124"="Dell";"001A4B"="Dell";"F0DEF1"="HP";"3C970E"="HP"
            }
            if ($v.ContainsKey($p)) { return $v[$p] }
            return "Desconocido"
        }

        function Test-TcpPort {
            param([string]$IP, [int]$Port, [int]$T = 600)
            try {
                $t = [System.Net.Sockets.TcpClient]::new()
                $a = $t.BeginConnect($IP, $Port, $null, $null)
                $r = $a.AsyncWaitHandle.WaitOne($T)
                $t.Close()
                return $r
            } catch { return $false }
        }

        # Leer tabla ARP una vez
        $arpMap = @{}
        try {
            $arpRaw = & arp -a 2>$null
            foreach ($line in $arpRaw) {
                if ($line -match '^\s+([\d\.]+)\s+([\w\:\-]+)\s+(\w+)') {
                    $xip = $Matches[1]; $xmac = $Matches[2].ToUpper()
                    if ($xip -notmatch '^(224\.|239\.|255\.|169\.254)') {
                        $arpMap[$xip] = $xmac
                    }
                }
            }
        } catch {}

        for ($i = $RangeStart; $i -le $RangeEnd; $i++) {
            $ip = "$Subnet.$i"
            try {
                $ping  = [System.Net.NetworkInformation.Ping]::new()
                $reply = $ping.Send($ip, 500)
                $ping.Dispose()

                if ($reply.Status -eq 'Success') {
                    $mac    = if ($arpMap.ContainsKey($ip)) { $arpMap[$ip] } else { "N/A" }
                    $vendor = Get-Vendor -MAC $mac
                    $nbname = Resolve-NBName -IP $ip
                    $smb    = Test-TcpPort -IP $ip -Port 445
                    $rdp    = Test-TcpPort -IP $ip -Port 3389

                    $issues = @()
                    if (-not $smb) { $issues += "Sin SMB" }
                    if (-not $rdp) { $issues += "Sin RDP" }
                    $status = "OK"
                    if ($mac -eq "N/A") { $issues += "Sin ARP"; $status = "SIN_ARP" }
                    elseif ($issues.Count -gt 0) { $status = "WARN" }

                    $row = [PSCustomObject]@{
                        IP         = $ip
                        NombreNB   = $nbname
                        MAC        = $mac
                        Fabricante = $vendor
                        Ping       = $reply.RoundtripTime
                        SMB        = if ($smb) { "SI" } else { "NO" }
                        RDP        = if ($rdp) { "SI" } else { "NO" }
                        Estado     = $status
                        Problemas  = if ($issues.Count -gt 0) { $issues -join " | " } else { "-" }
                    }
                    $Queue.Enqueue($row)
                }
            } catch {}

            $DoneCountRef.Value++
        }
        $DoneRef.Value = $true
    }

    $doneRef      = [ref]$false
    $doneCountRef = [ref]0
    $Global:ScanDoneRef       = $doneRef
    $Global:ScanDoneCountRef  = $doneCountRef

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = "STA"
    $rs.ThreadOptions  = "ReuseThread"
    $rs.Open()

    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    $null = $ps.AddScript($scanScript).AddArgument($Subnet).AddArgument($RangeStart).AddArgument($RangeEnd).AddArgument($Global:ScanQueue).AddArgument($doneRef).AddArgument($doneCountRef)

    $Global:ScanPS = $ps
    $Global:ScanRS = $rs
    $null = $ps.BeginInvoke()
}

##############################################################
# BLOCK 3 – CONFLICT ANALYSIS
##############################################################

function Find-Conflicts {
    param(
        [System.Collections.ObjectModel.ObservableCollection[PSObject]]$Results,
        [string[]]$ArpLines = @()
    )

    $conflicts = @()

    # IPs duplicadas (misma IP, distintas MACs en tabla ARP)
    if ($ArpLines.Count -eq 0) { $ArpLines = @(arp -a 2>$null) }
    $arpEntries = foreach ($line in $ArpLines) {
        if ($line -match '^\s+([\d\.]+)\s+([\w\:\-]+)\s+(\w+)') {
            [PSCustomObject]@{ IP = $Matches[1]; MAC = $Matches[2].ToUpper() }
        }
    }
    foreach ($group in ($arpEntries | Group-Object IP)) {
        $ip = $group.Name
        $macs = @($group.Group.MAC | Select-Object -Unique)
        if ($macs.Count -gt 1) {
            $conflicts += [PSCustomObject]@{
                Tipo      = "IP Duplicada"
                IP        = $ip
                Detalle   = "MACs: $($macs -join ' / ')"
                Severidad = "CRITICO"
            }
        }
    }

    # Nombres NetBIOS duplicados
    $nameMap = @{}
    foreach ($row in $Results) {
        $nb = $row.NombreNB
        if ($nb -ne "?" -and $nb -ne "") {
            if (-not $nameMap.ContainsKey($nb)) { $nameMap[$nb] = @() }
            $nameMap[$nb] += $row.IP
        }
    }
    foreach ($name in $nameMap.Keys) {
        if ($nameMap[$name].Count -gt 1) {
            $conflicts += [PSCustomObject]@{
                Tipo      = "NetBIOS Duplicado"
                IP        = ($nameMap[$name] -join " / ")
                Detalle   = "Nombre '$name' en múltiples IPs"
                Severidad = "CRITICO"
            }
        }
    }

    # Ping OK pero sin SMB ni RDP
    foreach ($row in $Results) {
        if ($row.SMB -eq "NO" -and $row.RDP -eq "NO") {
            $conflicts += [PSCustomObject]@{
                Tipo      = "Acceso Bloqueado"
                IP        = $row.IP
                Detalle   = "$($row.NombreNB) responde ping pero sin SMB/RDP"
                Severidad = "AVISO"
            }
        }
    }

    # Missing ARP entry (corpses)
    foreach ($row in $Results) {
        if ($row.MAC -eq "N/A" -or $row.Estado -eq "SIN_ARP") {
            $conflicts += [PSCustomObject]@{
                Tipo      = "Sin entrada ARP"
                IP        = $row.IP
                Detalle   = "$($row.NombreNB) responde ping pero sin registro ARP"
                Severidad = "AVISO"
            }
        }
    }

    return $conflicts
}

function Clear-ArpCache {
    try {
        $result = netsh interface ip delete arpcache 2>&1
        return "ARP cache limpiada: $result"
    } catch {
        return "Error al limpiar ARP: $_"
    }
}

##############################################################
# BLOCK 4 – WPF INTERFACE
##############################################################

$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="NetGhost – Red Scan &amp; Conflict Hunter v1.1"
    Height="750" Width="1200"
    MinHeight="600" MinWidth="900"
    WindowStartupLocation="CenterScreen"
    Background="#0D0F14">

    <Window.Resources>

        <SolidColorBrush x:Key="BgDeep"      Color="#0D0F14"/>
        <SolidColorBrush x:Key="BgPanel"     Color="#131720"/>
        <SolidColorBrush x:Key="BgCard"      Color="#1A1F2E"/>
        <SolidColorBrush x:Key="BgSidebar"   Color="#0F1219"/>
        <SolidColorBrush x:Key="AccentCyan"  Color="#00D4FF"/>
        <SolidColorBrush x:Key="AccentBlue"  Color="#3B82F6"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#E8EAF0"/>
        <SolidColorBrush x:Key="TextMuted"   Color="#6B7280"/>
        <SolidColorBrush x:Key="BorderSub"   Color="#252B3A"/>
        <SolidColorBrush x:Key="GreenOk"     Color="#22C55E"/>
        <SolidColorBrush x:Key="YellowWarn"  Color="#EAB308"/>
        <SolidColorBrush x:Key="RedCrit"     Color="#EF4444"/>

        <Style x:Key="BtnPrimary" TargetType="Button">
            <Setter Property="Background" Value="#3B82F6"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize"   Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding"    Value="14,8"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor"    Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#2563EB"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#1E293B"/>
                                <Setter Property="Foreground" Value="#4B5563"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="BtnSecondary" TargetType="Button">
            <Setter Property="Background" Value="#1A1F2E"/>
            <Setter Property="Foreground" Value="#94A3B8"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize"   Value="12"/>
            <Setter Property="Padding"    Value="12,8"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="BorderBrush" Value="#252B3A"/>
            <Setter Property="Cursor"    Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#252B3A"/>
                                <Setter Property="Foreground" Value="#E8EAF0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="BtnDetect" TargetType="Button">
            <Setter Property="Background" Value="#064E3B"/>
            <Setter Property="Foreground" Value="#34D399"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize"   Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding"    Value="14,8"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor"    Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#065F46"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#1E293B"/>
                                <Setter Property="Foreground" Value="#4B5563"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="BtnDanger" TargetType="Button">
            <Setter Property="Background" Value="#7F1D1D"/>
            <Setter Property="Foreground" Value="#FCA5A5"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize"   Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding"    Value="12,8"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor"    Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#991B1B"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="DarkTextBox" TargetType="TextBox">
            <Setter Property="Background"       Value="#0D0F14"/>
            <Setter Property="Foreground"       Value="#E8EAF0"/>
            <Setter Property="CaretBrush"       Value="#00D4FF"/>
            <Setter Property="BorderBrush"      Value="#252B3A"/>
            <Setter Property="BorderThickness"  Value="1"/>
            <Setter Property="FontFamily"       Value="Consolas"/>
            <Setter Property="FontSize"         Value="13"/>
            <Setter Property="Padding"          Value="8,6"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="5">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="2"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsFocused" Value="True">
                                <Setter Property="BorderBrush" Value="#00D4FF"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="NavButton" TargetType="Button">
            <Setter Property="Background"      Value="Transparent"/>
            <Setter Property="Foreground"      Value="#6B7280"/>
            <Setter Property="FontFamily"      Value="Consolas"/>
            <Setter Property="FontSize"        Value="13"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Padding"         Value="16,12"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor"          Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bdr"
                                Background="{TemplateBinding Background}"
                                BorderThickness="0"
                                CornerRadius="6"
                                Margin="8,2"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bdr" Property="Background" Value="#1A1F2E"/>
                                <Setter Property="Foreground" Value="#94A3B8"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="DarkGrid" TargetType="DataGrid">
            <Setter Property="Background"               Value="#131720"/>
            <Setter Property="Foreground"               Value="#E8EAF0"/>
            <Setter Property="BorderThickness"          Value="0"/>
            <Setter Property="GridLinesVisibility"      Value="Horizontal"/>
            <Setter Property="HorizontalGridLinesBrush" Value="#1E2433"/>
            <Setter Property="RowBackground"            Value="#131720"/>
            <Setter Property="AlternatingRowBackground" Value="#161B27"/>
            <Setter Property="FontFamily"               Value="Consolas"/>
            <Setter Property="FontSize"                 Value="12"/>
            <Setter Property="ColumnHeaderHeight"       Value="36"/>
            <Setter Property="RowHeight"                Value="32"/>
            <Setter Property="SelectionMode"            Value="Single"/>
            <Setter Property="AutoGenerateColumns"      Value="False"/>
            <Setter Property="CanUserAddRows"           Value="False"/>
            <Setter Property="CanUserDeleteRows"        Value="False"/>
            <Setter Property="IsReadOnly"               Value="True"/>
            <Setter Property="ScrollViewer.CanContentScroll" Value="True"/>
        </Style>

        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background"      Value="#0D0F14"/>
            <Setter Property="Foreground"      Value="#00D4FF"/>
            <Setter Property="FontFamily"      Value="Consolas"/>
            <Setter Property="FontSize"        Value="11"/>
            <Setter Property="FontWeight"      Value="Bold"/>
            <Setter Property="Padding"         Value="10,0"/>
            <Setter Property="BorderBrush"     Value="#252B3A"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
        </Style>

        <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding"         Value="8,0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Background="{TemplateBinding Background}" Padding="8,0">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#1E3A5F"/>
                    <Setter Property="Foreground" Value="White"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="ScrollBar">
            <Setter Property="Background" Value="#0D0F14"/>
            <Setter Property="Width" Value="8"/>
        </Style>

        <Style x:Key="SectionLabel" TargetType="TextBlock">
            <Setter Property="Foreground"  Value="#374151"/>
            <Setter Property="FontFamily"  Value="Consolas"/>
            <Setter Property="FontSize"    Value="10"/>
            <Setter Property="FontWeight"  Value="Bold"/>
            <Setter Property="Margin"      Value="16,12,0,4"/>
            <Setter Property="Text"        Value=""/>
        </Style>

    </Window.Resources>

    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="200"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- SIDEBAR -->
        <Border Grid.Column="0"
                Background="#0F1219"
                BorderBrush="#1A1F2E"
                BorderThickness="0,0,1,0">
            <DockPanel>

                <Border DockPanel.Dock="Top"
                        Background="#0B0D12"
                        Padding="16,20,16,16"
                        BorderBrush="#1A1F2E"
                        BorderThickness="0,0,0,1">
                    <StackPanel>
                        <TextBlock Text="◈  N E T G H O S T"
                                   Foreground="#00D4FF"
                                   FontFamily="Consolas"
                                   FontSize="14"
                                   FontWeight="Bold"/>
                        <TextBlock Text="Red Scan &amp; Conflict Hunter"
                                   Foreground="#374151"
                                   FontFamily="Consolas"
                                   FontSize="10"
                                   Margin="0,3,0,0"/>
                    </StackPanel>
                </Border>

                <Border DockPanel.Dock="Bottom"
                        Padding="16,10"
                        BorderBrush="#1A1F2E"
                        BorderThickness="0,1,0,0">
                    <TextBlock Foreground="#2D3748"
                               FontFamily="Consolas"
                               FontSize="10"
                               Text="v1.1.0 · PowerShell + WPF"/>
                </Border>

                <StackPanel Margin="0,8,0,0">
                    <TextBlock Style="{StaticResource SectionLabel}" Text="EXPLORACIÓN"/>
                    <Button x:Name="NavScan"      Style="{StaticResource NavButton}" Content="⬡  Escaneo de Red"   Tag="scan"/>
                    <Button x:Name="NavConflicts" Style="{StaticResource NavButton}" Content="⚡  Conflictos"       Tag="conflicts"/>
                    <TextBlock Style="{StaticResource SectionLabel}" Text="HERRAMIENTAS" Margin="16,16,0,4"/>
                    <Button x:Name="NavTools"     Style="{StaticResource NavButton}" Content="⬢  Herramientas ARP" Tag="tools"/>
                    <Button x:Name="NavLog"       Style="{StaticResource NavButton}" Content="≡  Log de Actividad" Tag="log"/>
                </StackPanel>
            </DockPanel>
        </Border>

        <!-- MAIN AREA -->
        <Grid Grid.Column="1">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <!-- TopBar -->
            <Border Grid.Row="0"
                    Background="#0F1219"
                    BorderBrush="#1A1F2E"
                    BorderThickness="0,0,0,1"
                    Padding="20,12">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock x:Name="TopBarTitle"
                               Text="Escaneo de Red"
                               Foreground="#E8EAF0"
                               FontFamily="Consolas"
                               FontSize="15"
                               FontWeight="SemiBold"
                               VerticalAlignment="Center"/>
                    <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                        <Ellipse x:Name="StatusDot" Width="8" Height="8" Fill="#22C55E" Margin="0,0,6,0"/>
                        <TextBlock x:Name="StatusText" Text="Listo"
                                   Foreground="#6B7280" FontFamily="Consolas" FontSize="11" VerticalAlignment="Center"/>
                    </StackPanel>
                </Grid>
            </Border>

            <!-- Per-page content -->
            <Grid Grid.Row="1" x:Name="MainContent">

                <!-- PAGE: SCAN -->
                <Grid x:Name="PageScan" Visibility="Visible">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <!-- Detected network banner -->
                    <Border x:Name="NetInfoBanner"
                            Grid.Row="0"
                            Background="#0A1628"
                            BorderBrush="#1E3A5F"
                            BorderThickness="0,0,0,1"
                            Padding="20,8"
                            Visibility="Collapsed">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="◈ " Foreground="#00D4FF" FontFamily="Consolas" FontSize="12" VerticalAlignment="Center"/>
                            <TextBlock x:Name="NetInfoText"
                                       Text=""
                                       Foreground="#60A5FA"
                                       FontFamily="Consolas"
                                       FontSize="11"
                                       VerticalAlignment="Center"/>
                        </StackPanel>
                    </Border>

                    <!-- Settings panel -->
                    <Border Grid.Row="1"
                            Background="#131720"
                            BorderBrush="#1A1F2E"
                            BorderThickness="0,0,0,1"
                            Padding="20,14">
                        <WrapPanel Orientation="Horizontal" VerticalAlignment="Center">

                            <!-- Detect network button -->
                            <StackPanel Orientation="Vertical" VerticalAlignment="Bottom" Margin="0,0,16,0">
                                <TextBlock Text="AUTO" Foreground="#374151"
                                           FontFamily="Consolas" FontSize="10" FontWeight="Bold" Margin="0,0,0,4"/>
                                <Button x:Name="BtnDetectNet"
                                        Content="⬡  DETECTAR RED"
                                        Style="{StaticResource BtnDetect}"
                                        Width="130"/>
                            </StackPanel>

                            <StackPanel Orientation="Vertical" Margin="0,0,16,0">
                                <TextBlock Text="SUBRED" Foreground="#374151"
                                           FontFamily="Consolas" FontSize="10" FontWeight="Bold" Margin="0,0,0,4"/>
                                <TextBox x:Name="TxtSubnet"
                                         Style="{StaticResource DarkTextBox}"
                                         Text="192.168.1"
                                         Width="130"/>
                            </StackPanel>

                            <StackPanel Orientation="Vertical" Margin="0,0,16,0">
                                <TextBlock Text="DESDE" Foreground="#374151"
                                           FontFamily="Consolas" FontSize="10" FontWeight="Bold" Margin="0,0,0,4"/>
                                <TextBox x:Name="TxtRangeStart"
                                         Style="{StaticResource DarkTextBox}"
                                         Text="1"
                                         Width="60"/>
                            </StackPanel>

                            <StackPanel Orientation="Vertical" Margin="0,0,20,0">
                                <TextBlock Text="HASTA" Foreground="#374151"
                                           FontFamily="Consolas" FontSize="10" FontWeight="Bold" Margin="0,0,0,4"/>
                                <TextBox x:Name="TxtRangeEnd"
                                         Style="{StaticResource DarkTextBox}"
                                         Text="50"
                                         Width="60"/>
                            </StackPanel>

                            <StackPanel Orientation="Vertical" VerticalAlignment="Bottom" Margin="0,0,10,0">
                                <TextBlock Text=" " FontSize="10" Margin="0,0,0,4"/>
                                <Button x:Name="BtnScan"
                                        Content="▶  ESCANEAR"
                                        Style="{StaticResource BtnPrimary}"
                                        Width="130"/>
                            </StackPanel>

                            <StackPanel Orientation="Vertical" VerticalAlignment="Bottom" Margin="0,0,10,0">
                                <TextBlock Text=" " FontSize="10" Margin="0,0,0,4"/>
                                <Button x:Name="BtnStopScan"
                                        Content="■  DETENER"
                                        Style="{StaticResource BtnSecondary}"
                                        Width="100"
                                        IsEnabled="False"/>
                            </StackPanel>

                            <StackPanel Orientation="Vertical" VerticalAlignment="Bottom">
                                <TextBlock Text=" " FontSize="10" Margin="0,0,0,4"/>
                                <Button x:Name="BtnClearScan"
                                        Content="✕  LIMPIAR"
                                        Style="{StaticResource BtnSecondary}"
                                        Width="100"/>
                            </StackPanel>

                        </WrapPanel>
                    </Border>

                    <!-- Results -->
                    <Grid Grid.Row="2">
                        <Grid.RowDefinitions>
                            <RowDefinition Height="*"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <DataGrid x:Name="GridScan" Grid.Row="0" Style="{StaticResource DarkGrid}" Margin="0">
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="IP"         Binding="{Binding IP}"         Width="120"/>
                                <DataGridTextColumn Header="NOMBRE"     Binding="{Binding NombreNB}"   Width="140"/>
                                <DataGridTextColumn Header="MAC"        Binding="{Binding MAC}"        Width="150"/>
                                <DataGridTextColumn Header="FABRICANTE" Binding="{Binding Fabricante}" Width="160"/>
                                <DataGridTextColumn Header="PING (ms)"  Binding="{Binding Ping}"       Width="80"/>
                                <DataGridTextColumn Header="SMB"        Binding="{Binding SMB}"        Width="55"/>
                                <DataGridTextColumn Header="RDP"        Binding="{Binding RDP}"        Width="55"/>
                                <DataGridTextColumn Header="ESTADO" Binding="{Binding Estado}" Width="90"/>
                                <DataGridTextColumn Header="PROBLEMAS" Binding="{Binding Problemas}" Width="*"/>
                            </DataGrid.Columns>
                        </DataGrid>

                        <!-- Progress bar -->
                        <Border Grid.Row="1"
                                Background="#0F1219"
                                BorderBrush="#1A1F2E"
                                BorderThickness="0,1,0,0"
                                Padding="16,8">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="*"/>
                                    <ColumnDefinition Width="Auto"/>
                                </Grid.ColumnDefinitions>
                                <ProgressBar x:Name="ScanProgress"
                                             Grid.Column="0"
                                             Height="6"
                                             Minimum="0" Maximum="100" Value="0"
                                             Background="#1A1F2E"
                                             Foreground="#00D4FF"
                                             BorderThickness="0"/>
                                <TextBlock x:Name="ScanProgressLabel"
                                           Grid.Column="1"
                                           Text="0 hosts"
                                           Foreground="#4B5563"
                                           FontFamily="Consolas"
                                           FontSize="11"
                                           Margin="12,0,0,0"
                                           VerticalAlignment="Center"/>
                            </Grid>
                        </Border>
                    </Grid>
                </Grid>

                <!-- PAGE: CONFLICTS -->
                <Grid x:Name="PageConflicts" Visibility="Collapsed">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border Grid.Row="0"
                            Background="#131720"
                            BorderBrush="#1A1F2E"
                            BorderThickness="0,0,0,1"
                            Padding="20,14">
                        <StackPanel Orientation="Horizontal">
                            <Button x:Name="BtnAnalyze"          Content="⚡  ANALIZAR CONFLICTOS" Style="{StaticResource BtnPrimary}"   Margin="0,0,10,0"/>
                            <Button x:Name="BtnExportConflicts"  Content="↓  EXPORTAR CSV"         Style="{StaticResource BtnSecondary}"/>
                            <Border Background="#1A1F2E" CornerRadius="6" Padding="10,0" Margin="16,0,0,0" VerticalAlignment="Center">
                                <TextBlock x:Name="ConflictCount"
                                           Text="0 conflictos detectados"
                                           Foreground="#6B7280"
                                           FontFamily="Consolas"
                                           FontSize="12"
                                           VerticalAlignment="Center"/>
                            </Border>
                        </StackPanel>
                    </Border>

                    <DataGrid x:Name="GridConflicts" Grid.Row="1" Style="{StaticResource DarkGrid}">
                        <DataGrid.Columns>
                            <DataGridTextColumn Header="TIPO" Binding="{Binding Tipo}" Width="160"/>
                            <DataGridTextColumn Header="IP / EQUIPOS" Binding="{Binding IP}"       Width="200"/>
                            <DataGridTextColumn Header="DETALLE"      Binding="{Binding Detalle}"   Width="*"/>
                            <DataGridTextColumn Header="SEVERIDAD" Binding="{Binding Severidad}" Width="100"/>
                        </DataGrid.Columns>
                    </DataGrid>
                </Grid>

                <!-- PAGE: ARP TOOLS -->
                <Grid x:Name="PageTools" Visibility="Collapsed">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border Grid.Row="0"
                            Background="#131720"
                            BorderBrush="#1A1F2E"
                            BorderThickness="0,0,0,1"
                            Padding="20,16">
                        <StackPanel>
                            <TextBlock Text="Herramientas Correctivas ARP"
                                       Foreground="#E8EAF0" FontFamily="Consolas" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,16"/>

                            <Border Background="#1A1F2E" CornerRadius="8" BorderBrush="#252B3A" BorderThickness="1"
                                    Padding="16" Margin="0,0,0,12" MaxWidth="500" HorizontalAlignment="Left">
                                <StackPanel>
                                    <TextBlock Text="Limpiar caché ARP local"
                                               Foreground="#E8EAF0" FontFamily="Consolas" FontSize="13" FontWeight="SemiBold"/>
                                    <TextBlock Text="Elimina todas las entradas ARP del equipo local. Requiere permisos de administrador."
                                               Foreground="#6B7280" FontFamily="Consolas" FontSize="11" TextWrapping="Wrap" Margin="0,6,0,12"/>
                                    <Button x:Name="BtnClearArp" Content="✕  LIMPIAR CACHÉ ARP LOCAL"
                                            Style="{StaticResource BtnDanger}" HorizontalAlignment="Left"/>
                                </StackPanel>
                            </Border>

                            <Border Background="#1A1F2E" CornerRadius="8" BorderBrush="#252B3A" BorderThickness="1"
                                    Padding="16" MaxWidth="500" HorizontalAlignment="Left">
                                <StackPanel>
                                    <TextBlock Text="Ver tabla ARP actual"
                                               Foreground="#E8EAF0" FontFamily="Consolas" FontSize="13" FontWeight="SemiBold"/>
                                    <TextBlock Text="Muestra la tabla ARP completa del sistema en el log de actividad."
                                               Foreground="#6B7280" FontFamily="Consolas" FontSize="11" TextWrapping="Wrap" Margin="0,6,0,12"/>
                                    <Button x:Name="BtnShowArp" Content="◈  VER TABLA ARP"
                                            Style="{StaticResource BtnSecondary}" HorizontalAlignment="Left"/>
                                </StackPanel>
                            </Border>
                        </StackPanel>
                    </Border>

                    <Border Grid.Row="1" Background="#0B0D12" Padding="16">
                        <TextBox x:Name="TxtArpOutput"
                                 Background="#0B0D12" Foreground="#00D4FF"
                                 FontFamily="Consolas" FontSize="12"
                                 BorderThickness="0" IsReadOnly="True"
                                 TextWrapping="NoWrap"
                                 VerticalScrollBarVisibility="Auto"
                                 HorizontalScrollBarVisibility="Auto"
                                 Text="-- Salida ARP aparecerá aquí --"/>
                    </Border>
                </Grid>

                <!-- PAGE: LOG -->
                <Grid x:Name="PageLog" Visibility="Collapsed">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>

                    <Border Grid.Row="0"
                            Background="#131720"
                            BorderBrush="#1A1F2E"
                            BorderThickness="0,0,0,1"
                            Padding="20,14">
                        <StackPanel Orientation="Horizontal">
                            <Button x:Name="BtnClearLog"  Content="✕  LIMPIAR LOG"   Style="{StaticResource BtnSecondary}" Margin="0,0,10,0"/>
                            <Button x:Name="BtnExportLog" Content="↓  EXPORTAR LOG"  Style="{StaticResource BtnSecondary}"/>
                        </StackPanel>
                    </Border>

                    <TextBox x:Name="TxtLog"
                             Grid.Row="1"
                             Background="#0B0D12" Foreground="#94A3B8"
                             FontFamily="Consolas" FontSize="12"
                             BorderThickness="0" IsReadOnly="True"
                             TextWrapping="NoWrap"
                             VerticalScrollBarVisibility="Auto"
                             HorizontalScrollBarVisibility="Auto"
                             Padding="16"/>
                </Grid>

            </Grid>

            <!-- Bottom StatusBar -->
            <Border Grid.Row="2"
                    Background="#0B0D12"
                    BorderBrush="#1A1F2E"
                    BorderThickness="0,1,0,0"
                    Padding="16,6">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock x:Name="StatusBarMsg"
                               Foreground="#374151" FontFamily="Consolas" FontSize="11"
                               VerticalAlignment="Center"
                               Text="Configura la subred y pulsa Escanear"/>
                    <TextBlock Grid.Column="1" x:Name="HostCount"
                               Foreground="#374151" FontFamily="Consolas" FontSize="11"
                               Margin="20,0,0,0" VerticalAlignment="Center" Text="0 hosts"/>
                    <TextBlock Grid.Column="2" x:Name="TimeStamp"
                               Foreground="#2D3748" FontFamily="Consolas" FontSize="11"
                               Margin="20,0,0,0" VerticalAlignment="Center"/>
                </Grid>
            </Border>

        </Grid>
    </Grid>
</Window>
"@

##############################################################
# BLOCK 4b – WINDOW LOADING AND BUILDING
##############################################################

$reader = [System.Xml.XmlNodeReader]::new([xml]$xaml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# Referencias a controles
$NavScan            = $window.FindName("NavScan")
$NavConflicts       = $window.FindName("NavConflicts")
$NavTools           = $window.FindName("NavTools")
$NavLog             = $window.FindName("NavLog")

$PageScan           = $window.FindName("PageScan")
$PageConflicts      = $window.FindName("PageConflicts")
$PageTools          = $window.FindName("PageTools")
$PageLog            = $window.FindName("PageLog")

$TopBarTitle        = $window.FindName("TopBarTitle")
$StatusDot          = $window.FindName("StatusDot")
$StatusText         = $window.FindName("StatusText")
$StatusBarMsg       = $window.FindName("StatusBarMsg")
$HostCount          = $window.FindName("HostCount")
$TimeStamp          = $window.FindName("TimeStamp")

$NetInfoBanner      = $window.FindName("NetInfoBanner")
$NetInfoText        = $window.FindName("NetInfoText")

$TxtSubnet          = $window.FindName("TxtSubnet")
$TxtRangeStart      = $window.FindName("TxtRangeStart")
$TxtRangeEnd        = $window.FindName("TxtRangeEnd")
$BtnDetectNet       = $window.FindName("BtnDetectNet")
$BtnScan            = $window.FindName("BtnScan")
$BtnStopScan        = $window.FindName("BtnStopScan")
$BtnClearScan       = $window.FindName("BtnClearScan")
$GridScan           = $window.FindName("GridScan")
$ScanProgress       = $window.FindName("ScanProgress")
$ScanProgressLabel  = $window.FindName("ScanProgressLabel")

$BtnAnalyze         = $window.FindName("BtnAnalyze")
$BtnExportConflicts = $window.FindName("BtnExportConflicts")
$GridConflicts      = $window.FindName("GridConflicts")
$ConflictCount      = $window.FindName("ConflictCount")

$BtnClearArp        = $window.FindName("BtnClearArp")
$BtnShowArp         = $window.FindName("BtnShowArp")
$TxtArpOutput       = $window.FindName("TxtArpOutput")

$TxtLog             = $window.FindName("TxtLog")
$BtnClearLog        = $window.FindName("BtnClearLog")
$BtnExportLog       = $window.FindName("BtnExportLog")

# Bindings
$GridScan.ItemsSource      = $Global:ScanResults
$GridConflicts.ItemsSource = $Global:ConflictResults

# GridScan row coloring by Estado
$GridScan.Add_LoadingRow({
    param($s, $e)
    $item = $e.Row.Item
    if ($item -isnot [PSCustomObject]) { return }
    switch ($item.Estado) {
        "OK"      {
            $e.Row.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0x22,0xC5,0x5E))
        }
        "WARN"    {
            $e.Row.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0xEA,0xB3,0x08))
        }
        "SIN_ARP" {
            $e.Row.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0xF9,0x73,0x16))
        }
        default   {
            $e.Row.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0xE8,0xEA,0xF0))
        }
    }
})

# GridConflicts row coloring by Severidad
$GridConflicts.Add_LoadingRow({
    param($s, $e)
    $item = $e.Row.Item
    if ($item -isnot [PSCustomObject]) { return }
    switch ($item.Severidad) {
        "CRITICO" {
            $e.Row.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0xEF,0x44,0x44))
            $e.Row.Background = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromArgb(0x22,0x45,0x0A,0x0A))
        }
        "AVISO"   {
            $e.Row.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0xEA,0xB3,0x08))
            $e.Row.Background = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromArgb(0x22,0x3F,0x31,0x00))
        }
        default   {
            $e.Row.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0xE8,0xEA,0xF0))
        }
    }
})

##############################################################
# BLOCK 4c – UI FUNCTIONS
##############################################################

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts     = (Get-Date).ToString("HH:mm:ss")
    $prefix = switch ($Level) {
        "OK"    { "[✔]" }
        "WARN"  { "[⚠]" }
        "ERROR" { "[✘]" }
        default { "[·]" }
    }
    $line = "$ts  $prefix  $Message"
    $window.Dispatcher.Invoke([action]{
        $TxtLog.AppendText("$line`n")
        $TxtLog.ScrollToEnd()
        $TimeStamp.Text = (Get-Date).ToString("HH:mm:ss")
    })
}

function Set-ActivePage {
    param([string]$Page)
    $pages   = @($PageScan, $PageConflicts, $PageTools, $PageLog)
    $navBtns = @($NavScan, $NavConflicts, $NavTools, $NavLog)
    foreach ($p in $pages)   { $p.Visibility = "Collapsed" }
    foreach ($b in $navBtns) {
        $b.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0x6B,0x72,0x80))
    }
    switch ($Page) {
        "scan"      { $PageScan.Visibility      = "Visible"; $TopBarTitle.Text = "Escaneo de Red";        $NavScan.Foreground      = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0x00,0xD4,0xFF)) }
        "conflicts" { $PageConflicts.Visibility = "Visible"; $TopBarTitle.Text = "Análisis de Conflictos"; $NavConflicts.Foreground = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0x00,0xD4,0xFF)) }
        "tools"     { $PageTools.Visibility     = "Visible"; $TopBarTitle.Text = "Herramientas ARP";      $NavTools.Foreground     = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0x00,0xD4,0xFF)) }
        "log"       { $PageLog.Visibility       = "Visible"; $TopBarTitle.Text = "Log de Actividad";      $NavLog.Foreground       = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0x00,0xD4,0xFF)) }
    }
}

function Set-ScanningState {
    param([bool]$Scanning)
    $Global:IsScanning       = $Scanning
    $BtnScan.IsEnabled       = -not $Scanning
    $BtnStopScan.IsEnabled   = $Scanning
    $BtnDetectNet.IsEnabled  = -not $Scanning
    $TxtSubnet.IsEnabled     = -not $Scanning
    $TxtRangeStart.IsEnabled = -not $Scanning
    $TxtRangeEnd.IsEnabled   = -not $Scanning
    if ($Scanning) {
        $StatusDot.Fill  = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0x00,0xD4,0xFF))
        $StatusText.Text = "Escaneando..."
        $StatusBarMsg.Text = "Escaneo en progreso..."
    } else {
        $StatusDot.Fill  = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromRgb(0x22,0xC5,0x5E))
        $StatusText.Text = "Listo"
    }
}

function Invoke-DetectNetwork {
    $info = Get-ActiveSubnet
    if ($info) {
        $TxtSubnet.Text     = $info.Subnet
        $TxtRangeStart.Text = $info.RangeStart.ToString()
        $TxtRangeEnd.Text   = $info.RangeEnd.ToString()
        $NetInfoText.Text   = "IP local: $($info.LocalIP)/$($info.Prefix)  ·  Gateway: $($info.Gateway)  ·  Interfaz: $($info.Interface)  ·  Red: $($info.Network)/$($info.Prefix)"
        $NetInfoBanner.Visibility = "Visible"
        $StatusBarMsg.Text  = "Red detectada: $($info.LocalIP) | GW: $($info.Gateway) | Iface: $($info.Interface)"
        Write-Log "Red detectada → Red: $($info.Network)/$($info.Prefix) | Rango: $($info.Subnet).$($info.RangeStart)-$($info.Subnet).$($info.RangeEnd) | IP: $($info.LocalIP) | GW: $($info.Gateway) | Interfaz: $($info.Interface)" "OK"
    } else {
        $NetInfoBanner.Visibility = "Collapsed"
        $StatusBarMsg.Text = "Sin red detectada — configura la subred manualmente"
        Write-Log "No se pudo autodetectar la red. Configura la subred manualmente." "WARN"
    }
    return $info
}

##############################################################
# BLOCK 4d – NAVIGATION EVENTS
##############################################################

$NavScan.Add_Click({      Set-ActivePage "scan"      })
$NavConflicts.Add_Click({ Set-ActivePage "conflicts" })
$NavTools.Add_Click({     Set-ActivePage "tools"     })
$NavLog.Add_Click({       Set-ActivePage "log"       })

##############################################################
# BLOCK 4e – DETECTION AND SCAN EVENTS
##############################################################

$BtnDetectNet.Add_Click({
    Invoke-DetectNetwork | Out-Null
})

$BtnScan.Add_Click({
    $subnet = $TxtSubnet.Text.Trim()
    $start  = 0; $end = 0
    if (-not [int]::TryParse($TxtRangeStart.Text, [ref]$start) -or
        -not [int]::TryParse($TxtRangeEnd.Text,   [ref]$end)) {
        [System.Windows.MessageBox]::Show(
            "El rango debe ser numérico (1-254).",
            "NetGhost – Configuración inválida",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning) | Out-Null
        return
    }

    if (-not (Test-ScanConfiguration -Subnet $subnet -RangeStart $start -RangeEnd $end)) {
        [System.Windows.MessageBox]::Show(
            "Verifica la subred (ej: 192.168.1) y el rango (1-254).",
            "NetGhost – Configuración inválida",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning) | Out-Null
        return
    }

    $Global:ScanResults.Clear()
    $ScanProgress.Value     = 0
    $ScanProgressLabel.Text = "0 hosts"
    $HostCount.Text         = "0 hosts activos"
    Set-ScanningState $true
    Write-Log "Iniciando escaneo: $subnet.$start – $subnet.$end  ($(($end - $start + 1)) IPs)"

    Start-NetworkScan -Subnet $subnet -RangeStart $start -RangeEnd $end

    $Global:PollTimer = [System.Windows.Threading.DispatcherTimer]::new()
    $Global:PollTimer.Interval = [TimeSpan]::FromMilliseconds(250)

    $Global:PollTimer.Add_Tick({
        $item = $null
        while ($Global:ScanQueue.TryDequeue([ref]$item)) {
            $Global:ScanResults.Add($item)
        }

        $done  = $Global:ScanDoneCountRef.Value
        $total = $Global:ScanTotal
        $count = $Global:ScanResults.Count
        $pct   = if ($total -gt 0) { [int](($done / $total) * 100) } else { 0 }

        $ScanProgress.Value     = $pct
        $ScanProgressLabel.Text = "$count hosts"
        $HostCount.Text         = "$count hosts activos"
        $StatusBarMsg.Text      = "Progreso: $pct%  ($done/$total IPs)  ·  $count activos"

        if ($Global:ScanDoneRef.Value -eq $true) {
            $item2 = $null
            while ($Global:ScanQueue.TryDequeue([ref]$item2)) {
                $Global:ScanResults.Add($item2)
            }
            $Global:PollTimer.Stop()
            try { $Global:ScanPS.Dispose() } catch {}
            try { $Global:ScanRS.Close(); $Global:ScanRS.Dispose() } catch {}

            $finalCount = $Global:ScanResults.Count
            $ScanProgress.Value     = 100
            $ScanProgressLabel.Text = "$finalCount hosts"
            $HostCount.Text         = "$finalCount hosts activos"
            $StatusBarMsg.Text      = "Escaneo completado · $finalCount hosts activos"
            Set-ScanningState $false
            Write-Log "Escaneo finalizado: $finalCount hosts activos en $($TxtSubnet.Text).$($TxtRangeStart.Text)-$($TxtRangeEnd.Text)" "OK"
        }
    })

    $Global:PollTimer.Start()
})

$BtnStopScan.Add_Click({
    if ($Global:PollTimer) { $Global:PollTimer.Stop() }
    try { $Global:ScanPS.Stop(); $Global:ScanPS.Dispose() } catch {}
    try { $Global:ScanRS.Close(); $Global:ScanRS.Dispose() } catch {}
    $item = $null
    while ($Global:ScanQueue -and $Global:ScanQueue.TryDequeue([ref]$item)) {
        $Global:ScanResults.Add($item)
    }
    Set-ScanningState $false
    $count = $Global:ScanResults.Count
    $StatusBarMsg.Text      = "Escaneo detenido · $count hosts hasta ahora"
    $ScanProgressLabel.Text = "$count hosts"
    Write-Log "Escaneo detenido por el usuario. $count hosts encontrados." "WARN"
})

$BtnClearScan.Add_Click({
    $Global:ScanResults.Clear()
    $ScanProgress.Value     = 0
    $ScanProgressLabel.Text = "0 hosts"
    $HostCount.Text         = "0 hosts"
    $StatusBarMsg.Text      = "Resultados limpiados"
    Write-Log "Tabla de escaneo limpiada"
})

##############################################################
# BLOCK 4f – CONFLICT EVENTS
##############################################################

$BtnAnalyze.Add_Click({
    if ($Global:ScanResults.Count -eq 0) {
        [System.Windows.MessageBox]::Show(
            "Realiza primero un escaneo de red.",
            "NetGhost – Sin datos",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Information) | Out-Null
        return
    }
    $Global:ConflictResults.Clear()
    Write-Log "Analizando conflictos..."
    $StatusBarMsg.Text = "Analizando conflictos..."
    $found = Find-Conflicts -Results $Global:ScanResults
    foreach ($c in $found) { $Global:ConflictResults.Add($c) }
    $n = $Global:ConflictResults.Count
    $ConflictCount.Text = "$n conflictos detectados"
    $StatusBarMsg.Text  = "Análisis completado: $n conflictos"
    Write-Log "Análisis completado: $n conflictos detectados" $(if ($n -gt 0) {"WARN"} else {"OK"})
})

$BtnExportConflicts.Add_Click({
    if ($Global:ConflictResults.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No hay conflictos para exportar.", "NetGhost",
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
        return
    }
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter   = "CSV|*.csv"
    $dlg.FileName = "NetGhost_Conflictos_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    if ($dlg.ShowDialog()) {
        $Global:ConflictResults | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
        Write-Log "Conflictos exportados: $($dlg.FileName)" "OK"
        $StatusBarMsg.Text = "Exportado: $($dlg.FileName)"
    }
})

##############################################################
# BLOCK 4g – ARP TOOLS EVENTS
##############################################################

$BtnClearArp.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show(
        "¿Limpiar la caché ARP local? Esto puede afectar temporalmente la conectividad.",
        "NetGhost – Confirmar acción",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning)
    if ($confirm -eq "Yes") {
        $result = Clear-ArpCache
        Write-Log $result $(if ($result -match "Error") {"ERROR"} else {"OK"})
        $StatusBarMsg.Text = $result
    }
})

$BtnShowArp.Add_Click({
    $raw = arp -a 2>$null
    $TxtArpOutput.Text = ($raw -join "`n")
    Write-Log "Tabla ARP volcada en Herramientas" "INFO"
    Set-ActivePage "tools"
})

##############################################################
# BLOCK 4h – LOG EVENTS
##############################################################

$BtnClearLog.Add_Click({
    $TxtLog.Clear()
    Write-Log "Log limpiado"
})

$BtnExportLog.Add_Click({
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter   = "Texto|*.txt"
    $dlg.FileName = "NetGhost_Log_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
    if ($dlg.ShowDialog()) {
        $TxtLog.Text | Out-File -FilePath $dlg.FileName -Encoding UTF8
        Write-Log "Log exportado: $($dlg.FileName)" "OK"
    }
})

##############################################################
# BLOCK 4i – INIT AND STARTUP
##############################################################

# Timestamp en tiempo real
$timer = [System.Windows.Threading.DispatcherTimer]::new()
$timer.Interval = [TimeSpan]::FromSeconds(1)
$timer.Add_Tick({ $TimeStamp.Text = (Get-Date).ToString("HH:mm:ss") })
$timer.Start()

# Initial page
Set-ActivePage "scan"
Write-Log "NetGhost iniciado. Versión $Global:AppVersion"
Write-Log "Sistema: $env:COMPUTERNAME | Usuario: $env:USERNAME"

# Network autodetection at startup
Invoke-DetectNetwork | Out-Null

# Mostrar ventana
$null = $window.ShowDialog()
$timer.Stop()

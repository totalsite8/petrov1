# Amiconnect: MTU физических адаптеров при установке и удалении.
# Save: сохранить исходный NlMtu каждого отобранного адаптера (по InterfaceGuid) и установить 1400.
# Restore: вернуть сохранённые значения и удалить ключ OriginalMtu.
# MTU сторонних VPN и виртуальных адаптеров (Cisco AnyConnect / Secure Client и т. п.) не меняется ни в каком
# режиме установки (ТП 784). HardwareInterface объявляет сам драйвер минипорта, поэтому отбор — по нескольким
# независимым признакам: аппаратный интерфейс, не Virtual, есть разъём, устройство не программное (ROOT\, SWD\)
# и описание не стороннего VPN/виртуального адаптера.
param([Parameter(Mandatory=$true)][ValidateSet('Save','Restore')][string]$Mode)
$ErrorActionPreference = 'Continue'
$key = 'HKLM:\SOFTWARE\AMICON\Amiconnect\OriginalMtu'
$ThirdParty = 'Cisco|AnyConnect|Secure Client|VPN|TAP-Win|Wintun|WireGuard|Forti|Juniper|Pulse Secure|Ivanti|PANGP|GlobalProtect|Palo Alto|Check Point|Kaspersky|Npcap|Loopback|Virtual Miniport|Virtual Adapter|Virtual Ethernet|VirtualBox|Amiconnect'
function Test-AmiconnectMtuAdapter($adapter) {
    if ($adapter.HardwareInterface -ne $true -or $adapter.Virtual -eq $true -or $adapter.ConnectorPresent -ne $true) { return $false }
    if ([string]$adapter.PnPDeviceID -match '^(ROOT|SWD)\\') { return $false }
    foreach ($text in @([string]$adapter.InterfaceDescription, [string]$adapter.DriverDescription)) {
        if ($text -match $ThirdParty) { return $false }
    }
    return $true
}
$all = @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter)
$adapters = @($all | Where-Object { Test-AmiconnectMtuAdapter $_ })
if ($Mode -eq 'Save') {
    if (!(Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    $saved = @((Get-Item $key).Property)
    foreach ($adapter in $all) {
        if ($adapters -notcontains $adapter) { Write-Output "MTU unchanged: $($adapter.Name) ($($adapter.InterfaceDescription))" }
    }
    foreach ($adapter in $adapters) {
        $guid = $adapter.InterfaceGuid
        if ($saved -notcontains $guid) {
            $ip = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetIPInterface -Filter ("InterfaceIndex=" + $adapter.InterfaceIndex + " AND AddressFamily=2")
            if ($ip) { New-ItemProperty -Path $key -Name $guid -Value ([int]$ip.NlMtu) -PropertyType DWord -Force | Out-Null }
        }
        Write-Output "MTU 1400: $($adapter.Name) ($($adapter.InterfaceDescription))"
        netsh interface ipv4 set subinterface "$($adapter.Name)" mtu=1400 store=persistent
    }
}
else {
    if (Test-Path $key) {
        $values = Get-ItemProperty $key
        foreach ($guid in (Get-Item $key).Property) {
            # Среди всех адаптеров: значение могла сохранить прежняя версия для адаптера, который теперь не отбирается.
            $adapter = $all | Where-Object { $_.InterfaceGuid -eq $guid }
            if ($adapter) { netsh interface ipv4 set subinterface "$($adapter.Name)" mtu=$($values.$guid) store=persistent }
        }
        Remove-Item -Path $key -Force
    }
}

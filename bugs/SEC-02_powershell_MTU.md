# SEC-02. Скрытый запуск PowerShell с `-ExecutionPolicy Bypass` и снижение MTU до 1400

* **Важность:** средняя (обход политики выполнения скриптов, незаметное изменение
  сетевых настроек, непроверяемый результат)
* **Компонент:** `extracted/payload/amiconnect-mtu.ps1` (3 563 Б, UTF-8 с BOM) +
  места вызова
* **Инструкции:** установщик 1655–1663 (секция «Reduce MTU…»), деинсталлятор 140–145

## Что происходит

1. Скрипт кладётся в каталог установки (`SetOutPath $INSTDIR`, 1655) и запускается
   скрыто и в обход политики выполнения:

```
1660  Push "powershell.exe -InputFormat None -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $\"$INSTDIR\amiconnect-mtu.ps1$\" -Mode Save"
1661  Push "/TIMEOUT=60000"
1662  CallInstDLL/Plugin "$PLUGINSDIR\nsExec.dll" (func="ExecToLog")
1663  Pop $0
```

   Деинсталлятор делает то же самое с `-Mode Restore` (142–145).

2. Сам скрипт (`param([Parameter(Mandatory=$true)][ValidateSet('Save','Restore')])`)
   **не меняет MTU «всего подряд»** — он специально отбирает адаптеры
   (`Test-AmiconnectMtuAdapter`):

```powershell
if ($adapter.HardwareInterface -ne $true -or $adapter.Virtual -eq $true -or $adapter.ConnectorPresent -ne $true) { return $false }
if ([string]$adapter.PnPDeviceID -match '^(ROOT|SWD)\\') { return $false }
# описание не должно содержать:
'Cisco|AnyConnect|Secure Client|VPN|TAP-Win|Wintun|WireGuard|Forti|Juniper|Pulse Secure|Ivanti|
 PANGP|GlobalProtect|Palo Alto|Check Point|Kaspersky|Npcap|Loopback|Virtual Miniport|
 Virtual Adapter|Virtual Ethernet|VirtualBox|Amiconnect'
```

   Для отобранных адаптеров прежнее `NlMtu` сохраняется в
   `HKLM\SOFTWARE\AMICON\Amiconnect\OriginalMtu` (DWORD на каждый `InterfaceGuid`),
   после чего выполняется `netsh interface ipv4 set subinterface "<имя>" mtu=1400
   store=persistent`; для остальных печатается `MTU unchanged: …`.
   `-Mode Restore` возвращает сохранённые значения и удаляет ключ `OriginalMtu`.

## Почему это риск/дефект

1. **`-ExecutionPolicy Bypass` + `-WindowStyle Hidden`.** Установщик запускает
   PowerShell-код, игнорируя политику выполнения (в домене она обычно задаётся GPO)
   и ничего не показывая пользователю. Именно так выглядят и вредоносные скрипты,
   поэтому такой запуск закономерно вызывает срабатывание EDR и вопросы ИБ.
   Для служебного скрипта достаточно подписи и `-ExecutionPolicy RemoteSigned`.
2. **Изменение MTU у пользователя без его ведома.** В интерфейсе нет ничего, кроме
   строки в окне деталей; между тем снижение MTU до 1400 у физических адаптеров
   заметно для VPN, RDP, IPv6 и приложений с крупными пакетами. Формально это
   требование ТП 784 (скрипт его упоминает), но пользователь о нём не
   информируется и не может отказаться.
3. **Отбор адаптеров по подстроке в описании — хрупкий.** Любой «неизвестный»
   виртуальный адаптер (новый VPN-клиент, не перечисленный в списке, эмулятор,
   туннель с описанием без ключевых слов) будет считаться физическим и получит
   MTU 1400; наоборот, физический адаптер с описанием, содержащим «VPN» (частый
   случай у некоторых usb-модемов), не будет изменён. Правильнее ориентироваться на
   `NdisPhysicalMedium`/`MediaType` и `ifType`, а список вендоров держать в
   настраиваемом виде.
4. **Результат не проверяется.** `Pop $0` (1663) снимает код возврата, но
   ветвления по нему нет: если PowerShell не отработал (политика, отсутствие
   `netsh`, отсутствие `MSFT_NetAdapter` в старых сборках), установка всё равно
   считается успешной, а MTU остаётся прежним — ошибку никто не увидит.
5. **Восстановление зависит от одного ключа реестра.** Если
   `HKLM\SOFTWARE\AMICON\Amiconnect\OriginalMtu` будет удалён (чистка реестра,
   «оптимизаторы», неполное удаление), `-Mode Restore` молча ничего не сделает
   (`if (Test-Path $key)`), и MTU 1400 останется на машине навсегда — пользователь
   не поймёт причину.
6. **Файл скрипта лежит в каталоге установки** и запускается «как есть», без
   проверки подписи/хэша. Каталог `$INSTDIR` этот установщик «Пользователям» не
   открывает (права на запись выданы только на `$INSTDIR\log` и три конфигурации —
   см. `SEC-03`), поэтому атака требует прав администратора; но там, где ACL
   каталога ослаблены (старые версии продукта, сторонние «установщики в Program
   Files», ручные правки), это готовая точка подмены кода, который затем
   выполняется с повышением прав при удалении продукта. Хранить скрипт стоит в
   защищённом месте (`%ProgramData%\AMICON\…` с ACL SYSTEM/Administrators), а не в
   каталоге с данными пользователя.

## Рекомендации

* подписать скрипт и запускать без `Bypass`/`Hidden`, показывать пользователю
  список интерфейсов, которые будут изменены, и запрашивать согласие;
* отбор адаптеров — по типу носителя, а не по подстроке описания;
* проверять код возврата и писать результат в журнал/интерфейс;
* перед восстановлением проверять, что сохранённые значения действительно есть, и
  предусмотреть ручное восстановление MTU (документация/пункт в GUI).

## Как проверить самому

```bash
grep -n "amiconnect-mtu.ps1" decompiled/functions.txt decompiled_uninstaller/functions.txt
python3 -c "print(open('extracted/payload/amiconnect-mtu.ps1',encoding='utf-8-sig').read())"
```

Динамически: запустить установщик на тестовой машине с виртуальными адаптерами и
посмотреть, у каких адаптеров изменился MTU (`netsh interface ipv4 show subinterfaces`).

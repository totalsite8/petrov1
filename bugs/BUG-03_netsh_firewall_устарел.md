# BUG-03. Устаревший контекст `netsh firewall` для правила брандмауэра

* **Важность:** средняя (зависит от версии Windows и политик; ошибка игнорируется)
* **Компонент:** установщик (добавление правила), деинсталлятор (удаление правила)
* **Инструкции:** установщик 1101 и 1605; деинсталлятор 156

## Суть

Правило брандмауэра создаётся и удаляется через устаревший контекст `netsh firewall`:

```
установщик:
1101  Push "netsh firewall delete allowedprogram $\"$1\amiconnectd.exe$\""       ; удаление «старой» записи
1605  Push "netsh firewall add allowedprogram $\"$INSTDIR\amiconnectd.exe$\" $\"Amiconnect$\" ENABLE"

деинсталлятор:
156   Push "netsh firewall delete allowedprogram $\"$INSTDIR\amiconnectd.exe$\""
```

Microsoft признала контекст `netsh firewall` устаревшим начиная с Windows Vista и
рекомендует `netsh advfirewall firewall` (KB947709). На современных системах
`netsh firewall` — это совместимый шим, который:

* печатает предупреждение `IMPORTANT: "netsh firewall" is deprecated; use "netsh advfirewall firewall" instead`;
* добавляет правило не в тот профиль/не с теми параметрами, что ожидалось
  (легаси-контекст работает только через `WF_*` API и не покрывает, например,
  разделение профилей domain/private/public);
* может быть недоступен/запрещён групповыми политиками, а на серверных SKU и в
  hardened-образах отрабатывает с ошибкой.

Результат команды нигде не проверяется (см. BUG-04), поэтому и «правило добавлено»,
и «правило не добавлено» выглядят в журнале одинаково — только текстом вывода
`nsExec`, который никто не читает.

## Последствия

* VPN-клиент может не получить разрешение в брандмауэре → не работает установка
  туннеля, при этом инсталлятор сообщает об успехе;
* при удалении правило может остаться (мусор в списке правил, потенциально
  разрешающий трафик уже удалённой программы).

## Что должно быть

```nsis
; добавление
Push '"$SYSDIR\netsh.exe" advfirewall firewall add rule name="Amiconnect Service" ^
      dir=in program="$INSTDIR\amiconnectd.exe" action=allow profile=any enable=yes'
; удаление
Push '"$SYSDIR\netsh.exe" advfirewall firewall delete rule name="Amiconnect Service"'
```

Плюс проверка кода возврата `Pop $0` и `StrCmp $0 "0"`.

## Как воспроизвести

На Windows 10/11 выполнить в консоли администратора:

```
netsh firewall add allowedprogram "C:\Program Files\AMICON\Amiconnect\amiconnectd.exe" "Amiconnect" ENABLE
```

— будет выведено предупреждение об устаревшем контексте; сравнить список правил
(`netsh advfirewall firewall show rule name=all`) до и после.

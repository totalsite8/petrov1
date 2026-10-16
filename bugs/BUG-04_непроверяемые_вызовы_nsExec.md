# BUG-04. 22 из 27 внешних команд выполняются без проверки результата

* **Важность:** средняя (установка «успешна», хотя часть шагов могла не выполниться;
  затрудняет диагностику)
* **Компонент:** установщик и деинсталлятор, все вызовы `nsExec::ExecToLog`
* **Инструкции:** см. таблицу

## Суть

Все внешние команды (`certutil`, `sc`, `net`, `taskkill`, `netsh`, `copy`, `ADrvInst.exe`,
`powershell`) выполняются плагином `nsExec::ExecToLog`, который **кладёт код возврата
процесса на стек скрипта**. Если результат не снять (`Pop`) и не проверить, то:

1. сбой команды остаётся незамеченным — установщик рапортует об успехе;
2. на стеке накапливаются неиспользуемые значения (разбалансировка стека скрипта:
   любой последующий `Pop`/`Exch` получает «чужие» данные).

Проверено автоматически по декомпиляции: из 27 вызовов `ExecToLog` в установщике
`Pop` есть только у 5, в деинсталляторе — у 4 из 9.

### Установщик — вызовы без проверки (22)

| Инстр. | Команда |
|---|---|
| 755 | `certutil -addstore "Root" …AmiCert_r1.cer` |
| 763 | `certutil -addstore "CA" …AmiCert_r2.cer` |
| 771 | `certutil -addstore "CA" …AmiCert_r3.cer` |
| 779 | `certutil -addstore "TrustedPublisher" …AmiCert_o1.cer` |
| 787 | `certutil -addstore "TrustedPublisher" …AmiCert_o2.cer` |
| 855 | `sc failure amiconnectd reset= 0 actions= ""` |
| 862 | `net stop amiconnectd` |
| 869 | `taskkill /f /t /im amiconnect.exe` |
| 1104 | `netsh firewall delete allowedprogram "$1\amiconnectd.exe"` |
| 1168 | `ADrvInst.exe /u …\AmiconnectFlt.inf` |
| 1176 | `ADrvInst.exe /do …\AmiconnectFlt.inf` |
| 1183 | `ADrvInst.exe /o …\AmiconnectFlt.inf` |
| 1205 | `copy /y "$INSTDIR\Drivers\AmiNdisFlt\AmiconnectFlt.sys" …` (см. BUG-02) |
| 1392 | `sc failure amiconnectd reset= 0 actions= ""` |
| 1399 | `net stop amiconnectd` |
| 1406 | `sc delete amiconnectd` |
| 1490 | `sc create amiconnectd start= auto displayname= "AMICON Amiconnect Service" …` |
| 1497 | `sc description amiconnectd "Amicon Amiconnect service for Amicon FPSU-IP…"` |
| 1594 | `sc failure amiconnectd reset= 600 actions= restart/5000/restart/10000/restart/10000/""/0` |
| 1601 | `sc failureflag amiconnectd 1` |
| 1608 | `netsh firewall add allowedprogram "$INSTDIR\amiconnectd.exe" "Amiconnect" ENABLE` |
| 2123 | `net start amiconnectd` |

### Деинсталлятор — вызовы без проверки (5)

`90` — `sc failure amiconnectd reset= 0 actions= ""`, `97` — `net stop amiconnectd`,
`104` — `taskkill /f /t /im amiconnect.exe`, `136` — `ADrvInst.exe /do …`,
`156` — `netsh firewall delete allowedprogram …`.

## Отдельно: проверка устаревшего значения (деинсталлятор, инструкции 115–138)

Самая показательная иллюстрация проблемы — удаление драйвера в деинсталляторе:

```
115  Pop  $0                     ; код возврата sc delete
116  DeleteRegKey HKLM "System\CurrentControlSet\Services\amiconnectd"
117  IntCmp $0 0 label_119 0 0   ; проверяем результат sc delete — корректно
118  IntOp $Var53 1 + 0          ; код выхода деинсталлятора = 1
119  File "AmiconnectFlt.inf"
...
134  Push "$INSTDIR\ADrvInst.exe" /do "$INSTDIR\Drivers\AmiconnectFlt\AmiconnectFlt.inf"
136  CallInstDLL/Plugin "$PLUGINSDIR\nsExec.dll" (func="ExecToLog")
137  IntCmp $0 0 label_139 0 0   ; ← проверяем… тот же $0, который остался от sc delete!
138  IntOp $Var53 1 + 0
```

Строка 137 не может отличить успех от неудачи `ADrvInst /do`: значение `$0`
не обновлялось с инструкции 115. Если `sc delete` завершился успешно, то любая
ошибка удаления драйвера будет считаться нормой (и `$Var53` — код возврата
деинсталлятора — не будет выставлен).

## Что должно быть

Для каждой внешней команды:

```nsis
nsExec::ExecToLog '"…команда…"'
Pop $0
StrCmp $0 "0" +3 0
  DetailPrint "Ошибка: … (код $0)"
  StrCpy $Var53 1          ; или MessageBox / SetErrors
```

Дополнительно полезно логировать сам вывод (сейчас `ExecToLog` пишет в окно
деталей, которое пользователь обычно не читает, и в `Install.log`).

## Как проверялось

Автоматический обход листинга (`../decompiled/functions.txt`,
`../decompiled_uninstaller/functions.txt`): для каждой инструкции `EW_REGISTERDLL`
с `func="ExecToLog"` проверялось наличие `Pop` в следующих 12 инструкциях.

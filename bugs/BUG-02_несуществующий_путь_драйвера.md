# BUG-02. Опечатка в пути к драйверу: `AmiNdisFlt` вместо `AmiconnectFlt`

* **Важность:** высокая (не выполняется запланированное копирование драйвера «на всякий
  случай», ошибка никак не диагностируется, установка считается успешной)
* **Компонент:** скрипт установщика, секция 0 («Amiconnect»), установка NDIS-фильтра
* **Инструкции:** 1131–1137 (распаковка драйвера), 1203–1206 (копирование)

## Суть

Драйвер распаковывается в каталог `$INSTDIR\Drivers\AmiconnectFlt`:

```
1131  RMDir  /r "$INSTDIR\Drivers\AmiconnectFlt"
1132  Sleep  2000
1133  SetOutPath "$INSTDIR\Drivers\AmiconnectFlt"      ; ← каталог AmiconnectFlt
1134  File "AmiconnectFlt.inf"   ; data +0x2BDFF size=3126
1135  File "amiconnectflt.cat"   ; data +0x2CA3D size=11332
1136  File "AmiconnectFlt.sys"   ; data +0x2F689 size=228080
1137  File "ADrvInst.exe"        ; data +0x67181 size=100168
```

а «страховочная» команда копирования драйвера в системный каталог берёт файл
из **несуществующего** каталога `AmiNdisFlt`:

```
1203  Push "copy /y $\"$INSTDIR\Drivers\AmiNdisFlt\AmiconnectFlt.sys$\" $\"$Var51\SYSTEM32\DRIVERS$\""
1204  Push "/TIMEOUT=30000"
1205  CallInstDLL/Plugin "$PLUGINSDIR\nsExec.dll" (func="ExecToLog")
1206  SetFlag bit=2 value=0                              ; результат не проверяется
```

Строка `AmiNdisFlt` встречается во всём скрипте **ровно один раз** — только здесь
(проверено поиском по `../decompiled/strings.txt`, строка № 18787; каталога с таким
именем установщик не создаёт никогда, файлов в него не кладёт).

## Последствия

1. `copy /y` завершается с ошибкой (`The system cannot find the path specified`),
   но её никто не проверяет: `nsExec::ExecToLog` пишет вывод в журнал и кладёт код
   возврата на стек, `Pop` не делается, ветвления по результату нет.
2. Резервный путь установки драйвера (прямая подмена файла в
   `%WINDIR%\SYSTEM32\DRIVERS`) фактически отсутствует: если `ADrvInst.exe` не смог
   поставить драйвер, установщик этого не заметит и продолжит работу, а пользователь
   получит неработающий VPN-клиент.
3. Ошибка вводит в заблуждение разработчика: код выглядит как «есть подстраховка».

## Что должно быть

```nsis
Push "copy /y $\"$INSTDIR\Drivers\AmiconnectFlt\AmiconnectFlt.sys$\" $\"$Var51\SYSTEM32\DRIVERS$\""
```

и проверка результата:

```nsis
nsExec::ExecToLog '"copy /y ..."'
Pop $0
StrCmp $0 "0" +2 0
  MessageBox MB_ICONEXCLAMATION "Не удалось скопировать драйвер AmiconnectFlt.sys"
```

## Как воспроизвести статически

```bash
grep -n "AmiNdisFlt" decompiled/*.txt          # единственное вхождение — строка 1203
grep -n "SetOutPath \"\$INSTDIR\\\\Drivers" decompiled/functions.txt   # 1133 → AmiconnectFlt
```

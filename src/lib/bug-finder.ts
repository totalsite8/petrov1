// PE Bug Finder — автоматический поиск реальных багов в PE файлах

import { PEResult } from './pe-parser';

export type BugSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface BugReport {
  id: string;
  severity: BugSeverity;
  category: string;
  title: string;
  description: string;
  details: string;
  offset?: string;
  recommendation?: string;
}

export function findBugs(result: PEResult): BugReport[] {
  const bugs: BugReport[] = [];
  let bugId = 0;
  const nextId = () => `BUG-${String(++bugId).padStart(4, '0')}`;

  // === 1. Проверка DOS Header ===
  if (result.dosHeader.e_magic !== 'MZ') {
    bugs.push({
      id: nextId(),
      severity: 'critical',
      category: 'DOS Header',
      title: 'Неверная MZ сигнатура',
      description: 'Файл не начинается с сигнатуры MZ (0x4D5A)',
      details: `Найдено: "${result.dosHeader.e_magic}". Это не валидный PE файл.`,
      recommendation: 'Файл повреждён или не является PE файлом.',
    });
  }

  // === 2. Проверка PE Signature ===
  if (result.peHeader.signature !== 'PE\0\0') {
    bugs.push({
      id: nextId(),
      severity: 'critical',
      category: 'PE Header',
      title: 'Неверная PE сигнатура',
      description: 'PE подпись не равна "PE\\0\\0" (0x00004550)',
      details: `Найдено: "${result.peHeader.signature}"`,
      recommendation: 'Файл повреждён. Возможно, это не Windows PE файл.',
    });
  }

  // === 3. Проверка Machine Type ===
  const validMachines = [0x14c, 0x8664, 0x1c0, 0x1c4, 0xaa64, 0x200];
  const machineRaw = result.rawBytes.length > 0 ?
    new DataView(result.rawBytes.buffer).getUint16(result.dosHeader.e_lfanew + 4, true) : 0;
  if (!validMachines.includes(machineRaw) && machineRaw !== 0) {
    bugs.push({
      id: nextId(),
      severity: 'high',
      category: 'PE Header',
      title: 'Неизвестный тип архитектуры',
      description: 'Значение Machine не соответствует известным архитектурам',
      details: `Machine = 0x${machineRaw.toString(16)} (${result.peHeader.machine})`,
      recommendation: 'Файл может быть для нестандартной платформы или повреждён.',
    });
  }

  // === 4. Проверка Timestamp ===
  if (result.peHeader.timeDateStamp > 0) {
    const date = new Date(result.peHeader.timeDateStamp * 1000);
    const now = new Date();
    const year = date.getFullYear();

    if (year < 1990 || year > now.getFullYear() + 1) {
      bugs.push({
        id: nextId(),
        severity: 'medium',
        category: 'PE Header',
        title: 'Аномальная дата компиляции',
        description: 'Дата компиляции файла выходит за разумные пределы',
        details: `Timestamp: ${result.peHeader.timeDateStamp} → ${date.toISOString()} (год ${year})`,
        offset: `0x${(result.dosHeader.e_lfanew + 8).toString(16).toUpperCase()}`,
        recommendation: 'Возможно, timestamp был обнулён или подделан. Некоторые упаковщики/протекторы сбрасывают timestamp.',
      });
    }

    if (result.peHeader.timeDateStamp === 0 || result.peHeader.timeDateStamp === 0xFFFFFFFF) {
      bugs.push({
        id: nextId(),
        severity: 'low',
        category: 'PE Header',
        title: 'Timestamp обнулён или максимален',
        description: 'Время компиляции установлено в 0 или 0xFFFFFFFF',
        details: `Value: 0x${result.peHeader.timeDateStamp.toString(16).toUpperCase()}`,
        recommendation: 'Обычно это делается упаковщиками или при повторной сборке.',
      });
    }
  }

  // === 5. Проверка количества секций ===
  if (result.peHeader.numberOfSections === 0) {
    bugs.push({
      id: nextId(),
      severity: 'critical',
      category: 'Sections',
      title: 'Нет секций в PE файле',
      description: 'Количество секций равно 0 — файл не может выполняться',
      details: 'NumberOfSections = 0',
      recommendation: 'Файл повреждён или является заглушкой.',
    });
  }

  if (result.peHeader.numberOfSections > 96) {
    bugs.push({
      id: nextId(),
      severity: 'high',
      category: 'Sections',
      title: 'Аномально большое количество секций',
      description: `Обнаружено ${result.peHeader.numberOfSections} секций (норма: 3-10)`,
      details: 'Большое количество секций может указывать на упаковщик, вирус или повреждение.',
      recommendation: 'Проверьте файл антивирусом. Упаковщики (UPX, Themida) часто создают множество секций.',
    });
  }

  // === 6. Проверка секций ===
  const sectionNames = new Set<string>();
  for (const section of result.sections) {
    // Дубликаты имён секций
    if (sectionNames.has(section.name)) {
      bugs.push({
        id: nextId(),
        severity: 'high',
        category: 'Sections',
        title: `Дублирование имени секции: "${section.name}"`,
        description: 'Обнаружены секции с одинаковыми именами',
        details: `Секция "${section.name}" встречается более одного раза. Это нестандартно и может быть признаком malware.`,
        recommendation: 'Проверьте файл антивирусом.',
      });
    }
    sectionNames.add(section.name);

    // Writable + Executable секция
    const isWritable = section.characteristics.includes('MEM_WRITE');
    const isExecutable = section.characteristics.includes('MEM_EXECUTE') || section.characteristics.includes('CODE');

    if (isWritable && isExecutable) {
      bugs.push({
        id: nextId(),
        severity: 'high',
        category: 'Security',
        title: `Секция "${section.name}" одновременно Writable + Executable`,
        description: 'Секция доступна и для записи, и для выполнения — серьёзная уязвимость',
        details: `Flags: ${section.characteristics.filter(c => c.includes('WRITE') || c.includes('EXECUTE') || c.includes('CODE')).join(', ')}`,
        recommendation: 'W^X violation. Это позволяет эксплуатировать buffer overflow для выполнения произвольного кода. Рекомендуется отключить запись или выполнение.',
      });
    }

    // Raw data больше virtual size (аномалия)
    if (section.sizeOfRawData > 0 && section.virtualSize > 0) {
      const ratio = section.sizeOfRawData / section.virtualSize;
      if (ratio > 10) {
        bugs.push({
          id: nextId(),
          severity: 'medium',
          category: 'Sections',
          title: `Аномальное соотношение Raw/Virtual для "${section.name}"`,
          description: `Raw data (${section.sizeOfRawData}) значительно больше Virtual Size (${section.virtualSize})`,
          details: `Ratio: ${ratio.toFixed(1)}x. Это может указывать на оверлей или упаковку.`,
          recommendation: 'Проверьте, не содержит ли секция скрытые данные.',
        });
      }
    }

    // Нулевой VirtualSize при ненулевом RawData
    if (section.virtualSize === 0 && section.sizeOfRawData > 0) {
      bugs.push({
        id: nextId(),
        severity: 'medium',
        category: 'Sections',
        title: `VirtualSize = 0 при ненулевом RawData для "${section.name}"`,
        description: 'Секция имеет данные в файле, но нулевой виртуальный размер',
        details: `VirtualSize = 0, SizeOfRawData = ${section.sizeOfRawData}`,
        recommendation: 'Некоторые линкеры используют это для последней секции. Windows загрузит данные, но это нестандартно.',
      });
    }

    // Переполнение: RawData выходит за пределы файла
    if (section.pointerToRawData + section.sizeOfRawData > result.fileSize) {
      bugs.push({
        id: nextId(),
        severity: 'critical',
        category: 'Sections',
        title: `Секция "${section.name}" выходит за пределы файла`,
        description: 'Raw data секции указывает за конец файла',
        details: `PointerToRawData (0x${section.pointerToRawData.toString(16)}) + SizeOfRawData (0x${section.sizeOfRawData.toString(16)}) = 0x${(section.pointerToRawData + section.sizeOfRawData).toString(16)} > FileSize (0x${result.fileSize.toString(16)})`,
        recommendation: 'Файл обрезан или повреждён. Загрузка может завершиться ошибкой.',
      });
    }

    // Подозрительные имена секций (признаки упаковщиков)
    const suspiciousNames = ['.aspack', '.adata', '.nsp0', '.nsp1', '.pec', '.pediy', '.tsuarch', '.tsustub', '.sforce', '.winup', '.MaskPE', '.packed', '.packed'];
    if (suspiciousNames.includes(section.name.toLowerCase())) {
      bugs.push({
        id: nextId(),
        severity: 'medium',
        category: 'Packer Detection',
        title: `Обнаружена секция упаковщика: "${section.name}"`,
        description: 'Имя секции характерно для упаковщиков/протекторов',
        details: `Секция "${section.name}" ассоциируется с упаковщиками. Реальный код зашифрован/сжат.`,
        recommendation: 'Для полного анализа необходимо распаковать файл (UPX -d, или специализированный unpacker).',
      });
    }
  }

  // Проверка стандартных секций
  const expectedSections = ['.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc'];
  const hasCodeSection = result.sections.some(s => s.name === '.text' || s.characteristics.includes('CODE'));
  if (!hasCodeSection && result.peHeader.numberOfSections > 0) {
    bugs.push({
      id: nextId(),
      severity: 'medium',
      category: 'Sections',
      title: 'Отсутствует кодовая секция (.text)',
      description: 'Не найдена секция с исполняемым кодом',
      details: `Имена секций: ${result.sections.map(s => s.name).join(', ')}`,
      recommendation: 'EXE файл без кодовой секции не может выполняться. Возможно, это DLL или повреждённый файл.',
    });
  }

  // === 7. Проверка EntryPoint ===
  if (result.optionalHeader) {
    const ep = result.optionalHeader.addressOfEntryPoint;
    if (ep === 0) {
      bugs.push({
        id: nextId(),
        severity: 'medium',
        category: 'Entry Point',
        title: 'EntryPoint = 0',
        description: 'Адрес точки входа равен нулю',
        details: 'AddressOfEntryPoint = 0x00000000',
        recommendation: 'Для EXE это критично — файл не сможет запуститься. Для DLL допустимо.',
      });
    }

    // EntryPoint вне секций
    const epInSection = result.sections.some(s =>
      ep >= s.virtualAddress && ep < s.virtualAddress + s.virtualSize
    );
    if (ep > 0 && !epInSection) {
      bugs.push({
        id: nextId(),
        severity: 'high',
        category: 'Entry Point',
        title: 'EntryPoint указывает за пределы всех секций',
        description: `АдресEntryPoint (0x${ep.toString(16)}) не попадает ни в одну секцию`,
        details: 'Это может быть признаком malware или повреждённого файла.',
        offset: `0x${ep.toString(16).padStart(8, '0')}`,
        recommendation: 'Проверьте файл антивирусом. Некоторые вирусы выносят EntryPoint в оверлей.',
      });
    }

    // === 8. Проверка ImageBase ===
    const defaultBase32 = 0x00400000;
    const defaultBase64 = 0x0000000140000000;
    const imageBase = result.optionalHeader.imageBase;
    const is64 = result.optionalHeader.magic.includes('PE32+');
    const expectedBase = is64 ? defaultBase64 : defaultBase32;

    if (imageBase !== expectedBase && imageBase !== 0) {
      bugs.push({
        id: nextId(),
        severity: 'low',
        category: 'Image Base',
        title: 'Нестандартный ImageBase',
        description: `ImageBase = 0x${imageBase.toString(16)} (ожидалось 0x${expectedBase.toString(16)})`,
        details: 'Нестандартный базовый адрес может вызывать конфликты при загрузке.',
        recommendation: 'Обычно это не критично, но может указывать на ASLR или модификацию.',
      });
    }

    // === 9. Проверка ASLR/DEP ===
    const hasASLR = result.optionalHeader.dllCharacteristics.includes('DYNAMIC_BASE (ASLR)');
    const hasDEP = result.optionalHeader.dllCharacteristics.includes('NX_COMPAT (DEP)');
    const hasHighEntropyVA = result.optionalHeader.dllCharacteristics.includes('HIGH_ENTROPY_VA');
    const hasCFG = result.optionalHeader.dllCharacteristics.includes('GUARD_CF');

    if (!hasASLR) {
      bugs.push({
        id: nextId(),
        severity: 'high',
        category: 'Security',
        title: 'Отсутствует ASLR (Address Space Layout Randomization)',
        description: 'Файл не поддерживает рандомизацию адресного пространства',
        details: 'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE не установлен. Все загрузки будут по одному адресу.',
        recommendation: 'Включите /DYNAMIC_BASE в линкере. Без ASLR файл уязвим к ROP-атакам.',
      });
    }

    if (!hasDEP) {
      bugs.push({
        id: nextId(),
        severity: 'high',
        category: 'Security',
        title: 'Отсутствует DEP (Data Execution Prevention)',
        description: 'Файл не поддерживает предотвращение выполнения данных',
        details: 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT не установлен. Данные могут быть выполнены как код.',
        recommendation: 'Включите /NXCOMPAT в линкере. Без DEP buffer overflow может привести к выполнению вредоносного кода.',
      });
    }

    if (is64 && !hasHighEntropyVA) {
      bugs.push({
        id: nextId(),
        severity: 'medium',
        category: 'Security',
        title: 'Отсутствует High Entropy VA для 64-bit',
        description: '64-bit файл не поддерживает высокоэнтропийную рандомизацию',
        details: 'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA не установлен. Снижена эффективность ASLR.',
        recommendation: 'Включите /HIGHENTROPYVA для 64-bit сборок.',
      });
    }

    if (!hasCFG) {
      bugs.push({
        id: nextId(),
        severity: 'medium',
        category: 'Security',
        title: 'Отсутствует Control Flow Guard (CFG)',
        description: 'Файл не использует защиту от атак на поток управления',
        details: 'IMAGE_DLLCHARACTERISTICS_GUARD_CF не установлен.',
        recommendation: 'Включите /GUARD:CF в линкере для защиты от hijacking указателей функций.',
      });
    }

    // === 10. Проверка Checksum ===
    if (result.optionalHeader.checksum === 0) {
      bugs.push({
        id: nextId(),
        severity: 'low',
        category: 'Integrity',
        title: 'PE Checksum не вычислен',
        description: 'Поле Checksum равно нулю',
        details: 'Ожидалось вычисленное значение checksum. Нулевое checksum — признак некорректной сборки.',
        recommendation: 'Вычислите checksum при сборке. Драйверы ядра требуют валидный checksum.',
      });
    }

    // === 11. Проверка Subsystem ===
    const isDLL = result.peHeader.characteristics.includes('DLL');
    if (result.optionalHeader.subsystem === 'UNKNOWN' && !isDLL) {
      bugs.push({
        id: nextId(),
        severity: 'high',
        category: 'PE Header',
        title: 'Неизвестный Subsystem',
        description: 'Subsystem = UNKNOWN для не-DLL файла',
        details: 'Windows не сможет определить, как запустить этот файл.',
        recommendation: 'Установите правильный subsystem: WINDOWS_GUI или WINDOWS_CUI.',
      });
    }

    // === 12. Проверка Section Alignment ===
    const sa = result.optionalHeader.sectionAlignment;
    const fa = result.optionalHeader.fileAlignment;
    if (sa < fa) {
      bugs.push({
        id: nextId(),
        severity: 'high',
        category: 'Alignment',
        title: 'SectionAlignment < FileAlignment',
        description: `SectionAlignment (${sa}) < FileAlignment (${fa})`,
        details: 'Это нарушает спецификацию PE и может вызвать проблемы при загрузке.',
        recommendation: 'SectionAlignment должен быть >= FileAlignment.',
      });
    }

    // === 13. Проверка Data Directories ===
    for (const dd of result.optionalHeader.dataDirectories) {
      if (dd.virtualAddress > 0 && dd.size === 0) {
        bugs.push({
          id: nextId(),
          severity: 'medium',
          category: 'Data Directory',
          title: `Data Directory "${dd.name}": RVA задан, но Size = 0`,
          description: `Виртуальный адрес 0x${dd.virtualAddress.toString(16)} при нулевом размере`,
          details: 'Это может привести к проблемам при загрузке или быть признаком повреждения.',
          recommendation: 'Проверьте корректность PE файла.',
        });
      }
    }
  }

  // === 14. Проверка импортов на подозрительные функции ===
  const suspiciousFunctions: Record<string, string> = {
    'VirtualAlloc': 'Выделение памяти — часто используется malware для распаковки',
    'VirtualAllocEx': 'Выделение памяти в другом процессе — инъекция кода',
    'VirtualProtect': 'Изменение прав памяти — часто для распаковки кода',
    'WriteProcessMemory': 'Запись в другой процесс — инъекция кода',
    'CreateRemoteThread': 'Создание потока в другом процессе — DLL injection',
    'LoadLibraryA': 'Динамическая загрузка DLL — обход static import analysis',
    'LoadLibraryW': 'Динамическая загрузка DLL (Unicode)',
    'GetProcAddress': 'Получение адреса функции — динамический ресолвинг',
    'IsDebuggerPresent': 'Антиотладочная проверка',
    'CheckRemoteDebuggerPresent': 'Антиотладочная проверка удалённого дебаггера',
    'NtQueryInformationProcess': 'Антиотладочная проверка через NT API',
    'OutputDebugString': 'Антиотладочная техника',
    'URLDownloadToFile': 'Загрузка файлов из интернета',
    'InternetOpen': 'Инициализация WinINet — сетевые операции',
    'InternetOpenUrl': 'Открытие URL — сетевые операции',
    'WinHttpOpen': 'Инициализация WinHTTP — сетевые операции',
    'WSAStartup': 'Инициализация Winsock — сетевые операции',
    'RegSetValueEx': 'Запись в реестр — persistence',
    'RegCreateKeyEx': 'Создание ключей реестра',
    'CreateService': 'Создание Windows сервиса — persistence',
    'ShellExecute': 'Запуск внешних программ',
    'ShellExecuteEx': 'Запуск внешних программ (расширенный)',
    'CryptEncrypt': 'Шифрование данных',
    'CryptDecrypt': 'Дешифрование данных',
    'AdjustTokenPrivileges': 'Изменение привилегий — эскалация',
    'OpenProcess': 'Открытие процесса — потенциальная инъекция',
    'SetWindowsHookEx': 'Установка хуков — кейлоггинг',
    'GetAsyncKeyState': 'Чтение состояния клавиш — кейлоггинг',
    'GetKeyState': 'Чтение состояния клавиш',
    'MapVirtualKey': 'Маппинг виртуальных клавиш',
    'CreateFileMapping': 'Создание mapped файла — shared memory',
    'MapViewOfFile': 'Отображение файла в память',
  };

  const foundSuspicious: { dll: string; func: string; reason: string }[] = [];
  for (const imp of result.imports) {
    for (const fn of imp.functions) {
      const cleanName = fn.replace(/@.*$/, '').replace(/\d+$/, '');
      if (suspiciousFunctions[cleanName]) {
        foundSuspicious.push({
          dll: imp.dllName,
          func: fn,
          reason: suspiciousFunctions[cleanName],
        });
      }
    }
  }

  if (foundSuspicious.length > 0) {
    const grouped = new Map<string, typeof foundSuspicious>();
    for (const s of foundSuspicious) {
      const key = s.reason;
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key)!.push(s);
    }

    for (const [reason, items] of grouped) {
      bugs.push({
        id: nextId(),
        severity: 'medium',
        category: 'Suspicious Imports',
        title: `Подозрительные импорты: ${reason}`,
        description: `Найдено ${items.length} функций: ${items.map(i => i.func).join(', ')}`,
        details: items.map(i => `• ${i.dll}!${i.func} — ${i.reason}`).join('\n'),
        recommendation: 'Эти функции часто используются malware. Контекст использования определяет, является ли это реальным багом.',
      });
    }
  }

  // === 15. Проверка строк на подозрительные паттерны ===
  const suspiciousPatterns: [RegExp, string, BugSeverity][] = [
    [/https?:\/\/\d+\.\d+\.\d+\.\d+/i, 'URL с IP-адресом вместо домена', 'medium'],
    [/\.onion/i, 'Ссылка на .onion (Tor hidden service)', 'high'],
    [/password|passwd|pwd/i, 'Строка с "password" — возможное хранение паролей', 'low'],
    [/cmd\.exe|powershell/i, 'Ссылка на cmd/powershell — выполнение команд', 'medium'],
    [/reg add|reg delete|regedit/i, 'Операции с реестром через CLI', 'medium'],
    [/\\\.\\[a-z]/i, 'Путь к устройству (\\\\.\\) — прямой доступ к устройствам', 'medium'],
    [/keylog|screenshot|capture/i, 'Ключевые слова кейлоггинга/скриншотов', 'high'],
    [/inject|hook|patch/i, 'Ключевые слова инъекции/патчинга', 'medium'],
    [/crypt|encrypt|decrypt|cipher/i, 'Криптографические операции', 'low'],
    [/mutex|single.?instance/i, 'Mutex — контроль единственного экземпляра', 'info'],
    [/\.dll|\.exe|\.sys|\.bat|\.vbs|\.ps1/i, 'Ссылки на исполняемые файлы', 'info'],
  ];

  const foundPatterns: { pattern: string; severity: BugSeverity; matches: string[] }[] = [];
  for (const [regex, desc, severity] of suspiciousPatterns) {
    const matches: string[] = [];
    for (const str of result.strings) {
      if (regex.test(str.value)) {
        matches.push(str.value.substring(0, 100));
        if (matches.length >= 5) break;
      }
    }
    if (matches.length > 0) {
      foundPatterns.push({ pattern: desc, severity, matches });
    }
  }

  for (const fp of foundPatterns) {
    bugs.push({
      id: nextId(),
      severity: fp.severity,
      category: 'String Analysis',
      title: fp.pattern,
      description: `Найдено ${fp.matches.length} совпадений`,
      details: fp.matches.map(m => `• "${m}"`).join('\n'),
      recommendation: 'Проанализируйте контекст использования этих строк.',
    });
  }

  // === 16. Проверка оверлея ===
  if (result.sections.length > 0) {
    const lastSection = result.sections.reduce((a, b) =>
      (a.pointerToRawData + a.sizeOfRawData) > (b.pointerToRawData + b.sizeOfRawData) ? a : b
    );
    const overlayStart = lastSection.pointerToRawData + lastSection.sizeOfRawData;
    const overlaySize = result.fileSize - overlayStart;

    if (overlaySize > 0) {
      bugs.push({
        id: nextId(),
        severity: 'medium',
        category: 'Overlay',
        title: `Обнаружен оверлей: ${formatBytes(overlaySize)}`,
        description: `После последней секции "${lastSection.name}" есть ${formatBytes(overlaySize)} дополнительных данных`,
        details: `Overlay начинается с offset 0x${overlayStart.toString(16).toUpperCase()} (размер: ${overlaySize} байт). Оверлей часто используется упаковщиками, инсталлерами или malware для хранения зашифрованных данных.`,
        recommendation: 'Проанализируйте содержимое оверлея. Для UPX используйте "upx -d" для распаковки.',
      });
    }
  }

  // === 17. Проверка переполнения имён секций ===
  for (const section of result.sections) {
    if (section.name.length === 8) {
      // Имя секции ровно 8 символов — возможно, оно обрезано
      bugs.push({
        id: nextId(),
        severity: 'info',
        category: 'Sections',
        title: `Имя секции "${section.name}" максимально (8 байт)`,
        description: 'Имя секции занимает все 8 доступных байт — возможно, оно обрезано',
        details: 'PE формат ограничивает имена секций 8 байтами. Если реальное имя длиннее, оно будет обрезано.',
        recommendation: 'Это informational. Обычно не является проблемой.',
      });
    }
  }

  // === 18. Проверка: нет .rsrc секции ===
  const hasRsrc = result.sections.some(s => s.name === '.rsrc');
  const hasRsrcDir = result.optionalHeader?.dataDirectories.some(d => d.name === 'RESOURCE_TABLE' && d.virtualAddress > 0);
  if (!hasRsrc && !hasRsrcDir && !result.peHeader.characteristics.includes('DLL')) {
    bugs.push({
      id: nextId(),
      severity: 'info',
      category: 'Resources',
      title: 'Отсутствует секция ресурсов (.rsrc)',
      description: 'EXE файл не содержит ресурсов (иконки, диалоги, строки)',
      details: 'Это нормально для консольных утилит, но необычно для GUI-приложений.',
      recommendation: 'Проверьте, не были ли ресурсы удалены или перемещены.',
    });
  }

  // === 19. Проверка: нет .reloc секции при ASLR ===
  const hasReloc = result.sections.some(s => s.name === '.reloc');
  const hasRelocDir = result.optionalHeader?.dataDirectories.some(d => d.name === 'BASE_RELOCATION_TABLE' && d.virtualAddress > 0);
  if (result.optionalHeader?.dllCharacteristics.includes('DYNAMIC_BASE (ASLR)') && !hasReloc && !hasRelocDir) {
    bugs.push({
      id: nextId(),
        severity: 'medium',
        category: 'Relocations',
        title: 'ASLR включён, но таблица релокаций отсутствует',
        description: 'Файл поддерживает ASLR, но не содержит таблицу базовых релокаций',
        details: 'Без релокаций ASLR не может переместить образ в памяти, что делает его бесполезным.',
        recommendation: 'Добавьте таблицу релокаций при сборке или отключите ASLR.',
      });
  }

  // === 20. Проверка: импорт из нестандартных DLL ===
  const standardDLLs = ['kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll',
    'ole32.dll', 'oleaut32.dll', 'msvcrt.dll', 'ntdll.dll', 'ws2_32.dll', 'wininet.dll',
    'comctl32.dll', 'comdlg32.dll', 'shlwapi.dll', 'version.dll', 'winmm.dll', 'crypt32.dll',
    'msvcp140.dll', 'vcruntime140.dll', 'ucrtbase.dll', 'api-ms-win-', 'msvcr', 'msvcp',
    'iphlpapi.dll', 'psapi.dll', 'setupapi.dll', 'dbghelp.dll', 'winspool.drv',
    'bcrypt.dll', 'secur32.dll', 'sspicli.dll', 'winhttp.dll', 'urlmon.dll',
    'msxml', 'mscoree.dll', 'clr.dll', 'msvfw32.dll', 'avicap32.dll', 'd3d', 'dinput',
    'dxgi.dll', 'd3d9.dll', 'd3d11.dll', 'opengl32.dll', 'glu32.dll'];

  for (const imp of result.imports) {
    const dllLower = imp.dllName.toLowerCase();
    const isStandard = standardDLLs.some(s => dllLower.startsWith(s));
    if (!isStandard && imp.dllName.length > 0) {
      bugs.push({
        id: nextId(),
        severity: 'info',
        category: 'Imports',
        title: `Нестандартная DLL в импортах: ${imp.dllName}`,
        description: `Импортируется "${imp.dllName}" — не из стандартного набора Windows`,
        details: `Функции: ${imp.functions.slice(0, 10).join(', ')}${imp.functions.length > 10 ? ` (+${imp.functions.length - 10} ещё)` : ''}`,
        recommendation: 'Это может быть сторонняя библиотека. Убедитесь, что DLL легитимна.',
      });
    }
  }

  // === 21. Проверка: файл слишком мал для EXE ===
  if (result.fileSize < 512 && !result.peHeader.characteristics.includes('DLL')) {
    bugs.push({
      id: nextId(),
      severity: 'medium',
      category: 'File Size',
      title: 'Подозрительно малый размер файла',
      description: `Файл весит всего ${formatBytes(result.fileSize)}`,
      details: 'Нормальные EXE файлы обычно больше 1KB. Очень маленькие файлы могут быть заглушками или malware.',
      recommendation: 'Проверьте содержимое файла.',
    });
  }

  // === 22. Проверка выравнивания секций ===
  if (result.optionalHeader) {
    const fa = result.optionalHeader.fileAlignment;
    for (const section of result.sections) {
      if (section.pointerToRawData % fa !== 0 && section.sizeOfRawData > 0) {
        bugs.push({
          id: nextId(),
          severity: 'high',
          category: 'Alignment',
          title: `Секция "${section.name}" не выровнена по FileAlignment`,
          description: `PointerToRawData (0x${section.pointerToRawData.toString(16)}) не кратна FileAlignment (0x${fa.toString(16)})`,
          details: 'Это нарушает спецификацию PE и может вызвать проблемы при загрузке.',
          recommendation: 'Исправьте выравнивание при сборке.',
        });
      }
    }
  }

  // === 23. Проверка: нет DLL Characteristics при PE32+ ===
  if (result.optionalHeader?.magic.includes('PE32+') && result.optionalHeader.dllCharacteristics.length === 0) {
    bugs.push({
      id: nextId(),
      severity: 'high',
      category: 'Security',
      title: '64-bit файл без каких-либо security flags',
      description: 'Все DLL Characteristics сброшены — ни одна защита не включена',
      details: 'Современные 64-bit приложения должны иметь как минимум ASLR и DEP.',
      recommendation: 'Включите /DYNAMIC_BASE и /NXCOMPAT при сборке.',
    });
  }

  // Сортировка по severity
  const severityOrder: Record<BugSeverity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  bugs.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return bugs;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function generateBugReportText(result: PEResult, bugs: BugReport[]): string {
  const lines: string[] = [];
  const now = new Date().toISOString();

  lines.push('═'.repeat(70));
  lines.push('  EXE DECOMPILER — BUG REPORT');
  lines.push('═'.repeat(70));
  lines.push('');
  lines.push(`Файл:        ${result.fileName}`);
  lines.push(`Размер:      ${formatBytes(result.fileSize)}`);
  lines.push(`Архитектура: ${result.peHeader.machine}`);
  lines.push(`Секций:      ${result.peHeader.numberOfSections}`);
  lines.push(`Импортов:    ${result.imports.reduce((s, i) => s + i.functions.length, 0)} функций из ${result.imports.length} DLL`);
  lines.push(`Экспортов:   ${result.exports.length}`);
  lines.push(`Строк:       ${result.strings.length}`);
  lines.push(`Дата анализа: ${now}`);
  lines.push('');

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const b of bugs) counts[b.severity]++;

  lines.push('─'.repeat(70));
  lines.push('  СВОДКА');
  lines.push('─'.repeat(70));
  lines.push(`  Всего багов: ${bugs.length}`);
  lines.push(`  🔴 Critical: ${counts.critical}`);
  lines.push(`  🟠 High:     ${counts.high}`);
  lines.push(`  🟡 Medium:   ${counts.medium}`);
  lines.push(`  🔵 Low:      ${counts.low}`);
  lines.push(`  ⚪ Info:      ${counts.info}`);
  lines.push('');

  lines.push('─'.repeat(70));
  lines.push('  ДЕТАЛЬНЫЙ ОТЧЁТ');
  lines.push('─'.repeat(70));
  lines.push('');

  for (const bug of bugs) {
    const icon = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[bug.severity];
    lines.push(`[${bug.id}] ${icon} [${bug.severity.toUpperCase()}] ${bug.title}`);
    lines.push(`  Категория: ${bug.category}`);
    lines.push(`  Описание:  ${bug.description}`);
    if (bug.offset) lines.push(`  Смещение:  ${bug.offset}`);
    lines.push(`  Детали:`);
    for (const line of bug.details.split('\n')) {
      lines.push(`    ${line}`);
    }
    if (bug.recommendation) {
      lines.push(`  Рекомендация: ${bug.recommendation}`);
    }
    lines.push('');
  }

  lines.push('═'.repeat(70));
  lines.push('  END OF REPORT');
  lines.push('═'.repeat(70));

  return lines.join('\n');
}

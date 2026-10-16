import { useState, useCallback } from 'react';
import { parsePE, PEResult } from './lib/pe-parser';

type Tab = 'overview' | 'sections' | 'imports' | 'exports' | 'strings' | 'disasm' | 'hex';

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatTimestamp(ts: number): string {
  const date = new Date(ts * 1000);
  return date.toLocaleString('ru-RU');
}

function formatHex(n: number): string {
  return '0x' + n.toString(16).toUpperCase().padStart(8, '0');
}

export default function App() {
  const [result, setResult] = useState<PEResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [dragOver, setDragOver] = useState(false);

  const processFile = useCallback((file: File) => {
    setLoading(true);
    setError(null);
    setResult(null);

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const buffer = e.target?.result as ArrayBuffer;
        const parsed = parsePE(buffer, file.name);
        setResult(parsed);
        setActiveTab('overview');
      } catch (err: any) {
        setError(err.message || 'Ошибка при анализе файла');
      } finally {
        setLoading(false);
      }
    };
    reader.onerror = () => {
      setError('Ошибка чтения файла');
      setLoading(false);
    };
    reader.readAsArrayBuffer(file);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) processFile(file);
  }, [processFile]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) processFile(file);
  }, [processFile]);

  const tabs: { id: Tab; label: string; icon: string; count?: number }[] = [
    { id: 'overview', label: 'Обзор', icon: '📋' },
    { id: 'sections', label: 'Секции', icon: '📦', count: result?.sections.length },
    { id: 'imports', label: 'Импорты', icon: '📥', count: result?.imports.length },
    { id: 'exports', label: 'Экспорты', icon: '📤', count: result?.exports.length },
    { id: 'strings', label: 'Строки', icon: '🔤', count: result?.strings.length },
    { id: 'disasm', label: 'Дизассемблер', icon: '⚙️', count: result?.disassembly.length },
    { id: 'hex', label: 'HEX', icon: '🔢' },
  ];

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-mono">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center gap-4">
          <div className="text-3xl">🔬</div>
          <div>
            <h1 className="text-xl font-bold text-emerald-400">EXE Decompiler</h1>
            <p className="text-xs text-gray-500">PE Format Analyzer — анализ исполняемых файлов Windows</p>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Upload Area */}
        {!result && !loading && (
          <div
            className={`border-2 border-dashed rounded-xl p-16 text-center transition-all cursor-pointer
              ${dragOver ? 'border-emerald-400 bg-emerald-400/5' : 'border-gray-700 hover:border-gray-500'}`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => document.getElementById('file-input')?.click()}
          >
            <div className="text-6xl mb-4">📁</div>
            <h2 className="text-xl font-semibold mb-2">Перетащите EXE файл сюда</h2>
            <p className="text-gray-500 mb-4">или нажмите для выбора файла</p>
            <p className="text-xs text-gray-600">Поддерживаются: .exe, .dll, .sys, .ocx, .scr и другие PE файлы</p>
            <input
              id="file-input"
              type="file"
              className="hidden"
              accept=".exe,.dll,.sys,.ocx,.scr,.drv,.cpl,.ax,.efi,.node"
              onChange={handleFileInput}
            />
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="text-center py-20">
            <div className="inline-block animate-spin text-4xl mb-4">⚙️</div>
            <p className="text-gray-400">Анализ PE файла...</p>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="bg-red-900/30 border border-red-800 rounded-lg p-6 text-center">
            <div className="text-4xl mb-2">❌</div>
            <p className="text-red-400 font-semibold">Ошибка анализа</p>
            <p className="text-red-300 text-sm mt-2">{error}</p>
            <button
              onClick={() => { setError(null); setResult(null); }}
              className="mt-4 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded text-sm"
            >
              Попробовать снова
            </button>
          </div>
        )}

        {/* Results */}
        {result && (
          <div>
            {/* File info bar */}
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-6 flex items-center justify-between flex-wrap gap-4">
              <div className="flex items-center gap-3">
                <span className="text-2xl">📄</span>
                <div>
                  <p className="font-semibold text-emerald-400">{result.fileName}</p>
                  <p className="text-xs text-gray-500">{formatBytes(result.fileSize)} • {result.peHeader.machine}</p>
                </div>
              </div>
              <button
                onClick={() => { setResult(null); setError(null); }}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded text-sm flex items-center gap-2"
              >
                <span>📁</span> Загрузить другой файл
              </button>
            </div>

            {/* Tabs */}
            <div className="flex flex-wrap gap-1 mb-6 bg-gray-900 rounded-lg p-1 border border-gray-800">
              {tabs.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-4 py-2 rounded text-sm flex items-center gap-2 transition-all
                    ${activeTab === tab.id
                      ? 'bg-emerald-600 text-white'
                      : 'text-gray-400 hover:text-white hover:bg-gray-800'}`}
                >
                  <span>{tab.icon}</span>
                  <span>{tab.label}</span>
                  {tab.count !== undefined && (
                    <span className="text-xs bg-gray-700 px-1.5 py-0.5 rounded">
                      {tab.count}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
              {activeTab === 'overview' && <OverviewTab result={result} />}
              {activeTab === 'sections' && <SectionsTab result={result} />}
              {activeTab === 'imports' && <ImportsTab result={result} />}
              {activeTab === 'exports' && <ExportsTab result={result} />}
              {activeTab === 'strings' && <StringsTab result={result} />}
              {activeTab === 'disasm' && <DisasmTab result={result} />}
              {activeTab === 'hex' && <HexTab result={result} />}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function InfoRow({ label, value, highlight }: { label: string; value: string | number; highlight?: boolean }) {
  return (
    <div className="flex items-center justify-between py-2 px-4 border-b border-gray-800/50 hover:bg-gray-800/30">
      <span className="text-gray-500 text-sm">{label}</span>
      <span className={`text-sm font-medium ${highlight ? 'text-emerald-400' : 'text-gray-200'}`}>{value}</span>
    </div>
  );
}

function OverviewTab({ result }: { result: PEResult }) {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-emerald-400 mb-3 flex items-center gap-2">
          <span>📋</span> DOS Header
        </h3>
        <div className="bg-gray-950 rounded-lg border border-gray-800">
          <InfoRow label="Signature" value={result.dosHeader.e_magic} />
          <InfoRow label="PE Header Offset (e_lfanew)" value={formatHex(result.dosHeader.e_lfanew)} />
        </div>
      </div>

      <div>
        <h3 className="text-lg font-semibold text-emerald-400 mb-3 flex items-center gap-2">
          <span>🔧</span> PE/COFF Header
        </h3>
        <div className="bg-gray-950 rounded-lg border border-gray-800">
          <InfoRow label="Signature" value={result.peHeader.signature} highlight />
          <InfoRow label="Machine" value={result.peHeader.machine} highlight />
          <InfoRow label="Number of Sections" value={result.peHeader.numberOfSections} />
          <InfoRow label="Time Date Stamp" value={`${formatTimestamp(result.peHeader.timeDateStamp)} (${formatHex(result.peHeader.timeDateStamp)})`} />
          <InfoRow label="Optional Header Size" value={`${result.peHeader.optionalHeaderSize} bytes`} />
          <div className="py-2 px-4 border-b border-gray-800/50">
            <span className="text-gray-500 text-sm block mb-1">Characteristics</span>
            <div className="flex flex-wrap gap-1">
              {result.peHeader.characteristics.map(f => (
                <span key={f} className="text-xs bg-blue-900/40 text-blue-300 px-2 py-0.5 rounded">{f}</span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {result.optionalHeader && (
        <div>
          <h3 className="text-lg font-semibold text-emerald-400 mb-3 flex items-center gap-2">
            <span>⚡</span> Optional Header
          </h3>
          <div className="bg-gray-950 rounded-lg border border-gray-800">
            <InfoRow label="Format" value={result.optionalHeader.magic} highlight />
            <InfoRow label="Linker Version" value={`${result.optionalHeader.majorLinkerVersion}.${result.optionalHeader.minorLinkerVersion}`} />
            <InfoRow label="Entry Point" value={formatHex(result.optionalHeader.addressOfEntryPoint)} highlight />
            <InfoRow label="Image Base" value={formatHex(result.optionalHeader.imageBase)} highlight />
            <InfoRow label="Section Alignment" value={formatHex(result.optionalHeader.sectionAlignment)} />
            <InfoRow label="File Alignment" value={formatHex(result.optionalHeader.fileAlignment)} />
            <InfoRow label="Size of Image" value={formatBytes(result.optionalHeader.sizeOfImage)} />
            <InfoRow label="Size of Headers" value={formatBytes(result.optionalHeader.sizeOfHeaders)} />
            <InfoRow label="Subsystem" value={result.optionalHeader.subsystem} highlight />
            <InfoRow label="OS Version" value={`${result.optionalHeader.majorOSVersion}.${result.optionalHeader.minorOSVersion}`} />
            <InfoRow label="Checksum" value={formatHex(result.optionalHeader.checksum)} />
            <div className="py-2 px-4 border-b border-gray-800/50">
              <span className="text-gray-500 text-sm block mb-1">DLL Characteristics</span>
              <div className="flex flex-wrap gap-1">
                {result.optionalHeader.dllCharacteristics.map(f => (
                  <span key={f} className="text-xs bg-purple-900/40 text-purple-300 px-2 py-0.5 rounded">{f}</span>
                ))}
                {result.optionalHeader.dllCharacteristics.length === 0 && (
                  <span className="text-xs text-gray-600">Нет</span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {result.optionalHeader && result.optionalHeader.dataDirectories.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold text-emerald-400 mb-3 flex items-center gap-2">
            <span>📊</span> Data Directories
          </h3>
          <div className="bg-gray-950 rounded-lg border border-gray-800 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left py-2 px-4 text-gray-500 font-medium">Name</th>
                  <th className="text-right py-2 px-4 text-gray-500 font-medium">Virtual Address</th>
                  <th className="text-right py-2 px-4 text-gray-500 font-medium">Size</th>
                </tr>
              </thead>
              <tbody>
                {result.optionalHeader.dataDirectories.map((dd, i) => (
                  <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="py-2 px-4 text-gray-300">{dd.name}</td>
                    <td className="py-2 px-4 text-right text-yellow-400">{dd.virtualAddress > 0 ? formatHex(dd.virtualAddress) : '—'}</td>
                    <td className="py-2 px-4 text-right text-gray-400">{dd.size > 0 ? formatBytes(dd.size) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function SectionsTab({ result }: { result: PEResult }) {
  return (
    <div className="p-6">
      <h3 className="text-lg font-semibold text-emerald-400 mb-4 flex items-center gap-2">
        <span>📦</span> Section Headers ({result.sections.length})
      </h3>
      <div className="space-y-4">
        {result.sections.map((section, i) => (
          <div key={i} className="bg-gray-950 rounded-lg border border-gray-800 p-4">
            <div className="flex items-center justify-between mb-3">
              <h4 className="font-bold text-yellow-400 text-lg">{section.name}</h4>
              <span className="text-xs text-gray-500">#{i + 1}</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <InfoRow label="Virtual Size" value={formatBytes(section.virtualSize)} />
              <InfoRow label="Virtual Address" value={formatHex(section.virtualAddress)} />
              <InfoRow label="Raw Data Size" value={formatBytes(section.sizeOfRawData)} />
              <InfoRow label="Raw Data Pointer" value={formatHex(section.pointerToRawData)} />
            </div>
            <div className="mt-2 pt-2 border-t border-gray-800">
              <span className="text-xs text-gray-500 block mb-1">Characteristics:</span>
              <div className="flex flex-wrap gap-1">
                {section.characteristics.map(c => (
                  <span key={c} className={`text-xs px-2 py-0.5 rounded ${
                    c.includes('EXECUTE') ? 'bg-red-900/40 text-red-300' :
                    c.includes('WRITE') ? 'bg-orange-900/40 text-orange-300' :
                    c.includes('READ') ? 'bg-green-900/40 text-green-300' :
                    c.includes('CODE') ? 'bg-blue-900/40 text-blue-300' :
                    c.includes('INITIALIZED') ? 'bg-cyan-900/40 text-cyan-300' :
                    c.includes('UNINITIALIZED') ? 'bg-gray-700/40 text-gray-400' :
                    'bg-gray-800 text-gray-400'
                  }`}>{c}</span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ImportsTab({ result }: { result: PEResult }) {
  return (
    <div className="p-6">
      <h3 className="text-lg font-semibold text-emerald-400 mb-4 flex items-center gap-2">
        <span>📥</span> Import Table ({result.imports.length} DLL)
      </h3>
      {result.imports.length === 0 ? (
        <p className="text-gray-500 text-center py-8">Импорты не найдены</p>
      ) : (
        <div className="space-y-3">
          {result.imports.map((imp, i) => (
            <details key={i} className="bg-gray-950 rounded-lg border border-gray-800 group">
              <summary className="p-4 cursor-pointer flex items-center justify-between hover:bg-gray-800/30 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="text-blue-400">📚</span>
                  <span className="font-semibold text-blue-300">{imp.dllName}</span>
                </div>
                <span className="text-xs text-gray-500">{imp.functions.length} функций</span>
              </summary>
              <div className="px-4 pb-4 border-t border-gray-800">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-1 mt-2">
                  {imp.functions.map((fn, j) => (
                    <div key={j} className="text-xs text-gray-400 py-1 px-2 bg-gray-900/50 rounded">
                      <span className="text-gray-600 mr-1">#{j}</span>
                      <span className="text-cyan-300">{fn}</span>
                    </div>
                  ))}
                </div>
              </div>
            </details>
          ))}
        </div>
      )}
    </div>
  );
}

function ExportsTab({ result }: { result: PEResult }) {
  return (
    <div className="p-6">
      <h3 className="text-lg font-semibold text-emerald-400 mb-4 flex items-center gap-2">
        <span>📤</span> Export Table ({result.exports.length})
      </h3>
      {result.exports.length === 0 ? (
        <p className="text-gray-500 text-center py-8">Экспорты не найдены (обычно только для DLL)</p>
      ) : (
        <div className="bg-gray-950 rounded-lg border border-gray-800 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="text-left py-2 px-4 text-gray-500 font-medium">Ordinal</th>
                <th className="text-left py-2 px-4 text-gray-500 font-medium">Name</th>
                <th className="text-right py-2 px-4 text-gray-500 font-medium">Address</th>
              </tr>
            </thead>
            <tbody>
              {result.exports.map((exp, i) => (
                <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="py-2 px-4 text-gray-500">{exp.ordinal}</td>
                  <td className="py-2 px-4 text-cyan-300">{exp.name}</td>
                  <td className="py-2 px-4 text-right text-yellow-400">{formatHex(exp.address)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function StringsTab({ result }: { result: PEResult }) {
  const [filter, setFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | 'ascii' | 'unicode'>('all');

  const filtered = result.strings.filter(s => {
    if (typeFilter !== 'all' && s.type !== typeFilter) return false;
    if (filter && !s.value.toLowerCase().includes(filter.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="p-6">
      <h3 className="text-lg font-semibold text-emerald-400 mb-4 flex items-center gap-2">
        <span>🔤</span> Strings ({result.strings.length} найдено)
      </h3>

      <div className="flex gap-3 mb-4 flex-wrap">
        <input
          type="text"
          placeholder="Поиск строк..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="flex-1 min-w-[200px] bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-emerald-500 focus:outline-none"
        />
        <div className="flex gap-1 bg-gray-950 rounded border border-gray-700 p-1">
          {(['all', 'ascii', 'unicode'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-3 py-1 rounded text-xs ${typeFilter === t ? 'bg-emerald-600 text-white' : 'text-gray-400 hover:text-white'}`}
            >
              {t === 'all' ? 'Все' : t.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-gray-950 rounded-lg border border-gray-800 max-h-[600px] overflow-y-auto">
        {filtered.length === 0 ? (
          <p className="text-gray-500 text-center py-8">Строки не найдены</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-gray-950">
              <tr className="border-b border-gray-800">
                <th className="text-left py-2 px-4 text-gray-500 font-medium w-24">Offset</th>
                <th className="text-left py-2 px-4 text-gray-500 font-medium w-16">Type</th>
                <th className="text-left py-2 px-4 text-gray-500 font-medium">Value</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((s, i) => (
                <tr key={i} className="border-b border-gray-800/30 hover:bg-gray-800/30">
                  <td className="py-1 px-4 text-gray-600 text-xs">{formatHex(s.offset)}</td>
                  <td className="py-1 px-4">
                    <span className={`text-xs px-1.5 py-0.5 rounded ${
                      s.type === 'ascii' ? 'bg-blue-900/40 text-blue-300' : 'bg-purple-900/40 text-purple-300'
                    }`}>{s.type}</span>
                  </td>
                  <td className="py-1 px-4 text-gray-300 break-all text-xs">{s.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function DisasmTab({ result }: { result: PEResult }) {
  return (
    <div className="p-6">
      <h3 className="text-lg font-semibold text-emerald-400 mb-4 flex items-center gap-2">
        <span>⚙️</span> Дизассемблер (.text секция)
      </h3>
      {result.disassembly.length === 0 ? (
        <p className="text-gray-500 text-center py-8">Код не найден или секция .text отсутствует</p>
      ) : (
        <div className="bg-gray-950 rounded-lg border border-gray-800 overflow-x-auto max-h-[600px] overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-gray-950">
              <tr className="border-b border-gray-800">
                <th className="text-left py-2 px-4 text-gray-500 font-medium">Offset</th>
                <th className="text-left py-2 px-4 text-gray-500 font-medium">Bytes</th>
                <th className="text-left py-2 px-4 text-gray-500 font-medium">Instruction</th>
              </tr>
            </thead>
            <tbody>
              {result.disassembly.map((line, i) => (
                <tr key={i} className="border-b border-gray-800/30 hover:bg-gray-800/30">
                  <td className="py-1 px-4 text-gray-600 text-xs font-mono">{formatHex(line.offset)}</td>
                  <td className="py-1 px-4 text-gray-500 text-xs font-mono">{line.bytes}</td>
                  <td className={`py-1 px-4 text-xs font-mono font-bold ${
                    line.instruction.startsWith('CALL') ? 'text-yellow-400' :
                    line.instruction.startsWith('JMP') || line.instruction.startsWith('JE') || line.instruction.startsWith('JNE') ? 'text-green-400' :
                    line.instruction.startsWith('MOV') ? 'text-cyan-300' :
                    line.instruction.startsWith('PUSH') || line.instruction.startsWith('POP') ? 'text-purple-300' :
                    line.instruction.startsWith('RET') ? 'text-red-400' :
                    line.instruction.startsWith('NOP') ? 'text-gray-600' :
                    line.instruction.startsWith('INT') ? 'text-orange-400' :
                    line.instruction.startsWith('XOR') ? 'text-pink-300' :
                    line.instruction.startsWith('ADD') || line.instruction.startsWith('SUB') ? 'text-emerald-300' :
                    'text-gray-300'
                  }`}>{line.instruction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function HexTab({ result }: { result: PEResult }) {
  return (
    <div className="p-6">
      <h3 className="text-lg font-semibold text-emerald-400 mb-4 flex items-center gap-2">
        <span>🔢</span> Hex View (первые 512 байт)
      </h3>
      <div className="bg-gray-950 rounded-lg border border-gray-800 overflow-x-auto max-h-[600px] overflow-y-auto">
        <div className="p-4 font-mono text-xs leading-5">
          {result.hexView.map((row, i) => (
            <div key={i} className="flex hover:bg-gray-800/30">
              <span className="text-gray-600 w-20 shrink-0">{row.offset.toString(16).padStart(8, '0').toUpperCase()}</span>
              <span className="text-gray-300 w-[380px] shrink-0">{row.bytes}</span>
              <span className="text-emerald-400/70">{row.ascii}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

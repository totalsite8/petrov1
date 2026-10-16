// PE (Portable Executable) Format Parser
// Parses Windows EXE/DLL files and extracts structural information

export interface DOSHeader {
  e_magic: string;
  e_lfanew: number;
}

export interface PEHeader {
  signature: string;
  machine: string;
  numberOfSections: number;
  timeDateStamp: number;
  optionalHeaderSize: number;
  characteristics: string[];
}

export interface OptionalHeader {
  magic: string;
  majorLinkerVersion: number;
  minorLinkerVersion: number;
  sizeOfCode: number;
  sizeOfInitializedData: number;
  sizeOfUninitializedData: number;
  addressOfEntryPoint: number;
  baseOfCode: number;
  imageBase: number;
  sectionAlignment: number;
  fileAlignment: number;
  majorOSVersion: number;
  minorOSVersion: number;
  majorImageVersion: number;
  minorImageVersion: number;
  majorSubsystemVersion: number;
  minorSubsystemVersion: number;
  subsystem: string;
  sizeOfImage: number;
  sizeOfHeaders: number;
  checksum: number;
  dllCharacteristics: string[];
  numberOfRvaAndSizes: number;
  dataDirectories: DataDirectory[];
}

export interface DataDirectory {
  name: string;
  virtualAddress: number;
  size: number;
}

export interface SectionHeader {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  characteristics: string[];
}

export interface ImportEntry {
  dllName: string;
  functions: string[];
}

export interface ExportEntry {
  name: string;
  ordinal: number;
  address: number;
}

export interface StringEntry {
  offset: number;
  value: string;
  type: 'ascii' | 'unicode';
}

export interface DisassemblyLine {
  offset: number;
  bytes: string;
  instruction: string;
}

export interface PEResult {
  fileName: string;
  fileSize: number;
  dosHeader: DOSHeader;
  peHeader: PEHeader;
  optionalHeader: OptionalHeader | null;
  sections: SectionHeader[];
  imports: ImportEntry[];
  exports: ExportEntry[];
  strings: StringEntry[];
  disassembly: DisassemblyLine[];
  hexView: { offset: number; bytes: string; ascii: string }[];
  rawBytes: Uint8Array;
}

const MACHINE_TYPES: Record<number, string> = {
  0x0: 'UNKNOWN',
  0x14c: 'I386 (32-bit)',
  0x162: 'MIPS',
  0x166: 'MIPS16',
  0x168: 'MIPS FPU',
  0x169: 'MIPS FPU16',
  0x1a2: 'SH3',
  0x1a3: 'SH3DSP',
  0x1a4: 'SH3E',
  0x1a6: 'SH4',
  0x1a8: 'SH5',
  0x1c0: 'ARM',
  0x1c4: 'ARM Thumb',
  0x1c5: 'ARM Thumb-2',
  0x8664: 'AMD64 (64-bit)',
  0x200: 'IA64',
  0xaa64: 'ARM64',
};

const SUBSYSTEM_TYPES: Record<number, string> = {
  0: 'UNKNOWN',
  1: 'NATIVE',
  2: 'WINDOWS_GUI',
  3: 'WINDOWS_CUI',
  5: 'OS2_CUI',
  7: 'POSIX_CUI',
  8: 'NATIVE_WINDOWS',
  9: 'WINDOWS_CE_GUI',
  10: 'EFI_APPLICATION',
  11: 'EFI_BOOT_SERVICE_DRIVER',
  12: 'EFI_RUNTIME_DRIVER',
  13: 'EFI_ROM',
  14: 'XBOX',
  16: 'WINDOWS_BOOT_APPLICATION',
};

const CHARACTERISTIC_FLAGS: [number, string][] = [
  [0x0002, 'EXECUTABLE_IMAGE'],
  [0x0001, 'RELOCS_STRIPPED'],
  [0x0004, 'LINE_NUMS_STRIPPED'],
  [0x0008, 'LOCAL_SYMS_STRIPPED'],
  [0x0010, 'AGGRESSIVE_WS_TRIM'],
  [0x0020, 'LARGE_ADDRESS_AWARE'],
  [0x0080, 'BYTES_REVERSED_LO'],
  [0x0100, '32BIT_MACHINE'],
  [0x0200, 'DEBUG_STRIPPED'],
  [0x0400, 'REMOVABLE_RUN_FROM_SWAP'],
  [0x0800, 'NET_RUN_FROM_SWAP'],
  [0x1000, 'SYSTEM'],
  [0x2000, 'DLL'],
  [0x4000, 'UP_SYSTEM_ONLY'],
  [0x8000, 'BYTES_REVERSED_HI'],
];

const DLL_CHARACTERISTIC_FLAGS: [number, string][] = [
  [0x0020, 'HIGH_ENTROPY_VA'],
  [0x0040, 'DYNAMIC_BASE (ASLR)'],
  [0x0080, 'FORCE_INTEGRITY'],
  [0x0100, 'NX_COMPAT (DEP)'],
  [0x0200, 'NO_ISOLATION'],
  [0x0400, 'NO_SEH'],
  [0x0800, 'NO_BIND'],
  [0x1000, 'APPCONTAINER'],
  [0x2000, 'WDM_DRIVER'],
  [0x4000, 'GUARD_CF'],
  [0x8000, 'TERMINAL_SERVER_AWARE'],
];

const SECTION_CHARACTERISTIC_FLAGS: [number, string][] = [
  [0x00000008, 'NO_PAD'],
  [0x00000010, 'UNUSED'],
  [0x00000020, 'CODE'],
  [0x00000040, 'INITIALIZED_DATA'],
  [0x00000080, 'UNINITIALIZED_DATA'],
  [0x00000100, 'LNK_OTHER'],
  [0x00000200, 'LNK_INFO'],
  [0x00000800, 'LNK_REMOVE'],
  [0x00001000, 'LNK_COMDAT'],
  [0x00004000, 'NO_DEFER_SPEC_EXC'],
  [0x00008000, 'GPREL'],
  [0x00020000, 'MEM_PURGEABLE'],
  [0x00040000, 'MEM_LOCKED'],
  [0x00080000, 'MEM_PRELOAD'],
  [0x00100000, 'ALIGN_1BYTES'],
  [0x00200000, 'ALIGN_2BYTES'],
  [0x00300000, 'ALIGN_4BYTES'],
  [0x00400000, 'ALIGN_8BYTES'],
  [0x00500000, 'ALIGN_16BYTES'],
  [0x00600000, 'ALIGN_32BYTES'],
  [0x00700000, 'ALIGN_64BYTES'],
  [0x00800000, 'ALIGN_128BYTES'],
  [0x00900000, 'ALIGN_256BYTES'],
  [0x00a00000, 'ALIGN_512BYTES'],
  [0x00b00000, 'ALIGN_1024BYTES'],
  [0x00c00000, 'ALIGN_2048BYTES'],
  [0x00d00000, 'ALIGN_4096BYTES'],
  [0x00e00000, 'ALIGN_8192BYTES'],
  [0x01000000, 'LNK_NRELOC_OVFL'],
  [0x02000000, 'MEM_DISCARDABLE'],
  [0x04000000, 'MEM_NOT_CACHED'],
  [0x08000000, 'MEM_NOT_PAGED'],
  [0x10000000, 'MEM_SHARED'],
  [0x20000000, 'MEM_EXECUTE'],
  [0x40000000, 'MEM_READ'],
  [0x80000000, 'MEM_WRITE'],
];

const DATA_DIRECTORY_NAMES = [
  'EXPORT_TABLE',
  'IMPORT_TABLE',
  'RESOURCE_TABLE',
  'EXCEPTION_TABLE',
  'CERTIFICATE_TABLE',
  'BASE_RELOCATION_TABLE',
  'DEBUG',
  'ARCHITECTURE',
  'GLOBAL_PTR',
  'TLS_TABLE',
  'LOAD_CONFIG_TABLE',
  'BOUND_IMPORT',
  'IAT',
  'DELAY_IMPORT_DESCRIPTOR',
  'CLR_RUNTIME_HEADER',
  'RESERVED',
];

function readUint16(view: DataView, offset: number): number {
  return view.getUint16(offset, true);
}

function readUint32(view: DataView, offset: number): number {
  return view.getUint32(offset, true);
}

function readInt32(view: DataView, offset: number): number {
  return view.getInt32(offset, true);
}

function readUint64(view: DataView, offset: number): number {
  const lo = view.getUint32(offset, true);
  const hi = view.getUint32(offset + 4, true);
  return hi * 0x100000000 + lo;
}

function readString(view: DataView, offset: number, maxLen: number = 8): string {
  let result = '';
  for (let i = 0; i < maxLen; i++) {
    const ch = view.getUint8(offset + i);
    if (ch === 0) break;
    result += String.fromCharCode(ch);
  }
  return result;
}

function readCString(buffer: Uint8Array, offset: number): string {
  let result = '';
  for (let i = offset; i < buffer.length; i++) {
    if (buffer[i] === 0) break;
    result += String.fromCharCode(buffer[i]);
  }
  return result;
}

function getFlags(value: number, flags: [number, string][]): string[] {
  const result: string[] = [];
  for (const [bit, name] of flags) {
    if (value & bit) {
      result.push(name);
    }
  }
  return result;
}

function rvaToOffset(rva: number, sections: SectionHeader[]): number {
  for (const section of sections) {
    if (rva >= section.virtualAddress && rva < section.virtualAddress + section.virtualSize) {
      return rva - section.virtualAddress + section.pointerToRawData;
    }
  }
  return rva;
}

export function parsePE(buffer: ArrayBuffer, fileName: string): PEResult {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // DOS Header
  const dosMagic = String.fromCharCode(view.getUint8(0), view.getUint8(1));
  if (dosMagic !== 'MZ') {
    throw new Error('Неверный формат: отсутствует MZ сигнатура. Это не PE файл.');
  }

  const e_lfanew = readUint32(view, 0x3C);

  const dosHeader: DOSHeader = {
    e_magic: dosMagic,
    e_lfanew,
  };

  // PE Signature
  const peSignature = String.fromCharCode(
    view.getUint8(e_lfanew),
    view.getUint8(e_lfanew + 1),
    view.getUint8(e_lfanew + 2),
    view.getUint8(e_lfanew + 3)
  );

  // COFF Header
  const coffOffset = e_lfanew + 4;
  const machine = readUint16(view, coffOffset);
  const numberOfSections = readUint16(view, coffOffset + 2);
  const timeDateStamp = readUint32(view, coffOffset + 4);
  const optionalHeaderSize = readUint16(view, coffOffset + 16);
  const characteristics = readUint16(view, coffOffset + 18);

  const peHeader: PEHeader = {
    signature: peSignature,
    machine: MACHINE_TYPES[machine] || `UNKNOWN (0x${machine.toString(16)})`,
    numberOfSections,
    timeDateStamp,
    optionalHeaderSize,
    characteristics: getFlags(characteristics, CHARACTERISTIC_FLAGS),
  };

  // Optional Header
  let optionalHeader: OptionalHeader | null = null;
  const optOffset = coffOffset + 20;

  if (optionalHeaderSize > 0) {
    const magic = readUint16(view, optOffset);
    const isPE32Plus = magic === 0x20b;

    const dataDirOffset = isPE32Plus ? optOffset + 112 : optOffset + 96;
    const numberOfRvaAndSizes = readUint32(view, dataDirOffset - 4);

    const dataDirectories: DataDirectory[] = [];
    for (let i = 0; i < Math.min(numberOfRvaAndSizes, 16); i++) {
      const ddOffset = dataDirOffset + i * 8;
      dataDirectories.push({
        name: DATA_DIRECTORY_NAMES[i] || `UNKNOWN_${i}`,
        virtualAddress: readUint32(view, ddOffset),
        size: readUint32(view, ddOffset + 4),
      });
    }

    optionalHeader = {
      magic: isPE32Plus ? 'PE32+ (64-bit)' : 'PE32 (32-bit)',
      majorLinkerVersion: view.getUint8(optOffset + 2),
      minorLinkerVersion: view.getUint8(optOffset + 3),
      sizeOfCode: readUint32(view, optOffset + 4),
      sizeOfInitializedData: readUint32(view, optOffset + 8),
      sizeOfUninitializedData: readUint32(view, optOffset + 12),
      addressOfEntryPoint: readUint32(view, optOffset + 16),
      baseOfCode: readUint32(view, optOffset + 20),
      imageBase: isPE32Plus
        ? readUint64(view, optOffset + 24)
        : readUint32(view, optOffset + 28),
      sectionAlignment: readUint32(view, isPE32Plus ? optOffset + 32 : optOffset + 32),
      fileAlignment: readUint32(view, isPE32Plus ? optOffset + 36 : optOffset + 36),
      majorOSVersion: readUint16(view, isPE32Plus ? optOffset + 40 : optOffset + 40),
      minorOSVersion: readUint16(view, isPE32Plus ? optOffset + 42 : optOffset + 42),
      majorImageVersion: readUint16(view, isPE32Plus ? optOffset + 44 : optOffset + 44),
      minorImageVersion: readUint16(view, isPE32Plus ? optOffset + 46 : optOffset + 46),
      majorSubsystemVersion: readUint16(view, isPE32Plus ? optOffset + 48 : optOffset + 48),
      minorSubsystemVersion: readUint16(view, isPE32Plus ? optOffset + 50 : optOffset + 50),
      subsystem: SUBSYSTEM_TYPES[readUint16(view, isPE32Plus ? optOffset + 68 : optOffset + 68)] || 'UNKNOWN',
      sizeOfImage: readUint32(view, isPE32Plus ? optOffset + 56 : optOffset + 56),
      sizeOfHeaders: readUint32(view, isPE32Plus ? optOffset + 60 : optOffset + 60),
      checksum: readUint32(view, isPE32Plus ? optOffset + 64 : optOffset + 64),
      dllCharacteristics: getFlags(
        readUint16(view, isPE32Plus ? optOffset + 70 : optOffset + 70),
        DLL_CHARACTERISTIC_FLAGS
      ),
      numberOfRvaAndSizes,
      dataDirectories,
    };
  }

  // Section Headers
  const sectionOffset = optOffset + optionalHeaderSize;
  const sections: SectionHeader[] = [];

  for (let i = 0; i < numberOfSections; i++) {
    const secOffset = sectionOffset + i * 40;
    const secName = readString(view, secOffset, 8);
    const secCharacteristics = readUint32(view, secOffset + 36);

    sections.push({
      name: secName,
      virtualSize: readUint32(view, secOffset + 8),
      virtualAddress: readUint32(view, secOffset + 12),
      sizeOfRawData: readUint32(view, secOffset + 16),
      pointerToRawData: readUint32(view, secOffset + 20),
      characteristics: getFlags(secCharacteristics, SECTION_CHARACTERISTIC_FLAGS),
    });
  }

  // Parse Imports
  const imports: ImportEntry[] = [];
  if (optionalHeader) {
    const importDir = optionalHeader.dataDirectories.find(d => d.name === 'IMPORT_TABLE');
    if (importDir && importDir.virtualAddress > 0) {
      try {
        const importOffset = rvaToOffset(importDir.virtualAddress, sections);
        let idx = 0;

        while (true) {
          const descOffset = importOffset + idx * 20;
          if (descOffset + 20 > buffer.byteLength) break;

          const originalFirstThunk = readUint32(view, descOffset);
          const nameRVA = readUint32(view, descOffset + 12);

          if (nameRVA === 0) break;

          const nameOffset = rvaToOffset(nameRVA, sections);
          const dllName = readCString(bytes, nameOffset);

          const thunkRVA = originalFirstThunk || readUint32(view, descOffset + 16);
          const thunkOffset = rvaToOffset(thunkRVA, sections);

          const functions: string[] = [];
          const isPE32Plus = optionalHeader.magic.includes('PE32+');
          const thunkSize = isPE32Plus ? 8 : 4;
          let funcIdx = 0;

          while (funcIdx < 1000) {
            const fOffset = thunkOffset + funcIdx * thunkSize;
            if (fOffset + thunkSize > buffer.byteLength) break;

            const value = isPE32Plus ? readUint64(view, fOffset) : readUint32(view, fOffset);
            if (value === 0) break;

            const isOrdinal = isPE32Plus
              ? (value & 0x8000000000000000) !== 0
              : (value & 0x80000000) !== 0;

            if (isOrdinal) {
              functions.push(`Ordinal#${value & 0xFFFF}`);
            } else {
              const hintOffset = rvaToOffset(value & 0x7FFFFFFF, sections);
              if (hintOffset + 2 < buffer.byteLength) {
                const funcName = readCString(bytes, hintOffset + 2);
                if (funcName) functions.push(funcName);
              }
            }
            funcIdx++;
          }

          imports.push({ dllName, functions });
          idx++;
          if (idx > 500) break;
        }
      } catch (e) {
        // Import parsing failed partially
      }
    }
  }

  // Parse Exports
  const exports: ExportEntry[] = [];
  if (optionalHeader) {
    const exportDir = optionalHeader.dataDirectories.find(d => d.name === 'EXPORT_TABLE');
    if (exportDir && exportDir.virtualAddress > 0) {
      try {
        const exportOffset = rvaToOffset(exportDir.virtualAddress, sections);
        const nameRVA = readUint32(view, exportOffset + 12);
        const numFunctions = readUint32(view, exportOffset + 20);
        const numNames = readUint32(view, exportOffset + 24);
        const addrTableRVA = readUint32(view, exportOffset + 28);
        const namePtrTableRVA = readUint32(view, exportOffset + 32);
        const ordinalTableRVA = readUint32(view, exportOffset + 36);

        const addrTableOffset = rvaToOffset(addrTableRVA, sections);
        const namePtrTableOffset = rvaToOffset(namePtrTableRVA, sections);
        const ordinalTableOffset = rvaToOffset(ordinalTableRVA, sections);

        for (let i = 0; i < Math.min(numNames, 1000); i++) {
          const namePtrOffset = namePtrTableOffset + i * 4;
          if (namePtrOffset + 4 > buffer.byteLength) break;

          const fNameRVA = readUint32(view, namePtrOffset);
          const fNameOffset = rvaToOffset(fNameRVA, sections);
          const name = readCString(bytes, fNameOffset);

          const ordinal = readUint16(view, ordinalTableOffset + i * 2);
          const address = readUint32(view, addrTableOffset + ordinal * 4);

          exports.push({ name, ordinal, address });
        }
      } catch (e) {
        // Export parsing failed partially
      }
    }
  }

  // Extract Strings
  const strings: StringEntry[] = [];
  const minLen = 4;

  // ASCII strings
  let currentStr = '';
  let currentOffset = 0;
  for (let i = 0; i < bytes.length; i++) {
    const ch = bytes[i];
    if (ch >= 32 && ch <= 126) {
      if (currentStr.length === 0) currentOffset = i;
      currentStr += String.fromCharCode(ch);
    } else {
      if (currentStr.length >= minLen) {
        strings.push({ offset: currentOffset, value: currentStr, type: 'ascii' });
      }
      currentStr = '';
    }
  }
  if (currentStr.length >= minLen) {
    strings.push({ offset: currentOffset, value: currentStr, type: 'ascii' });
  }

  // Unicode strings
  currentStr = '';
  currentOffset = 0;
  for (let i = 0; i < bytes.length - 1; i += 2) {
    const ch = bytes[i] | (bytes[i + 1] << 8);
    if (ch >= 32 && ch <= 126) {
      if (currentStr.length === 0) currentOffset = i;
      currentStr += String.fromCharCode(ch);
    } else {
      if (currentStr.length >= minLen) {
        strings.push({ offset: currentOffset, value: currentStr, type: 'unicode' });
      }
      currentStr = '';
    }
  }

  // Limit strings to prevent UI overload
  const limitedStrings = strings.slice(0, 500);

  // Simple x86 disassembly (basic instructions)
  const disassembly: DisassemblyLine[] = [];
  const codeSection = sections.find(s => s.name === '.text' || s.characteristics.includes('CODE'));
  if (codeSection) {
    const codeStart = codeSection.pointerToRawData;
    const codeEnd = Math.min(codeStart + codeSection.sizeOfRawData, codeStart + 256);

    for (let i = codeStart; i < codeEnd && disassembly.length < 50; i++) {
      const byte = bytes[i];
      const byteStr = byte.toString(16).padStart(2, '0').toUpperCase();
      let instruction = '';

      // Basic x86 instruction decoding
      switch (byte) {
        case 0x90: instruction = 'NOP'; break;
        case 0xC3: instruction = 'RET'; break;
        case 0xCC: instruction = 'INT 3'; break;
        case 0x55: instruction = 'PUSH EBP'; break;
        case 0x56: instruction = 'PUSH ESI'; break;
        case 0x57: instruction = 'PUSH EDI'; break;
        case 0x53: instruction = 'PUSH EBX'; break;
        case 0x50: instruction = 'PUSH EAX'; break;
        case 0x51: instruction = 'PUSH ECX'; break;
        case 0x52: instruction = 'PUSH EDX'; break;
        case 0x54: instruction = 'PUSH ESP'; break;
        case 0x5D: instruction = 'POP EBP'; break;
        case 0x5E: instruction = 'POP ESI'; break;
        case 0x5F: instruction = 'POP EDI'; break;
        case 0x58: instruction = 'POP EAX'; break;
        case 0x59: instruction = 'POP ECX'; break;
        case 0x5A: instruction = 'POP EDX'; break;
        case 0x5B: instruction = 'POP EBX'; break;
        case 0x5C: instruction = 'POP ESP'; break;
        case 0x89: {
          const modrm = bytes[i + 1];
          const reg = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI'][(modrm >> 3) & 7];
          const rm = ['EAX', 'ECX', 'EDX', 'EBX', '', 'EBP', 'ESI', 'EDI'][modrm & 7];
          if ((modrm & 0xC0) === 0xC0) {
            instruction = `MOV ${rm}, ${reg}`;
            i += 1;
          } else if ((modrm & 0xC0) === 0x00 && (modrm & 7) === 5) {
            const disp = readInt32(view, i + 2);
            instruction = `MOV [${disp >= 0 ? '0x' + disp.toString(16) : '-0x' + Math.abs(disp).toString(16)}], ${reg}`;
            i += 5;
          } else {
            instruction = `MOV [${rm}], ${reg}`;
            i += 1;
          }
          break;
        }
        case 0x8B: {
          const modrm = bytes[i + 1];
          const reg = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI'][(modrm >> 3) & 7];
          const rm = ['EAX', 'ECX', 'EDX', 'EBX', '', 'EBP', 'ESI', 'EDI'][modrm & 7];
          if ((modrm & 0xC0) === 0xC0) {
            instruction = `MOV ${reg}, ${rm}`;
            i += 1;
          } else if ((modrm & 0xC0) === 0x00 && (modrm & 7) === 5) {
            const disp = readInt32(view, i + 2);
            instruction = `MOV ${reg}, [${disp >= 0 ? '0x' + disp.toString(16) : '-0x' + Math.abs(disp).toString(16)}]`;
            i += 5;
          } else if ((modrm & 0xC0) === 0x40) {
            instruction = `MOV ${reg}, [${rm}+0x${bytes[i + 2].toString(16)}]`;
            i += 2;
          } else {
            instruction = `MOV ${reg}, [${rm}]`;
            i += 1;
          }
          break;
        }
        case 0xE8: {
          const rel = readInt32(view, i + 1);
          const target = i + 5 + rel;
          instruction = `CALL 0x${(target >>> 0).toString(16).padStart(8, '0')}`;
          i += 4;
          break;
        }
        case 0xE9: {
          const rel = readInt32(view, i + 1);
          const target = i + 5 + rel;
          instruction = `JMP 0x${(target >>> 0).toString(16).padStart(8, '0')}`;
          i += 4;
          break;
        }
        case 0xEB: {
          const rel = bytes[i + 1];
          const target = i + 2 + rel;
          instruction = `JMP SHORT 0x${(target >>> 0).toString(16).padStart(8, '0')}`;
          i += 1;
          break;
        }
        case 0x74: {
          const rel = bytes[i + 1];
          const target = i + 2 + rel;
          instruction = `JE/JZ 0x${(target >>> 0).toString(16).padStart(8, '0')}`;
          i += 1;
          break;
        }
        case 0x75: {
          const rel = bytes[i + 1];
          const target = i + 2 + rel;
          instruction = `JNE/JNZ 0x${(target >>> 0).toString(16).padStart(8, '0')}`;
          i += 1;
          break;
        }
        case 0x31:
        case 0x33: {
          const modrm = bytes[i + 1];
          const reg = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI'][(modrm >> 3) & 7];
          const rm = ['EAX', 'ECX', 'EDX', 'EBX', '', 'EBP', 'ESI', 'EDI'][modrm & 7];
          if ((modrm & 0xC0) === 0xC0) {
            instruction = `XOR ${rm}, ${reg}`;
          } else {
            instruction = `XOR ${rm}, ${reg}`;
          }
          i += 1;
          break;
        }
        case 0x01: {
          const modrm = bytes[i + 1];
          const reg = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI'][(modrm >> 3) & 7];
          const rm = ['EAX', 'ECX', 'EDX', 'EBX', '', 'EBP', 'ESI', 'EDI'][modrm & 7];
          instruction = `ADD ${rm}, ${reg}`;
          i += 1;
          break;
        }
        case 0x29: {
          const modrm = bytes[i + 1];
          const reg = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI'][(modrm >> 3) & 7];
          const rm = ['EAX', 'ECX', 'EDX', 'EBX', '', 'EBP', 'ESI', 'EDI'][modrm & 7];
          instruction = `SUB ${rm}, ${reg}`;
          i += 1;
          break;
        }
        case 0x83: {
          const modrm = bytes[i + 1];
          const op = ['ADD', 'OR', 'ADC', 'SBB', 'AND', 'SUB', 'XOR', 'CMP'][(modrm >> 3) & 7];
          const rm = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI'][modrm & 7];
          const imm = bytes[i + 2];
          if ((modrm & 0xC0) === 0xC0) {
            instruction = `${op} ${rm}, 0x${imm.toString(16)}`;
          } else {
            instruction = `${op} [${rm}], 0x${imm.toString(16)}`;
          }
          i += 2;
          break;
        }
        case 0xFF: {
          const modrm = bytes[i + 1];
          const op = (modrm >> 3) & 7;
          const rm = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI'][modrm & 7];
          if (op === 2) instruction = `CALL ${rm}`;
          else if (op === 4) instruction = `JMP ${rm}`;
          else if (op === 6) instruction = `PUSH ${rm}`;
          else instruction = `FF /${op} [${rm}]`;
          i += 1;
          break;
        }
        default:
          instruction = `DB 0x${byteStr}`;
          break;
      }

      const bytesSlice = Array.from(bytes.slice(i, Math.min(i + 8, codeEnd)))
        .map(b => b.toString(16).padStart(2, '0').toUpperCase())
        .join(' ');

      disassembly.push({
        offset: i,
        bytes: bytesSlice,
        instruction,
      });
    }
  }

  // Hex View (first 512 bytes)
  const hexView: { offset: number; bytes: string; ascii: string }[] = [];
  const hexLen = Math.min(512, bytes.length);
  for (let i = 0; i < hexLen; i += 16) {
    const rowBytes: string[] = [];
    let rowAscii = '';
    for (let j = 0; j < 16 && i + j < bytes.length; j++) {
      const b = bytes[i + j];
      rowBytes.push(b.toString(16).padStart(2, '0').toUpperCase());
      rowAscii += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
    }
    hexView.push({
      offset: i,
      bytes: rowBytes.join(' '),
      ascii: rowAscii,
    });
  }

  return {
    fileName,
    fileSize: buffer.byteLength,
    dosHeader,
    peHeader,
    optionalHeader,
    sections,
    imports,
    exports,
    strings: limitedStrings,
    disassembly,
    hexView,
    rawBytes: bytes,
  };
}

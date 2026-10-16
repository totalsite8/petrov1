#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NSISBI (NSIS "Big Installer") script decoder / decompiler.

Input : decompressed NSISBI data stream (concatenation of the 32 stream items),
        starting at its 8-byte item-size prefix.
Output: structural report + annotated disassembly + best-effort .nsi source.

Layout (verified against jgh0721/nsisbi_mirror Source/exehead/fileform.h):
  H = 8 (stream item size prefix)
  H+0                    : common header (header struct)
      u32 flags (CH_FLAGS_*)
      block_header blocks[8] : 12 bytes each = u32 lo, u32 hi(pad), u32 num
      ... (see FIELD_MAP below)
  block NB_PAGES     : page   struct, 64 bytes  (16 u32)
  block NB_SECTIONS  : section struct, 2072 bytes (6 u32 + 1024 TCHAR name)
  block NB_ENTRIES   : entry struct, 36 bytes (u32 which + 8 u32 params)
  block NB_STRINGS   : UTF-16LE string table with 0x0001/0x0002/0x0003 escape codes
  block NB_LANGTABLES: langtable structs
  block NB_CTLCOLORS : control colours
  block NB_DATA      : packed file data (ExtractFile offsets are relative to this)
"""
import json
import os
import re
import struct
import sys

H = 8  # stream item size prefix

# --------------------------------------------------------------------------
# opcodes (enum EW_*, computed from /tmp/bi_fileform.h with all features on)
# --------------------------------------------------------------------------
_OPC = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'opcodes.json')))
OPC = _OPC['map']
OPC_CMT = _OPC['cmt']
NAME = {v: k for k, v in OPC.items()}

# NSIS internal variable names
_VARSTR = ["CMDLINE", "INSTDIR", "OUTDIR", "EXEDIR", "LANGUAGE", "TEMP",
           "PLUGINSDIR", "EXEPATH", "EXEFILE", "HWNDPARENT", "_CLICK", "_OUTDIR"]
NUM_INTERNAL_VARS = 32

# Отрицательные «строковые» параметры — это встроенные строки exehead'а
# (Source/exehead/lang.h: LANG_STR_TAB(x) = cur_langtable[-((int)x+1)]).
LANG_GENERIC = {
    1: 'BRANDING', 2: 'CAPTION', 3: 'NAME', 4: 'SPACE_AVAIL', 5: 'SPACE_REQ',
    6: 'CANTWRITE', 7: 'COPYFAILED', 8: 'COPYTO', 9: 'CANNOTFINDSYMBOL',
    10: 'COULDNOTLOAD', 11: 'CREATEDIR', 12: 'CREATESHORTCUT', 13: 'CREATEDUNINST',
    14: 'DELETEFILE', 15: 'DELETEONREBOOT', 16: 'ERRORCREATINGSHORTCUT',
    17: 'ERRORCREATING', 18: 'ERRORDECOMPRESSING', 19: 'DLLREGERROR', 20: 'EXECSHELL',
    21: 'EXECUTE', 22: 'EXTRACT', 23: 'ERRORWRITING', 24: 'INSTCORRUPTED', 25: 'NOOLE',
    26: 'OUTPUTDIR', 27: 'REMOVEDIR', 28: 'RENAMEONREBOOT', 29: 'RENAME', 30: 'SKIPPED',
    31: 'COPYDETAILS', 32: 'LOG_INSTALL_PROCESS', 33: 'BYTE', 34: 'KILO', 35: 'MEGA',
    36: 'GIGA',
}


def var_name(idx):
    if idx < 10:
        return '$%d' % idx
    if idx < 20:
        return '$R%d' % (idx - 10)
    if idx < NUM_INTERNAL_VARS:
        return '$' + _VARSTR[idx - 20]
    return '$Var%d' % (idx - NUM_INTERNAL_VARS)


# CSIDL -> NSIS shell folder constant ($DESKTOP etc.)
CSIDL = {
    0x00: "$DESKTOP", 0x02: "$PROGRAMS", 0x05: "$DOCUMENTS", 0x06: "$FAVORITES",
    0x07: "$STARTUP", 0x08: "$RECENT", 0x09: "$SENDTO", 0x0b: "$STARTMENU",
    0x10: "$DESKTOPDIRECTORY", 0x11: "$DRIVES", 0x12: "$NETWORK", 0x13: "$NETHOOD",
    0x14: "$FONTS", 0x15: "$TEMPLATES", 0x16: "$COMMONSTARTMENU", 0x17: "$SMPROGRAMS",
    0x18: "$COMMONSTARTUP", 0x19: "$COMMONDESKTOPDIRECTORY", 0x1a: "$APPDATA",
    0x1b: "$PRINTHOOD", 0x1c: "$LOCALAPPDATA", 0x1d: "$ALTSTARTUP",
    0x1e: "$COMMONALTSTARTUP", 0x1f: "$COMMONFAVORITES", 0x20: "$INTERNETCACHE",
    0x21: "$COOKIES", 0x22: "$HISTORY", 0x23: "$COMMONAPPDATA", 0x24: "$WINDOWS",
    0x25: "$SYSTEM", 0x26: "$PROGRAMFILES", 0x27: "$MYPICTURES", 0x28: "$PROFILE",
    0x29: "$SYSTEMX86", 0x2a: "$PROGRAMFILESX86", 0x2b: "$COMMONFILES",
    0x2c: "$COMMONFILESX86", 0x2d: "$COMMONTEMPLATES", 0x2e: "$COMMONDOCUMENTS",
    0x2f: "$COMMONADMINTOOLS", 0x30: "$ADMINTOOLS", 0x31: "$CONNECTIONS",
    0x3b: "$MUSIC", 0x3d: "$VIDEO",
}

# install type flags (header.install_types[])
INSTTYPE_FLAGS = {1: "SF_SELECTED", 2: "SF_SECGRP", 4: "SF_SECGRPEND", 8: "SF_BOLD",
                  16: "SF_RO", 32: "SF_EXPAND", 64: "SF_PSELECTED", 128: "SF_TOGGLED",
                  256: "SF_NAMECHG"}

CH_FLAGS = {1: "DETAILS_SHOWDETAILS", 2: "DETAILS_NEVERSHOW", 4: "PROGRESS_COLORED",
            8: "SILENT", 16: "SILENT_LOG", 32: "AUTO_CLOSE", 64: "DIR_NO_SHOW",
            128: "NO_ROOT_DIR", 256: "COMP_ONLY_ON_CUSTOM", 512: "NO_CUSTOM"}

PWP = {0: "PWP_LICENSE", 1: "PWP_SELCOM", 2: "PWP_DIR", 3: "PWP_INSTFILES",
       4: "PWP_UNINST", 5: "PWP_COMPLETED", 6: "PWP_CUSTOM"}

REGROOTS = {0x80000000: "HKCR", 0x80000001: "HKCU", 0x80000002: "HKLM",
            0x80000003: "HKU", 0x80000004: "HKPD", 0x80000005: "HKCC", 0x80000006: "HKDD",
            0x80000007: "HKDD"}


def decode_short(lo, hi):
    """NSIS 3 (unicode) inline 14-bit packing."""
    return ((lo & 0x7F) | ((hi & 0x7F) << 7))


class Header(object):
    """Common header (first part of the data stream)."""

    # field name -> number of u32 words (blocks are expanded separately)
    FIELDS = [
        ("install_reg_rootkey", 1),
        ("install_reg_key_ptr", 1),
        ("install_reg_value_ptr", 1),
        ("bg_color1", 1), ("bg_color2", 1), ("bg_textcolor", 1),
        ("lb_bg", 1), ("lb_fg", 1),
        ("langtable_size", 1),
        ("license_bg", 1),
        ("code_onInit", 1), ("code_onInstSuccess", 1), ("code_onInstFailed", 1),
        ("code_onUserAbort", 1),
        ("code_onGUIInit", 1), ("code_onGUIEnd", 1), ("code_onMouseOverSection", 1),
        ("code_onVerifyInstDir", 1), ("code_onSelChange", 1), ("code_onRebootFailed", 1),
        ("install_types", 33),
        ("install_directory_ptr", 1), ("install_directory_auto_append", 1),
        ("str_uninstchild", 1), ("str_uninstcmd", 1), ("str_wininit", 1),
    ]
    BLOCK_NAMES = ["pages", "sections", "entries", "strings", "langtables",
                   "ctlcolors", "bgfont", "data"]

    def __init__(self, stream):
        self.s = stream
        self.blocks = []
        self.flags, = struct.unpack_from('<I', stream, H)
        off = H + 4          # u32 flags, then the 8 block descriptors (12 B each)
        for i in range(8):
            lo, hi, num = struct.unpack_from('<3I', stream, off)
            self.blocks.append({'off': lo | (hi << 32), 'num': num})
            off += 12
        self.fields = {}
        for name, n in self.FIELDS:
            v = struct.unpack_from('<%dI' % n, stream, off)
            self.fields[name] = list(v) if n > 1 else v[0]
            off += 4 * n
        self.size = off - H

    def block(self, name):
        return self.blocks[self.BLOCK_NAMES.index(name)]


class StringTable(object):
    """NSIS 3 unicode string table with inline codes.

    0x0001 lang   : next u16 encodes -(index+1) of a string in another langtable
    0x0002 shell  : next u16 = CSIDL pair (all-users in high byte, user in low byte)
    0x0003 var    : next u16 = packed variable index
    0x0004 skip   : next TCHAR is taken literally
    """

    def __init__(self, data):
        self.data = data
        self.n = len(data) // 2
        self.starts = []          # start offsets (in TCHARs) of every string
        self._starts_set = set()
        i = 0
        while i < self.n:
            self._starts_set.add(i)
            self.starts.append(i)
            while i < self.n:
                c = self.u(i)
                if c == 0:
                    break
                if c in (1, 2, 3):
                    i += 2
                    continue
                if c == 4:
                    i += 2
                    continue
                i += 1
            i += 1

    def u(self, i):
        return struct.unpack_from('<H', self.data, i * 2)[0]

    def parse_at(self, i):
        """Decode the string starting at TCHAR offset i (NSIS string sharing)."""
        out = []
        n = self.n
        while i < n:
            c = self.u(i)
            if c == 0:
                break
            if c in (1, 2, 3):
                v = decode_short(self.u(i + 1) & 0xFF, (self.u(i + 1) >> 8) & 0xFF)
                if c == 1:
                    out.append('$(lang_%d)' % (-v - 1))
                elif c == 2:
                    # NOTE: for the shell code NSIS uses LOBYTE/HIBYTE, not the
                    # packed 14-bit value (see GetNSISString in util.c).
                    raw = self.u(i + 1)
                    lo, hi = raw & 0xFF, (raw >> 8) & 0xFF
                    if lo & 0x80:
                        fname = self.parse_at(lo & 0x3F) if (lo & 0x3F) < n else '?'
                        out.append('$SHELLREG("%s"%s, fallback "%s")' % (
                            fname, ",wow64" if (lo & 0x40) else "",
                            self.parse_at(hi) if hi < n else '?'))
                    else:
                        nm = CSIDL.get(lo)
                        nm2 = CSIDL.get(hi)
                        if nm and (hi == 0 or nm == nm2):
                            out.append(nm)
                        elif nm:
                            out.append('$SHELL(%s|%s)' % (nm, nm2 or '?'))
                        else:
                            out.append('$SHELL(0x%02x|0x%02x)' % (lo, hi))
                else:
                    out.append(var_name(v))
                i += 2
                continue
            if c == 4:
                i += 1
                out.append(chr(self.u(i)))
                i += 1
                continue
            out.append(chr(c))
            i += 1
        return ''.join(out)

    def get(self, idx):
        if not (0 <= idx < self.n):
            return '<str#%d out of range>' % idx
        return self.parse_at(idx)


class Section(object):
    def __init__(self, data):
        (self.name_ptr, self.install_types, self.flags, self.code,
         self.code_size, self.size_kb) = struct.unpack_from('<6I', data, 0)
        raw = data[24:24 + 2048].decode('utf-16le', 'replace')
        self.name_inline = raw.split('\x00')[0]


class Page(object):
    def __init__(self, data):
        f = struct.unpack_from('<16I', data, 0)
        (self.dlg_id, self.wndproc_id, self.prefunc, self.showfunc, self.leavefunc,
         self.flags, self.caption, self.back, self.next, self.clicknext, self.cancel) = f[:11]
        self.parms = f[11:]


class Entry(object):
    __slots__ = ('which', 'p', 'i')

    def __init__(self, i, which, p):
        self.i = i
        self.which = which
        self.p = p


class NSIS(object):
    def __init__(self, stream):
        self.s = stream
        self.h = Header(stream)
        b = self.h.block('pages')
        self.pages = [Page(stream[H + b['off'] + i * 64:]) for i in range(b['num'])]
        b = self.h.block('sections')
        self.sections = [Section(stream[H + b['off'] + i * 2072:]) for i in range(b['num'])]
        b = self.h.block('entries')
        self.entries = []
        off = H + b['off']
        for i in range(b['num']):
            which, = struct.unpack_from('<I', stream, off + i * 36)
            p = struct.unpack_from('<8I', stream, off + i * 36 + 4)
            self.entries.append(Entry(i, which, p))
        b = self.h.block('strings')
        nb = self.h.block('langtables')
        self.strings = StringTable(stream[H + b['off']:H + nb['off']])
        self.langtable_off = H + nb['off']
        # The stream starts with a u64 'length_of_header' (counted from the end of
        # that very field, i.e. from H) that gives the absolute offset of the
        # packed-file-data area; the ctlcolors / bgfont / data block descriptors
        # are zeroed in this NSISBI build.
        self.data_off = struct.unpack_from('<Q', self.s, 0)[0] + H

    # -- helpers ---------------------------------------------------------
    def op(self, e):
        return NAME.get(e.which, 'EW_%d?' % e.which)

    def sstr(self, idx):
        return self.strings.get(idx)

    def is_str(self, idx):
        """True when *idx* is an offset into the string block.

        NSIS stores a parameter as a plain TCHAR offset into the string block
        (``GetNSISStringNP(strtab)``); the compiler also lets shorter strings
        point into the middle of longer ones (suffix sharing), so offsets that
        are not recorded as a string start are still valid strings.
        """
        n = self.strings.n
        if not (0 < idx < n):
            return False
        t = self.sstr(idx)
        if not t:
            return False
        return all(0x20 <= ord(c) < 0x10000 for c in t)

    def regroot(self, v):
        return REGROOTS.get(v & 0xFFFFFFFF, '0x%08X' % v)

    def data_file(self, off):
        """Read the size prefix of packed file data at stream offset ``off``."""
        size, = struct.unpack_from('<Q', self.s, off)
        comp = bool(size >> 63)
        return size & 0x7FFFFFFFFFFFFFFF, comp


# --------------------------------------------------------------------------
#  Disassembler
# --------------------------------------------------------------------------
class Dis(object):
    def __init__(self, n):
        self.n = n
        self.entries = n.entries
        self.labels = {}          # entry index -> set of label kinds
        self.funcs = {}           # entry index -> function name
        self._scan()

    def _targets(self, i, which, p):
        t = []
        op = NAME.get(which)
        if op == 'EW_NOP' and p[0]:
            t.append(p[0])
        elif op == 'EW_CALL' and p[0]:
            t.append(p[0])
            self.funcs.setdefault(p[0] - 1, 'func_%d' % (p[0] - 1))
        elif op in ('EW_IFFILEEXISTS',):
            t += [p[1], p[2]]
        elif op == 'EW_IFFLAG':
            t += [p[0], p[1]]
        elif op == 'EW_STRCMP':
            t += [p[2], p[3]]
        elif op == 'EW_INTCMP':
            t += [p[2], p[3], p[4]]
        elif op == 'EW_ISWINDOW':
            t += [p[1], p[2]]
        elif op == 'EW_MESSAGEBOX':
            t += [p[2], p[3]]
        elif op == 'EW_FINDWINDOW':
            t += []
        return [x for x in t if x]

    def _scan(self):
        for e in self.entries:
            for x in self._targets(e.i, e.which, e.p):
                idx = x - 1
                if 0 <= idx < len(self.entries):
                    self.labels.setdefault(idx, set()).add('label')
        # callbacks from header
        self.cb = {}
        for k, v in (('code_onInit', '.onInit'), ('code_onInstSuccess', '.onInstSuccess'),
                     ('code_onInstFailed', '.onInstFailed'), ('code_onUserAbort', '.onUserAbort'),
                     ('code_onGUIInit', '.onGUIInit'), ('code_onGUIEnd', '.onGUIEnd'),
                     ('code_onMouseOverSection', '.onMouseOverSection'),
                     ('code_onVerifyInstDir', '.onVerifyInstDir'),
                     ('code_onSelChange', '.onSelChange'),
                     ('code_onRebootFailed', '.onRebootFailed')):
            val = self.n.h.fields[k]
            if val != 0xFFFFFFFF and 0 <= val < len(self.entries):
                self.labels.setdefault(val, set()).add('cb')
                self.cb[val] = v
        for s in self.n.sections:
            if s.code < len(self.entries):
                self.labels.setdefault(s.code, set()).add('sec')

    # ---- rendering -----------------------------------------------------
    def S(self, idx):
        """render a string-index parameter"""
        if idx in (0xFFFFFFFF,):
            return ''
        if not self.n.is_str(idx):
            return 'str?%d' % idx
        return '"%s"' % self.n.sstr(idx).replace('"', '$\\"')

    def maybe_str(self, idx, quoted=False):
        """Строковый параметр; отрицательные значения — встроенные строки exehead."""
        if self.n.is_str(idx):
            return '"%s"' % self.n.sstr(idx).replace('"', '$\\"')
        if 0xFFFFFF00 <= idx <= 0xFFFFFFFF:
            return self.langstr(idx)
        return str(idx)

    def num(self, v):
        """Числовой параметр инструкции.

        NSIS вычисляет все целочисленные операнды во время выполнения через
        ``myatoi(GetNSISString(param))``; компилятор NSISBI кладёт числовые
        литералы и ссылки на переменные в таблицу строк, поэтому значение,
        указывающее на строку, печатается либо как число, либо как имя
        переменной (``$0``, ``$LANGUAGE``, ``$Var61`` …).
        """
        v &= 0xFFFFFFFF
        if self.n.is_str(v):
            t = self.n.sstr(v).strip()
            if t.startswith('$'):
                return t
            m = re.match(r'[-+]?\d+', t)
            if m:
                return str(int(m.group(0)))
            return str(v - 0x100000000) if v >= 0x80000000 else str(v)
        return str(v - 0x100000000) if v >= 0x80000000 else str(v)

    def langstr(self, v):
        """Отрицательное значение = встроенная строка exehead'а (lang.h)."""
        n = -((v - 0x100000000) if v >= 0x80000000 else v)
        name = LANG_GENERIC.get(n)
        return '$(%s)' % name if name else '$(lang[-%d])' % n

    def A(self, v):
        """Операнд «строка или переменная»: как в исходном скрипте.

        Строка-ссылка на переменную печатается без кавычек, числовая строка —
        числом, произвольный текст — в кавычках (как это сделал бы компилятор).
        """
        v &= 0xFFFFFFFF
        if self.n.is_str(v):
            t = self.n.sstr(v)
            if re.fullmatch(r'\$(\d+|R\d+|[A-Za-z_][A-Za-z_0-9.]*|Var\d+)', t):
                return t
            if re.fullmatch(r'[-+]?\d+', t.strip()):
                return self.num(v)
            return '"%s"' % t.replace('"', '$\\"')
        if 0xFFFFFF00 <= v <= 0xFFFFFFFF:
            return self.langstr(v)
        return self.num(v)

    def I(self, v):
        """Числовой параметр: NSIS хранит числа интернированными строками."""
        v &= 0xFFFFFFFF
        if self.n.is_str(v):
            t = self.n.sstr(v).strip()
            if re.fullmatch(r'[-+]?\d+', t):
                return int(t)
            m = re.fullmatch(r'0[xX][0-9a-fA-F]+', t)
            if m:
                return int(t, 16)
        return v

    def tgt(self, v):
        return 'label_%d' % (v - 1) if v else '0'

    def render(self, e):
        op = self.n.op(e)
        p = e.p
        S = self.maybe_str
        G = self.tgt
        N = self.num
        A = self.A
        if op == 'EW_NOP':
            return 'Nop' if p[0] == 0 else 'Goto %s' % G(p[0])
        if op == 'EW_RET':
            return 'Return'
        if op == 'EW_ABORT':
            return 'Abort%s' % ((' ' + S(p[0])) if p[0] else '')
        if op == 'EW_QUIT':
            return 'Quit'
        if op == 'EW_CALL':
            return 'Call %s' % G(p[0])
        if op == 'EW_UPDATETEXT':
            # exec.c: UpdateStatusText / DetailPrint: parm0 = строка
            return 'DetailPrint %s' % A(p[0])
        if op == 'EW_SLEEP':
            return 'Sleep %s' % A(p[0])
        if op == 'EW_BRINGTOFRONT':
            return 'BringToFront'
        if op == 'EW_CHDETAILSVIEW':
            # exec.c: parm0/parm1 — флаги показа окна деталей
            return 'SetDetailsView show=%s button=%s' % (N(p[0]), N(p[1]))
        if op == 'EW_SETFILEATTRIBUTES':
            return 'SetFileAttributes %s %s' % (A(p[0]), N(p[1]))
        if op == 'EW_CREATEDIR':
            return ('SetOutPath %s' % A(p[0])) if p[1] else ('CreateDirectory %s' % A(p[0]))
        if op == 'EW_IFFILEEXISTS':
            return 'IfFileExists %s %s %s' % (S(p[0]), G(p[1]), G(p[2]))
        if op == 'EW_SETFLAG':
            # exec.c: g_exec_flags[parm0] = GetIntFromParm(1)
            return 'SetFlag bit=%s value=%s' % (N(p[0]), N(p[1]))
        if op == 'EW_IFFLAG':
            return 'IfFlag bit=%s mask=%s -> set:%s clear:%s' % (
                N(p[2]), N(p[3]), G(p[0]), G(p[1]))
        if op == 'EW_GETFLAG':
            return 'GetFlag %s 0x%X' % (var_name(p[0]), p[1])
        if op == 'EW_RENAME':
            return 'Rename %s %s' % (A(p[0]), A(p[1]))
        if op == 'EW_GETFULLPATHNAME':
            return 'GetFullPathName %s %s%s' % (var_name(p[0]), A(p[1]),
                                                '' if p[2] else ' (не сокращать в 8.3)')
        if op == 'EW_SEARCHPATH':
            return 'SearchPath %s %s' % (var_name(p[0]), S(p[1]))
        if op == 'EW_GETTEMPFILENAME':
            return 'GetTempFileName %s %s' % (var_name(p[0]), A(p[1]))
        if op in ('EW_EXTRACTFILE', 'EW_EXTRACTSTUBFILE'):
            name = S(p[1])
            size, comp = self.n.data_file(self.n.data_off + p[2])
            return 'File %s   ; data +0x%X size=%d%s' % (
                name, p[2], size, ' lzma' if comp else '')
        if op == 'EW_DELETEFILE':
            # flags: DEL_DIR 1, DEL_RECURSE 2, DEL_REBOOT 4, DEL_SIMPLE 8
            return 'Delete%s %s' % (' /REBOOTOK' if (p[1] & 4) else '', S(p[0]))
        if op == 'EW_MESSAGEBOX':
            return 'MessageBox MB=0x%X %s %s %s' % (int(N(p[0])), A(p[1]),
                                                    G(p[2]), G(p[3]))
        if op == 'EW_RMDIR':
            return 'RMDir%s%s %s' % (' /r' if (p[1] & 2) else '',
                                     ' /REBOOTOK' if (p[1] & 4) else '', A(p[0]))
        if op == 'EW_STRLEN':
            return 'StrLen %s %s' % (var_name(p[0]), A(p[1]))
        if op == 'EW_ASSIGNVAR':
            extra = ''
            if p[2] or p[3]:
                extra = ' maxlen=%s startpos=%s' % (N(p[2]), N(p[3]))
            return 'StrCpy %s %s%s' % (var_name(p[0]), A(p[1]), extra)
        if op == 'EW_STRCMP':
            return 'StrCmp%s %s %s %s %s' % ('S' if p[4] else '', A(p[0]), A(p[1]),
                                              G(p[2]), G(p[3]))
        if op == 'EW_READENVSTR':
            return ('ReadEnvStr %s %s' if p[2] else 'ExpandEnvStrings %s %s') % (
                var_name(p[0]), S(p[1]))
        if op == 'EW_INTCMP':
            return 'IntCmp%s%s %s %s %s %s %s' % ('U' if p[5] & 1 else '',
                                                  '64' if p[5] & 0x8000 else '',
                                                  N(p[0]), N(p[1]), G(p[2]), G(p[3]), G(p[4]))
        if op == 'EW_INTOP':
            instr = ['+', '-', '*', '/', '|', '&', '^', '~', '||', '&&', '%', '<<', '>>', '>>>'][p[3] & 0xF]
            return 'IntOp %s %s %s %s' % (var_name(p[0]), N(p[1]), instr, N(p[2]))
        if op == 'EW_INTFMT':
            return 'IntFmt %s %s %s' % (var_name(p[0]), A(p[1]), N(p[2]))
        if op == 'EW_PUSHPOP':
            if p[2]:
                return 'Exch' if p[2] == 1 else 'Exch %d' % p[2]
            if p[1]:
                return 'Pop %s' % var_name(p[0])
            return 'Push %s' % A(p[0])
        if op == 'EW_FINDWINDOW':
            return 'FindWindow %s %s %s' % (var_name(p[0]), S(p[1]), S(p[2]))
        if op == 'EW_SENDMESSAGE':
            return 'SendMessage %s %s %s %s (flags=0x%X)' % (
                'none' if p[0] == 0xFFFFFFFF else S(p[0]), S(p[1]), S(p[2]), S(p[3]), p[5])
        if op == 'EW_ISWINDOW':
            return 'IsWindow %s %s %s' % (A(p[0]), G(p[1]), G(p[2]))
        if op == 'EW_GETDLGITEM':
            return 'GetDlgItem %s %s %s' % (var_name(p[0]), A(p[1]), N(p[2]))
        if op == 'EW_SETCTLCOLORS':
            return 'SetCtlColors %s <colors %s>' % (S(p[0]), S(p[1]))
        if op == 'EW_LOADANDSETIMAGE':
            return 'LoadAndSetImage <ctrl=%s type=%s lrflags=%s img=%s>' % (
                S(p[0]), S(p[1]), S(p[2]), S(p[3]))
        if op == 'EW_CREATEFONT':
            # exec.c: parm1 = font name, parm2 = height, parm3 = weight, parm4 = style bits
            return 'CreateFont %s %s height=%s weight=%s italic=%d underline=%d strike=%d' % (
                var_name(p[0]), S(p[1]), N(p[2]), N(p[3]),
                p[4] & 1, (p[4] >> 1) & 1, (p[4] >> 2) & 1)
        if op == 'EW_SHOWWINDOW':
            return 'ShowWindow %s %s' % (A(p[0]), N(p[1]))
        if op == 'EW_SHELLEXEC':
            return 'ExecShell (mask=0x%X) %s %s %s' % (p[0], S(p[1]), S(p[2]), S(p[3]))
        if op == 'EW_EXECUTE':
            return 'Exec%s %s' % ('Wait' if p[1] else '', A(p[0]))
        if op == 'EW_GETFILETIME':
            return 'GetFileTime %s %s %s' % (S(p[0]), var_name(p[1]), var_name(p[2]))
        if op == 'EW_GETDLLVERSION':
            return 'GetDLLVersion %s %s %s' % (S(p[0]), var_name(p[1]), var_name(p[2]))
        if op == 'EW_REGISTERDLL':
            # exec.c EW_REGISTERDLL: [dll, func, ?, ?, flags, ?]
            return 'CallInstDLL/Plugin %s (func=%s)' % (
                A(p[0]), A(p[1]) if self.n.is_str(p[1]) else p[1])
        if op == 'EW_CREATESHORTCUT':
            return 'CreateShortCut %s -> %s args=%s icon=%s flags=0x%X' % (
                S(p[0]), S(p[1]), A(p[2]), A(p[3]), p[4])
        if op == 'EW_COPYFILES':
            # exec.c: buf0 = источник, buf1 = назначение, op.fFlags = parm2
            return 'CopyFiles %s %s flags=0x%X' % (A(p[0]), A(p[1]),
                                                   int(N(p[2])) if self.n.is_str(p[2]) else p[2])
        if op == 'EW_REBOOT':
            return 'Reboot'
        if op == 'EW_WRITEINI':
            return 'WriteINIStr %s %s %s %s' % (S(p[0]), S(p[1]), S(p[2]), S(p[3]))
        if op == 'EW_READINISTR':
            return 'ReadINIStr %s %s %s %s' % (var_name(p[0]), S(p[1]), S(p[2]), S(p[3]))
        if op == 'EW_DELREG':
            # [0, rootkey, keyname, valuename, action]  action 0 = value, 1 = key, 2 = /ifempty
            if p[4] == 0:
                return 'DeleteRegValue %s %s %s' % (self.n.regroot(p[1]), S(p[2]), S(p[3]))
            return 'DeleteRegKey %s %s%s' % (self.n.regroot(p[1]), S(p[2]),
                                             ' /ifempty' if (p[4] & 2) else '')
        if op == 'EW_WRITEREG':
            typ = p[5]
            kind = {1: 'WriteRegStr', 2: 'WriteRegExpandStr', 3: 'WriteRegBin',
                    4: 'WriteRegDWORD', 5: 'WriteRegDWORD64'}.get(typ, 'WriteReg?%d' % typ)
            return '%s %s %s %s %s' % (kind, self.n.regroot(p[0]), S(p[1]), S(p[2]), S(p[3]))
        if op == 'EW_READREGSTR':
            return '%s %s %s %s %s' % ('ReadRegDWORD' if p[4] else 'ReadRegStr',
                                       var_name(p[0]), self.n.regroot(p[1]), S(p[2]), S(p[3]))
        if op == 'EW_REGENUM':
            return 'EnumReg%s %s %s %s %s' % ('Value' if p[4] else 'Key', var_name(p[0]),
                                              self.n.regroot(p[1]), S(p[2]), S(p[3]))
        if op == 'EW_FCLOSE':
            return 'FileClose %s' % (var_name(p[0]))
        if op == 'EW_FOPEN':
            # exec.c: [handle var, dwDesiredAccess, dwCreationDisposition, file name]
            return 'FileOpen %s %s   ; access=0x%08X creat=%d' % (
                var_name(p[0]), A(p[3]), self.I(p[1]), self.I(p[2]))
        if op == 'EW_FPUTS':
            # exec.c: [handle var, value, writeCodPt, ?]  writeCodPt 0 = text, 1 = byte, 2 = word
            wcp = self.I(p[2])
            if wcp == 1:
                return 'FileWriteByte %s %d' % (var_name(p[0]), self.I(p[1]))
            if wcp == 2:
                return 'FileWriteWord %s %d' % (var_name(p[0]), self.I(p[1]))
            return 'FileWrite %s %s' % (var_name(p[0]), A(p[1]))
        if op == 'EW_FPUTWS':
            return 'FileWriteUTF16LE %s %s' % (var_name(p[0]), A(p[1]))
        if op == 'EW_FGETS':
            return 'FileRead %s %s %s' % (var_name(p[0]), A(p[1]), self.I(p[2]))
        if op == 'EW_FGETWS':
            return 'FileReadUTF16LE %s %s %s' % (var_name(p[0]), A(p[1]), self.I(p[2]))
        if op == 'EW_FSEEK':
            # exec.c: [handle var, optional result var, offset, mode(0=BEGIN,1=CUR,2=END)]
            res = '' if (p[1] & 0x80000000) else ' ' + var_name(p[1])
            mode = self.I(p[3])
            return 'FileSeek %s %s %s%s' % (var_name(p[0]), self.I(p[2]),
                                            {0: 'BEGIN', 1: 'CUR', 2: 'END'}.get(mode, str(mode)), res)
        if op == 'EW_FINDCLOSE':
            # exec.c: [handle var]
            return 'FindClose %s' % var_name(p[0])
        if op == 'EW_FINDNEXT':
            # exec.c: FindNext: [output name var, handle var]
            return 'FindNext %s %s' % (var_name(p[0]), var_name(p[1]))
        if op == 'EW_FINDFIRST':
            # exec.c: FindFirst: [output name var, output handle var, filespec]
            return 'FindFirst %s %s %s' % (var_name(p[0]), var_name(p[1]), A(p[2]))
        if op == 'EW_WRITEUNINSTALLER':
            # p[1] — смещение образа деинсталлятора относительно области данных
            return 'WriteUninstaller %s (data +0x%X)' % (S(p[0]), p[1])
        if op == 'EW_LOG':
            return 'LogSet/LogText %s %s' % (p[0], S(p[1]))
        if op == 'EW_SECTIONSET':
            return 'SectionSetText %d 0x%X %s' % (p[0], p[1], S(p[2]))
        if op == 'EW_INSTTYPESET':
            return 'InstTypeSetFlags %d 0x%X %s' % (p[0], p[1], S(p[2]))
        if op in ('EW_GETOSINFO', 'EW_GETLABELADDR', 'EW_GETFUNCTIONADDR'):
            return '%s %s' % (op[3:].capitalize(), ' '.join(S(x) for x in p if x))
        if op == 'EW_LOCKWINDOW':
            # exec.c EW_LOCKWINDOW: parm0 == 0 -> включить перерисовку
            return 'LockWindow %s' % ('off' if int(N(p[0])) == 0 else 'on')
        return '%s(%s)' % (op, ', '.join('0x%X' % x for x in p if x))

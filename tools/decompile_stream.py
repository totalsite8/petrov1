#!/usr/bin/env python3
"""Decompile an arbitrary NSISBI data stream (installer or its nested uninstaller)."""
import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nsisdec import NSIS, Dis  # noqa: E402

KEY = ('EW_EXTRACTFILE', 'EW_EXTRACTSTUBFILE', 'EW_CREATEDIR', 'EW_DELETEFILE', 'EW_RMDIR',
       'EW_WRITEREG', 'EW_DELREG', 'EW_EXECUTE', 'EW_EXECSHELL', 'EW_REGISTERDLL',
       'EW_MESSAGEBOX', 'EW_RENAME', 'EW_COPYFILES', 'EW_SHELLEXEC',
       'EW_WRITEUNINSTALLER', 'EW_CREATESHORTCUT', 'EW_FLAGFILE', 'EW_SETFILEATTRIBUTES',
       'EW_GETDLLVERSION', 'EW_REDIRECT' )


def run(stream_path, outdir, extractdir=None, writeuninstaller_only=False):
    s = open(stream_path, 'rb').read()
    n = NSIS(s)
    d = Dis(n)
    os.makedirs(outdir, exist_ok=True)

    starts = set(d.funcs) | set(d.cb)
    for sec in n.sections:
        starts.add(sec.code)
    starts.add(0)
    starts = sorted(x for x in starts if 0 <= x < len(n.entries)) + [len(n.entries)]
    names = dict(d.cb)
    for i in d.funcs:
        names.setdefault(i, 'Function_%d' % i)
    for idx, sec in enumerate(n.sections):
        names[sec.code] = 'SECTION_%d_%s' % (
            idx, (sec.name_inline or n.sstr(sec.name_ptr) or 'uninstall').replace(' ', '_'))

    head = ('NSISBI disassembly of %s\nstream %d B, entries %d, sections %d, pages %d, strings %d\n'
            'callbacks: %s\n\n' % (os.path.basename(stream_path), len(s), len(n.entries),
                                   len(n.sections), len(n.pages), len(n.strings.starts),
                                   ', '.join('%s@%d' % (v, k) for k, v in sorted(d.cb.items()))))
    lines = [head]
    for i in range(len(starts) - 1):
        a, b = starts[i], starts[i + 1]
        lines.append('\n===== %s   [entries %d..%d] =====' % (names.get(a, 'block_%d' % a), a, b - 1))
        for e in n.entries[a:b]:
            lines.append('%6d  %-18s %s' % (e.i, n.op(e), d.render(e)))
    open(outdir + '/functions.txt', 'w', encoding='utf-8').write('\n'.join(lines) + '\n')

    lines = [head]
    for e in n.entries:
        lines.append('%6d  %-18s %s' % (e.i, n.op(e), d.render(e)))
    open(outdir + '/disasm.txt', 'w', encoding='utf-8').write('\n'.join(lines) + '\n')

    lines = ['idx\ttext']
    for st in n.strings.starts:
        lines.append('%d\t%s' % (st, n.sstr(st).replace('\r', '\\r').replace('\n', '\\n')))
    open(outdir + '/strings.txt', 'w', encoding='utf-8').write('\n'.join(lines) + '\n')

    lines = [head]
    for i in range(len(starts) - 1):
        a, b = starts[i], starts[i + 1]
        rows = ['%6d  %s' % (e.i, d.render(e)) for e in n.entries[a:b] if n.op(e) in KEY]
        if rows:
            lines.append('\n===== %s =====' % names.get(a, 'block_%d' % a))
            lines.extend(rows)
    open(outdir + '/key_ops.txt', 'w', encoding='utf-8').write('\n'.join(lines) + '\n')

    rows = []
    for e in n.entries:
        if e.which != 20:
            continue
        off = n.data_off + e.p[2]
        size, = struct.unpack_from('<Q', s, off)
        comp = bool(size >> 63)
        size &= 0x7FFFFFFFFFFFFFFF
        data = s[off + 8:off + 8 + size]
        rows.append({'entry': e.i, 'name': n.sstr(e.p[1]), 'data_off': e.p[2], 'abs_off': off,
                     'size': size, 'compressed': comp, 'flags': e.p[0],
                     'sha256': hashlib.sha256(data).hexdigest()})
        if extractdir:
            os.makedirs(extractdir, exist_ok=True)
            name = os.path.basename(n.sstr(e.p[1]).replace('\\', '/')) or ('entry_%d.bin' % e.i)
            path = os.path.join(extractdir, name)
            if os.path.exists(path):
                old = open(path, 'rb').read()
                if old != data:
                    path = os.path.join(extractdir, 'entry_%d_%s' % (e.i, name))
            open(path, 'wb').write(data)
    open(outdir + '/payload_files.json', 'w', encoding='utf-8').write(
        json.dumps(rows, indent=1, ensure_ascii=False))
    print('%s: entries=%d sections=%d files=%d datbase=%d' %
          (stream_path, len(n.entries), len(n.sections), len(rows), n.data_off))
    return n, d


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2],
        sys.argv[3] if len(sys.argv) > 3 else None)

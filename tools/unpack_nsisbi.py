#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Распаковщик NSISBI (NSIS 3.x, 64-битный вариант).

Извлекает из установщика Amiconnect сжатый «поток данных» (stream), из которого
состоит скрипт установки, а также вложенный поток деинсталлятора.

Формат (определён экспериментально для этого файла и сверен с исходниками NSISBI
Source/exehead/*.c, Source/*.cpp):

  * в файле есть подпись  0xDEADBEEF 'NullsoftInst' (14 байт), за ней
    firstheader (flags u32, siginfo u32), а начиная со смещения sig+32 идут
    блоки LZMA:
        u24 length | 5 байт свойств LZMA1 | (length-5) байт «сырого» LZMA1-потока,
    где length отсчитывается от байта свойств (т.е. блок занимает 3+length байт)
  * результат склейки всех блоков — «поток NSISBI»:
        u64 length_of_header
        u32 flags
        8 * (u64 offset | u32 num)      — дескрипторы блоков
        header (поля: ключ реестра, callback-и, инсталляционные типы и т.д.)
        pages / sections / entries / strings / langtables / ctlcolors
        упакованные файлы (каждый: u64 размер | данные)
  * записи инструкций (entries) — 36 байт: u32 which + 8 * u32 параметров;
    смещения переходов/label-ов и смещения данных отсчитываются от начала потока.
  * инструкция EW_WRITEUNINSTALLER(64) содержит абсолютное смещение вложенного
    «потока деинсталлятора» (тот же самый формат, с собственной подписью).

Использование:
    python3 unpack_nsisbi.py Amiconnect_1_30_3004_Win.exe [-o outdir]
"""

import argparse
import lzma
import os
import struct
import sys

SIGNATURE = b'\xef\xbe\xad\xdeNullsoftInst'   # 0xDEADBEEF + 'NullsoftInst'
H = 8                     # размер поля length_of_header в начале потока
EW_EXTRACTFILE = 20
EW_WRITEUNINSTALLER = 64


def lzma_filter(props5):
    b = props5[0]
    lc = b % 9
    rest = b // 9
    lp = rest % 5
    pb = rest // 5
    dict_size = int.from_bytes(props5[1:5], 'little')
    return dict(id=lzma.FILTER_LZMA1, lc=lc, lp=lp, pb=pb,
                dict_size=max(dict_size, 4096))


def walk_chunks(data, off, limit=None):
    """Разжимает подряд идущие LZMA-блоки NSISBI, начиная со смещения off."""
    out = []
    total = 0
    while off + 8 <= len(data) and (limit is None or total < limit):
        ln = int.from_bytes(data[off:off + 3], 'little')
        props = data[off + 3:off + 8]
        body = data[off + 8:off + 3 + ln]
        if ln <= 5 or not body:
            break
        try:
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                        filters=[lzma_filter(props)])
            chunk = dec.decompress(body)
        except lzma.LZMAError:
            break                                # хвост может быть неполным
        out.append(chunk)
        total += len(chunk)
        off += 3 + ln
    return b''.join(out), off


def find_chunk_base(data, sig_off):
    """Первое смещение после подписи, с которого начинается корректный LZMA-блок."""
    for cand in range(sig_off + 13, sig_off + 64):
        if cand + 8 > len(data):
            break
        ln = int.from_bytes(data[cand:cand + 3], 'little')
        lc = data[cand + 3] % 9
        if 5 < ln and cand + 3 + ln <= len(data):
            try:
                lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                      filters=[lzma_filter(data[cand + 3:cand + 8])]
                                      ).decompress(data[cand + 8:cand + 3 + ln])
                return cand
            except lzma.LZMAError:
                continue
    return None


def stream_layout(stream):
    """Разбирает верхний уровень потока NSISBI: дескрипторы блоков + записи."""
    length_of_header, = struct.unpack_from('<Q', stream, 0)   # смещение области данных
    flags, = struct.unpack_from('<I', stream, 8)
    blocks = []
    off = 12
    for _ in range(8):
        lo, hi, num = struct.unpack_from('<III', stream, off)
        blocks.append({'off': lo | (hi << 32), 'num': num})
        off += 12
    entries = blocks[2]
    count = entries['num']
    eoff = H + entries['off']
    return {'length_of_header': length_of_header, 'flags': flags, 'blocks': blocks,
            'entries': [{'which': struct.unpack_from('<I', stream, eoff + 36 * i)[0],
                         'params': list(struct.unpack_from('<8I', stream, eoff + 36 * i + 4))}
                        for i in range(count)]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('installer')
    ap.add_argument('-o', '--outdir', default='.')
    args = ap.parse_args()

    data = open(args.installer, 'rb').read()
    os.makedirs(args.outdir, exist_ok=True)

    sig = data.find(SIGNATURE)
    if sig < 0:
        sys.exit('подпись NSISBI не найдена')
    base = find_chunk_base(data, sig)
    if base is None:
        sys.exit('не удалось найти начало LZMA-блоков')
    stream, end = walk_chunks(data, base)
    print('подпись NSISBI      : %#x' % sig)
    print('начало LZMA-блоков  : %#x' % base)
    print('поток установщика   : %d байт (до %#x, размер файла %#x)' % (len(stream), end, len(data)))
    out = os.path.join(args.outdir, 'installer_stream.bin')
    open(out, 'wb').write(stream)

    lay = stream_layout(stream)
    data_base = 8 + lay['length_of_header']
    files = 0
    for e in lay['entries']:
        if e['which'] == EW_EXTRACTFILE:
            files += 1
    print('записей инструкций  : %d' % len(lay['entries']))
    print('упакованных файлов  : %d' % files)
    print('область данных      : %#x' % data_base)
    print('-> %s' % out)

    # вложенный поток деинсталлятора
    for e in lay['entries']:
        if e['which'] == EW_WRITEUNINSTALLER:
            rel = e['params'][1]
            region = stream[data_base + rel:]
            sig2 = region.find(SIGNATURE)
            if sig2 < 0:
                print('!! вложенная подпись не найдена (смещение %#x)' % (data_base + rel))
                break
            base2 = find_chunk_base(region, sig2)
            nested, end2 = walk_chunks(region, base2)
            path = os.path.join(args.outdir, 'uninstaller_stream.bin')
            open(path, 'wb').write(nested)
            print('деинсталлятор       : смещение в потоке %#x, подпись %#x, %d байт'
                  % (data_base + rel, sig2, len(nested)))
            print('-> %s' % path)
            break
    return 0


if __name__ == '__main__':
    sys.exit(main())

from __future__ import annotations

import contextlib
import base64
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/generate-third-party-notices.py"


def load_generator():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("notice_generator", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load notice generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


generator = load_generator()


def compressed_fixture(encoded: str) -> bytes:
    return zlib.decompress(base64.b64decode(encoded, validate=True))


FFMPEG_ISC_NOTICE = compressed_fixture(
    'eNqtlFFP2zAUhd/3K6542lCXoYqhCdBUN3VaS0nc2S6IR9O4rbfWrhwH6L/fdSgw9kwemtzknu+eexL16vQjj09X'
    'p/D048K6Zabb3WW6Bn3fxqCX0XoHW30wAZs+embu94dg15sIn/MvMDw7+/51eDY8h6fhxTnsg/9tlhH7Uivp4saH'
    '9hJKH4yDyoRgY4TrbSp3oy571O3GunX0LjNN9zNpXo+ZccH+gWnQO2cCXG/6erR+rrOl373vJw4xUNkY/Eo7/wDX'
    '425d6TaaMHI6+CYL/00oMCYN061uE3+VqlHa4oWdmucm7GzbpkCjh641A1hiAAPY+cau8Kxd880HaCwmb++7aCBu'
    'bAutX8VHHQys8KF2h8Tad2HvWwOPNm4Ab6ez7yKsjAGUbEww9wfABV00zSBl+WAb0yBQR/wx+Hr9g0mk5es7cD7a'
    'pUkunufu3/y+PNrvjQ5gHejtNimtabPjdmpGQfJC3RJBgUmYC37DJnQCJ0RifQKknvRNZKFmXMCEybwkrJJAyhJQ'
    'JUitGJWJdcvUDASdEoESjirkvbHrvFxMWD3thayalwynvAGAF4lRUZHP8A4Zs5Kpu358wVRNpcyQATUHekNrBXKW'
    'OP84G1MoGRmXFAou+m+vvgM5pzkj5QB9C5qrASJerlCS81rSXwvEYQ9MSEWmyYjopceyX2xGlOQ4V+B6clGqtEYh'
    'eAUll8k5LCTFGUSRpMYM0bIcoI6iQZF8k7q3lCvG6yTA0UqQ5KOm05JNaZ3TpOW9QHGBjQt5FAyACCbTUL5Qx6B4'
    'j0VMTZ+hffopD/TSu6ACg6hIDy7ev43so/8V/gIrQE6g'
)

X264_ISC_NOTICE = compressed_fixture(
    'eNqtlFFP2zAUhd/3K6542lCXoWqgCdBUN3VbS0nc2S6IR5O4rbfWrhwH6L/fdSgw9kwemtzknu+eexL16vQjj09X'
    'p/D048K6OtPt7hKehhff8QL0fRuDrqP1Drb6YAI2fvTc3O8Pwa43ET7nX2B4dnb+dXg2PO89wD7436aO2JdaSRc3'
    'PrSXUPhgHJQmBBsjXG9TuRt12aNuN9ato3eZabqfSfN6zI0L9g/Mgt45E+B609ej9XOd1X73vp84xEBpY/Ar7fwD'
    'XI+7danbaMLI6eCbLPw3YYoxaZhtdZv4q1SN0hYv7NS8MGFn2zYFGj10rRlAjQEMYOcbu8Kzds03H6CxmLy976KB'
    'uLEttH4VH3UwsMKH2h0Sa9+FvW8NPNq4Abydzr6LsDIGULIxwdwfABd00TSDlOWDbUyDQB3xx+Dr9Q8mkerXd+B8'
    'tLVJLp7n7t/8vjza740OYB3o7TYprWmz43ZqTkHyqbolggKTsBD8hk3oBE6IxPoESDXpm8hSzbmACZN5QVgpgRQF'
    'oEqQSjEqE+uWqTkIOiMCJRxVyHtjV3mxnLBq1gtZuSgYTnkDAJ8mRklFPsc7ZMwKpu768VOmKiplhgyoONAbWimQ'
    '88T5x9mYQsHIuKAw5aL/9qo7kAuaM1IM0LeguRog4uUKJTmvJP21RBz2wISUZJaMiF56LPvF5kRJjnMFrieXhUpr'
    'TAUvoeAyOYelpDiDKJLUmCFalgPUUTQokm9S9ZZyxXiVBDhaCZJ8VHRWsBmtcpq0vBcoLrBxKY+CARDBZBrKl+oY'
    'FO+xiKnoM7RPP+WBXnoXVGAQJenB0/dvI/vof4W/47FQEA=='
)

IJG_INT_NOTICE = compressed_fixture(
    'eNp9VttOHDkQfd+vKPESiHomgkgr2DzNQhZNlAsCpGgfPe7qGQe33fEFmHz9nrJ7LkzQvsB0t33q+NSpKr97+we9'
    'pfuVidQZy4T/gwqJfEdpxTR3LQ+MPy7Rp5uP13QdfB7eRIq+S08q8BTbKwKTymnlQ6RePTB9/UbfZ7e3s6/3/5IP'
    'FHgIHAGjkvGuITaAD8TP8jrKCtMP1nDbCNoTvmJLHFgnSh5UzC5kQyZF+pmVNWndkNI6B6Xxq+egVwohFqZ+8kHA'
    'OpOcxOgQRJXTGZ2tCjTkMPjIU6rn3+AXDYJ/NC23dDS7o/ndEcK4VsDWPtf4OXLA2xhzz0UqnM1gczDxAa+F9R5N'
    '2b5lutPsIKr2wzqY5SrR8eUJnV5cnE7w588GK30PzOspfVauaE4za+lW1ka6hbDhEWT5WfOQJLooZzrISQu2/mkT'
    '8YZDb2JEBiQcEsCLNS0DNMNKMMahmsICYvrWdOtybmpNTMEscuKSCUHa0j6GqoMPktUoOgT23UnV2q03Ejcloz4n'
    '6hgPMS9+1MwKFDZFRlTXmoLyl7w8Pj2heVcx9vwYfQ5aFrdcYqRDCXdU20Z2uBoBX24/zq6+fKwu73NMUIaM0za3'
    'srQ4rqzbJUGO7vwE0KLQWpCch3mYslM24ajth5pYsFTtSL+hli2PP0FRLLnkWG3MeGOWBturMy0+bMhoyyrYNUi1'
    'RivJiHHiGd8PCGDcklqv4baxhooLjs+KTN5hHz+zzjC/HfV5TY1CYR9TQF7AVjoRD5JslejoN40XKlZyNTMV9MmH'
    'BwH738ZxVEm/P9l3ouQRxqs7D0JtvFkOaCq0VJ6cAVYvVuwySkGaBRQ3tfS3/stgEE0YRXGRf2Z2muOHKsTYsCqY'
    'YKFrfZ7P/p5/nqNtCUireiXZ89WLD0jOXst74VtSwwCWyLOs3J6i5WCkOLvge/FDVW9Ubf7pWqAkX42Yi36I+qNV'
    'sitFKFVszSKosEarQrbRg6pgORTZm/LGZ3i2uB0E9IPzT5bbpcj1evV//Xa/lbeWEm/SIPzBbNQH3d6pnouXq29K'
    'JcgrMWj7yKj+KP6UVpAX1mhJQWALQ+HtYf8uy4Jvs675eyGQSb+1416tpTwCdxxC7VPFDmhzRwdWE7hXx9TRRoPv'
    'vOmNWlmADKJJLXUYA4oi2/tSvGSuSouTFNYuiAWQROaOUXZ7qGY3PkoFIRBtmogc3ppxQqHklelhnMCCVocJWva6'
    'RBnh6BFn8+HF0ChNDM5LyojvKKLHT1DmkzpikmQm8ZLrVOVdcdfqLFXjAzi1dHV5T8dXJurA2HbpkUime3CNWNGf'
    'bMLO6GxyVRZr5SQdrcc6MD0dXwOclcbU9k/AtiBUTzJ+L2qNS7S3uXfI8xUGphZ9luiKaVWVwGOEgx+VsVK2DeFc'
    'Qnq9kanPwOh94GJHy88le5G5LxUEe4CeWLhTEU2anqTvwThZV/NIsb1Q80CjbYfDb5x1yw5GhUpmUXqfbCa6xED2'
    '3HVW7gIzPJhlYrfgsCycMK+/+KhX6/SroaMbzP4ktqN/QGxfGMI030pQJtHpKX3JNhlciXRhFXEFuQleT2H39MZO'
    'kSnXTYXiDK6NwI1NhbobmPWqDu47s8SoKRtxA5JiPL04v6Dj+eXs7u6G3pxfnMCsw5Quzs8nuG5MN1e5IZge/ebV'
    'w5chL/URhWY/0sSTRDy7kElYWo7UmlQR1ht0YxmYTqzZM7pKO57z7BDg/dkOoFwq20e50i131TjuN7FWl/No0kku'
    'dmm1q4niD3yH5d3omn05P1QoJT6VAkIPQ8suRti7qkkdHXijJD4iidKwzDO3k8Gj1uBNUQljX493CUW9cRDRkss9'
    'HCH048p0qRzt3X+US+k/'
)

IJG_FAST_NOTICE = compressed_fixture(
    'eNp9Vtty2zYQfe9X7PghlTKSU6VJGydPqq1mlEkcj+OZTB8hcikhBgkGIGSrX9+zC1IXJ9MXWySBvZxz9vLi+S/0'
    'nO42NlJlHRP+tyZ05CvqNkzLpuSW8afp6MPN4j29Dz61v0aKvuoeTOBzXM8WmEzqNj5Eqs090/Vn+jq/vZ1f3/1D'
    'PlDgNnCEGdNZ30yILcwH4kd5HeWErVtnuZyItQd8xZXYctFR5xGKPbickO0ifU/G2W43IVMUKZgCv2oOxcbAxcrm'
    'Tz6Iscp2jfio4MRodrZIzgRqU2h95HPK+Q/2FYPgt7bkks7mX2j55QxumlKM7XzK/lPkgLcxppoVKuRmcTnYeI/X'
    'EvVRmHJ9H+kBsydeC9/ugl1vOhpdjml2cfFqij9/THDS17D5/pw+mkYxp7lzdCtnI90C2LBFsPxYcNuJd0HOVoCT'
    'Vuz8w+DxhkNtYwQD4g4E8GpH6wDMcBIRI6mJRgEwfWmrneZNpY1dsKvUsTIhlvZhj4Bq64OwGgWHwL4aZ6yb3QDx'
    'RBn1qaOK8RDT6ltmVkzhUmR4bUqrVt7Ky9FsTMsq2zjSY/QpFHK4ZPXRPYXwEGo5kRtN9oAvt4v51adFVnmdYgdk'
    'yDaFS6UcVcXpuQMJknrjpzAtCO3EUuMhHqbUGNch1fJdJhZRmrIPf0IlO+5/IkSR5JpjljHjjV1bXM/KdPgwBFM4'
    'NsHtEFRpCyOM2EY04+sWDmyzptIXUFtfQ6qC0UuFyTe4x49cJIjf9fj8DA0N4dimGDkxm8OJeBCyTUdnP2C8MjEH'
    'l5nJRh98uBdj/9s4znLQv4+PlSg8Qnj55hNXgzY1QZtNS+VJDpC6SrFKKAVpFkDc5tLf6y8hgmhDD0oT+XvipuD4'
    'LgPRN6xsTGyha31czv9aflyibYmR0tRG2PNZi/cg56jlneiWTNsiSvAsJ/dZlBysFGcVfC16yOj1qC0/vBdTwtdE'
    'xEXfBP1eKqnRIpQqdnYVTNihVYFt9KAMWAoK+0Tf+ATNqtoRQHHf+AfH5Vrg+nn1X3++28ObS4kHGiR+RNbjg27f'
    'mJpVy1k3WgnySgRabhnVH0Wf0grSytlCKAjsICi8fdq/9VjwZSoyfycA2e6HdlybnZRH4IpDyH1K5YA2d/ZEamLu'
    'p2PqbMDgKw+9sTAORlrBJJc6hAFEwfYxFKeRG21xQmHugjgASGTuWOP2SU0O40MrCI5oaCKSvLP9hELJG1tDOIHF'
    'Wh4maNk79dKboy1y8+FkaGgTg/I6Y0V3VJnYZf1E34+ZTtjpeM15svKhwHOFauX4gLhKurq8o9GVjUVgXLv0IJPp'
    'DvFGnKjHg+s5vZxe6eHCNEJJ6XEO0c761zDOpsDk9g+w7TB4cjb9d0WsP1J4l+oGXF9haBaC0RqdsdtkNPAoiWyN'
    'dVK6E0ILk6B3A1R1go3aB1ZJOn5UBiNzrShAIghPZCzIAIIH6X0QTyqygKTgThB9gtG+y+H3PBg7ofk62TwNr829'
    '+WZrA3ntoxYodSxCVayAqozZhn3DR7eE2GikuJ7TcrG8XNBi+udsNJuN385+u3g9FrdWJ9YHgzrjeMj8yJX0dQZX'
    'dpW7sHy94abhFfauQM/ok+2KDTu3r4aOH7uV9/c0AkIYhH8vbhfXl4svAKzI6TZZUnlGjnPsPYVSwgKXWNvDUipr'
    'qB/p33adQMSr6Ruxc/Pskzb5rxsxCJ28mbYeShx0I/QM0sFxJ5sZqqSh2Qysus7KFhhlx6JcY9gf0NZhS/qaFFFf'
    'oEJ86umKPldaLZT3E+hgbBBNVJKVIyQVh4OVsoPlBOZiTj2eXBe16/Bc9VXjSkW+b9PDycLkMSBTw25t1Ie+lpUG'
    '7ILYEf/VY9qodSxBcwFeeszn82fXWGTRd9H02Wxl9Eize32SD1T48kJWjtg3/CNExZ1gje2TXXU+LOdtgGTDTlYC'
    'tGzZkteHBtc7tDHDqMtQZR+57LmrTbfRxXxYYeWo8xhVZVJigCwEYSM/WfT3e5vWhVg4BoG2xqV96rFGo+Q8iE5O'
    'HXDa6RajolFp9D4PHrLFSRbEj2VdeqCHkYk7muMGe960j0oa8jRypzMrb2aqSz2IOpgOqzxw1pH64j+3x4fq'
)

IJG_REV_NOTICE = compressed_fixture(
    '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'
)

LAME_FFTTBL_SOURCE = compressed_fixture(
    'eNrtlU1r1FAUhte5v+JSEFqYtvfcz3PsqnRRSheFStclnWRmgtOkNCPan1OYuFV0VbG6ELXdCYI/wiou3LrwjG0+'
    'WlyICxExhOTmOXnPOfe9l0SsRIPiUObpfbm+tb61mBeL/SKJ5TwQ0bKiBbESrRUHR4fZcDSR82sLchaQ5SgbpgXH'
    'yoO0n8VjORnF+d1STgq5s72zvdGTm2mW9UeZvLO6ubohBL86GExkmeW9flH2hofxUfXm+Hn1obrg0KwULmu4GvIJ'
    '89OH04vpx4Xj4+p99ao6O3v5+kWtePbl9FvzKlhZPa4+VdPqKUfP+f61esuKR9XJ+SlHPjN9V108ORXiVpb3x/eS'
    'VM7lcbm/NJoTIhqOi714nKSDiPuaxHu73GaXcsc/obP+d7M8SR9wijId7qf5ZDeJJ7GI4nE2zCV4IdqEt0WUJFIt'
    'qc5xhYIKoHxAAAxXiLTBQM5oB1AjVAGdRmWVqRE5QBu090E3aKazzmvlGkSeEAE9+RaRtkEBGuog7iBwBdNB5DQZ'
    'BNVFiNpYp7uIgnLorwm5grfeX0cIHm4g7lbZGwjRgRCt75fmwS+aZ1B7NNZo42sPgJwiZbRWTXnFhkIAdtPUuZQl'
    'TuUDS+tcSltnQWt2vp6d4scAjqtgk0t5MA7ReksNMpyLHOdrhIpVZla2I1TBe+LWoBUqw93PlhZbBATBBkehs43I'
    'YTCBOkJlAxlPbI6I2l3Y7lT2MUr2It2Tpif5an9cL8euM+5y/xua8Ifq4D82H/q/Pn/1fEB1vvX8k0z5Mc0T8R1l'
    'taDb'
)

SHARED_NOTICE = b"""/* Copyright (c) Shared Author
 * Permission is granted to redistribute this source.
 * This software is provided without warranty.
 */"""


class NoticeGeneratorTest(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def _write(root: Path, relative: str, data: bytes) -> None:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    @staticmethod
    def _lame_unsafe_block() -> bytes:
        seen = []
        original = generator._append_safe_block

        def observe(blocks, raw, source, file_sha256):  # type: ignore[no-untyped-def]
            seen.append(raw)
            return original(blocks, raw, source, file_sha256)

        with mock.patch.object(generator, "_append_safe_block", side_effect=observe):
            generator._extract_leading_blocks(
                LAME_FFTTBL_SOURCE,
                frozenset({"at", "c", "slash", "semicolon"}),
                generator.SourceRef("LAME", "libmp3lame/i386/ffttbl.nas"),
            )
        matching = [
            block
            for block in seen
            if hashlib.sha256(block).hexdigest()
            == "87077eb1b86cef850a07bb7b2aa4a87c7947ab245f9b22f769588fb392d4b541"
        ]
        if len(matching) != 1:
            raise AssertionError("authentic LAME unsafe fixture block is missing")
        return matching[0]

    def make_sources(
        self, base: Path, reverse: bool = False
    ) -> tuple[Path, Path, Path, Path, Path]:
        ffmpeg = base / "ffmpeg"
        x264 = base / "x264"
        lame = base / "lame"
        musl = base / "musl"
        fortify = base / "fortify-headers"
        ffmpeg.mkdir(parents=True)
        x264.mkdir()
        lame.mkdir()
        musl.mkdir()
        fortify.mkdir()
        files = [
            (
                ffmpeg,
                "libavutil/x86/x86inc.asm",
                FFMPEG_ISC_NOTICE + b"%define CODE 1\n",
            ),
            (
                x264,
                "common/x86/x86inc.asm",
                X264_ISC_NOTICE + b"%define CODE 2\n",
            ),
            (
                ffmpeg,
                "libavcodec/jfdctint_template.c",
                IJG_INT_NOTICE + b"\nint a;\n",
            ),
            (
                ffmpeg,
                "libavcodec/jfdctfst.c",
                IJG_FAST_NOTICE + b"\nint b;\n",
            ),
            (
                ffmpeg,
                "libavcodec/jrevdct.c",
                IJG_REV_NOTICE + b"\nint c;\n",
            ),
            (
                ffmpeg,
                "libswscale/filters.c",
                b"/* Copyright FFmpeg fixture */\nint before;\n\n"
                b"/*\n"
                b" * Some of the filter code originally derives (via libplacebo/mpv) from Glumpy:\n"
                b" * # Copyright (c) 2009-2016 Nicolas P. Rougier. All rights reserved.\n"
                b" * # Distributed under the (new) BSD License.\n"
                b" * (https://github.com/glumpy/glumpy/blob/master/glumpy/library/"
                b"build-spatial-filters.py)\n"
                b" *\n"
                b" * The math underlying each filter function was written from scratch.\n"
                b" */\nint after;\n",
            ),
            (ffmpeg, "z-last.c", SHARED_NOTICE + b"\nint z;\n"),
            (
                ffmpeg,
                "libavcodec/arm/example.S",
                b"@ Copyright ARM Author\n@ Permission to redistribute.\n\n.text\n",
            ),
            (
                x264,
                "gpu/example.cu",
                b"// Copyright GPU Author\n// Permission to redistribute.\n\nint gpu;\n",
            ),
            (
                ffmpeg,
                "doc/helper.pm",
                b"# Copyright Perl Module Author\n# Permission to redistribute.\n\n1;\n",
            ),
            (lame, "a-first.c", SHARED_NOTICE + b"\nint a;\n"),
            (
                lame,
                "zero-bsd.c",
                b"/* Copyright (c) Zero-Clause Author\n"
                b" * Permission to use, copy, modify, and/or distribute this software\n"
                b" * for any purpose with or without fee is hereby granted.\n"
                b" * THE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL\n"
                b" * WARRANTIES. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DAMAGES.\n"
                b" */\nint zero_bsd;\n",
            ),
            (
                lame,
                "legacy/example.nas",
                b"; Copyright Assembly Author\n; Permission to redistribute.\n\nBITS 32\n",
            ),
            (
                lame,
                "script.sh",
                b"#!/bin/sh\n\n# Copyright Example\n# Permission to redistribute.\n\nexec true\n",
            ),
            (
                lame,
                "extensionless-helper",
                b"#!/bin/sh\n# Copyright Helper Author\n# Permission to redistribute.\n\nexit 0\n",
            ),
            (lame, "ignored.bin", b"\x00\xff not source text"),
            (lame, "libmp3lame/i386/ffttbl.nas", LAME_FFTTBL_SOURCE),
            (
                musl,
                "src/crypt/crypt_blowfish.c",
                b"/*\n"
                b" * Written by Solar Designer in 1998-2012.\n"
                b" * No copyright is claimed; software is hereby placed in the public\n"
                b" * domain.\n"
                b" * Copyright (c) 1998-2014 Solar Designer.\n"
                b" * Redistribution and use in source and binary forms are permitted.\n"
                b" * There's ABSOLUTELY NO WARRANTY, express or implied.\n"
                b" */\nint crypt_fixture;\n",
            ),
            (
                fortify,
                "include/fortify-headers.h",
                b"/*\n"
                b" * Copyright (C) 2015-2016 Dimitris Papastamos\n"
                b" * Copyright (C) 2022 q66\n"
                b" * Permission to use, copy, modify, and/or distribute this software.\n"
                b" * THE SOFTWARE IS PROVIDED \"AS IS\".\n"
                b" * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION.\n"
                b" */\nint fortify_fixture;\n",
            ),
        ]
        if reverse:
            files.reverse()
        for root, relative, data in files:
            self._write(root, relative, data)
        return ffmpeg, x264, lame, musl, fortify

    def test_deterministic_inventory_deduplication_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as first_name, tempfile.TemporaryDirectory() as second_name:
            first = self.make_sources(Path(first_name), reverse=False)
            second = self.make_sources(Path(second_name), reverse=True)
            first_result = generator.generate(*first)
            second_result = generator.generate(*second)

        self.assertEqual(first_result.data, second_result.data)
        self.assertEqual(first_result.sha256, second_result.sha256)
        self.assertEqual(first_result.stats.isc_blocks, 2)
        self.assertEqual(first_result.stats.ijg_blocks, 3)
        self.assertEqual(first_result.stats.glumpy_blocks, 1)
        for notice in (
            FFMPEG_ISC_NOTICE,
            X264_ISC_NOTICE,
            IJG_INT_NOTICE,
            IJG_FAST_NOTICE,
            IJG_REV_NOTICE,
        ):
            self.assertEqual(first_result.data.count(notice), 1)
        self.assertEqual(first_result.data.count(SHARED_NOTICE), 1)
        rendered = first_result.data.decode("utf-8")
        self.assertIn("  - FFmpeg: libavutil/x86/x86inc.asm\n", rendered)
        self.assertIn("  - x264: common/x86/x86inc.asm\n", rendered)
        self.assertIn("  - FFmpeg: z-last.c\n  - LAME: a-first.c\n", rendered)
        self.assertIn("  - musl: src/crypt/crypt_blowfish.c\n", rendered)
        self.assertIn(
            "  - fortify-headers: include/fortify-headers.h\n", rendered
        )
        self.assertIn("  - FFmpeg: libswscale/filters.c\n", rendered)
        self.assertIn("  - FFmpeg: doc/helper.pm\n", rendered)
        self.assertIn("  - controlled-Glumpy: LICENSE.txt\n", rendered)
        self.assertIn("  - LAME: zero-bsd.c\n", rendered)
        self.assertIn("Complete ISC-form occurrences: 2\n", rendered)
        self.assertIn("Distributed under the (new) BSD License", rendered)
        self.assertIn("Neither the name of Nicolas P. Rougier", rendered)
        self.assertIn("Raw-Bytes: ", rendered)
        self.assertIn("Ends-With-Newline: yes\n", rendered)
        self.assertIn("Ends-With-Newline: no\n", rendered)
        self.assertIn(
            "does not determine an artifact's effective\nor concluded license",
            rendered,
        )
        self.assertIn("does not authenticate those inputs", rendered)
        self.assertIn(
            "Controlled Glumpy BSD-3-Clause SHA-256: "
            "0c52c60c6765db44c846b5acd2533652b73db55c2d50415d1a0bca0c7eeabad3",
            rendered,
        )

    def test_cli_requires_five_roots_and_writes_atomic_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            base = Path(directory_name)
            sources = self.make_sources(base / "input")
            ffmpeg, x264, lame, musl, fortify = sources
            output = base / "THIRD-PARTY-NOTICES.txt"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = generator.main(
                    [
                        "--ffmpeg",
                        str(ffmpeg),
                        "--x264",
                        str(x264),
                        "--lame",
                        str(lame),
                        "--musl",
                        str(musl),
                        "--fortify-headers",
                        str(fortify),
                        "--output",
                        str(output),
                    ]
                )
            summary = json.loads(stdout.getvalue())
            expected = generator.generate(*sources)

            self.assertEqual(status, 0)
            self.assertEqual(output.read_bytes(), expected.data)
            self.assertEqual(summary["sha256"], expected.sha256)
            self.assertEqual(summary["ijgBlocks"], 3)
            self.assertEqual(summary["glumpyBlocks"], 1)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)

    def test_rejects_symlinks_unsafe_paths_and_special_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            sources = self.make_sources(Path(directory_name))
            lame = sources[2]
            target = lame / "ordinary.txt"
            target.write_text("ordinary\n", encoding="utf-8")
            (lame / "escape.bin").symlink_to(target)
            with self.assertRaisesRegex(generator.NoticeError, "symbolic link"):
                generator.generate(*sources)

        with tempfile.TemporaryDirectory() as directory_name:
            sources = self.make_sources(Path(directory_name))
            self._write(sources[2], "bad\nname.c", SHARED_NOTICE)
            with self.assertRaisesRegex(generator.NoticeError, "unsafe path"):
                generator.generate(*sources)

        if hasattr(os, "mkfifo"):
            with tempfile.TemporaryDirectory() as directory_name:
                sources = self.make_sources(Path(directory_name))
                os.mkfifo(sources[2] / "named-pipe")
                with self.assertRaisesRegex(generator.NoticeError, "non-regular"):
                    generator.generate(*sources)

        with tempfile.TemporaryDirectory() as directory_name:
            sources = self.make_sources(Path(directory_name))
            deep = sources[2]
            for _index in range(generator.MAX_DIRECTORY_DEPTH + 1):
                deep = deep / "d"
                deep.mkdir()
            with self.assertRaisesRegex(generator.NoticeError, "directory-depth"):
                generator.generate(*sources)

    def test_non_utf8_exception_is_exact_and_everything_else_fails(self) -> None:
        cases = (
            (b"/* Copyright \xff */\nint value;\n", "not UTF-8"),
            (b"/* Copyright\x01 notice */\nint value;\n", "control characters"),
            (b"/* Copyright\rnotice */\nint value;\n", "control characters"),
            (b"\xff/* Copyright hidden */\n", "not UTF-8"),
            (b"\x01/* Copyright hidden */\n", "control characters"),
        )
        for data, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory_name:
                sources = self.make_sources(Path(directory_name))
                self._write(sources[2], "00-unsafe.c", data)
                with self.assertRaisesRegex(generator.NoticeError, message):
                    generator.generate(*sources)

        with tempfile.TemporaryDirectory() as directory_name:
            sources = self.make_sources(Path(directory_name))
            # The exact authenticated exception succeeds in the ordinary fixture.
            generator.generate(*sources)
            path = sources[2] / "libmp3lame/i386/ffttbl.nas"
            changed = bytearray(path.read_bytes())
            changed[-2] ^= 1
            path.write_bytes(changed)
            with self.assertRaisesRegex(generator.NoticeError, "not UTF-8"):
                generator.generate(*sources)

        with tempfile.TemporaryDirectory() as directory_name:
            sources = self.make_sources(Path(directory_name))
            path = sources[2] / "libmp3lame/i386/ffttbl.nas"
            unsafe = self._lame_unsafe_block()
            changed = bytearray(path.read_bytes())
            start = changed.find(unsafe)
            self.assertGreaterEqual(start, 0)
            unsafe_byte = unsafe.find(b"\xa5")
            self.assertGreaterEqual(unsafe_byte, 0)
            changed[start + unsafe_byte] ^= 1
            path.write_bytes(changed)
            with self.assertRaisesRegex(generator.NoticeError, "not UTF-8"):
                generator.generate(*sources)

        with tempfile.TemporaryDirectory() as directory_name:
            sources = self.make_sources(Path(directory_name))
            self._write(sources[2], "copied-unsafe.nas", LAME_FFTTBL_SOURCE)
            with self.assertRaisesRegex(generator.NoticeError, "not UTF-8"):
                generator.generate(*sources)

    def test_collection_budgets_reject_before_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            sources = self.make_sources(Path(directory_name))
            oversized = sources[2] / "oversized.dat"
            with oversized.open("wb") as stream:
                stream.truncate(generator.MAX_SOURCE_FILE_BYTES + 1)
            with self.assertRaisesRegex(generator.NoticeError, "too large"):
                generator.generate(*sources)

        with tempfile.TemporaryDirectory() as directory_name:
            sources = self.make_sources(Path(directory_name))
            controlled_cost = (
                len(generator._GLUMPY_CONTROLLED_LICENSE)
                + len(generator._GLUMPY_LICENSE_SOURCE.component.encode("utf-8"))
                + len(generator._GLUMPY_LICENSE_SOURCE.path.encode("utf-8"))
                + 512
            )
            # Enough for the controlled notice and the first tree's first block,
            # but not for all five trees.  Collection must stop before rendering.
            with mock.patch.object(
                generator, "MAX_RETAINED_NOTICE_BYTES", controlled_cost + 1800
            ), mock.patch.object(generator, "_render") as render:
                with self.assertRaisesRegex(generator.NoticeError, "memory budget"):
                    generator.generate(*sources)
                render.assert_not_called()

        with tempfile.TemporaryDirectory() as directory_name:
            sources = self.make_sources(Path(directory_name))
            with mock.patch.object(generator, "MAX_OUTPUT_BYTES", 128):
                with self.assertRaisesRegex(generator.NoticeError, "output-size"):
                    generator.generate(*sources)

    def test_private_ancestor_and_output_path_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            base = Path(directory_name)
            sources = self.make_sources(base)
            roots = tuple(path.resolve(strict=True) for path in sources)
            with self.assertRaisesRegex(generator.NoticeError, "inside an input"):
                generator._validate_output(sources[0] / "notices.txt", roots)

            real_output = base / "real.txt"
            real_output.write_text("old\n", encoding="utf-8")
            linked_output = base / "linked.txt"
            linked_output.symlink_to(real_output)
            with self.assertRaisesRegex(generator.NoticeError, "not a link"):
                generator._validate_output(linked_output, roots)

        with tempfile.TemporaryDirectory(dir="/tmp") as directory_name:
            base = Path(directory_name)
            sources = self.make_sources(base / "inputs")
            base.chmod(0o755)
            try:
                with self.assertRaisesRegex(generator.NoticeError, "0700 ancestor"):
                    generator.generate(*sources)

                private_inputs = base / "private-inputs"
                private_sources = self.make_sources(private_inputs)
                private_inputs.chmod(0o700)
                roots = tuple(
                    path.resolve(strict=True) for path in private_sources
                )
                with self.assertRaisesRegex(generator.NoticeError, "0700 ancestor"):
                    generator._validate_output(base / "notices.txt", roots)
            finally:
                base.chmod(0o700)

    def test_locked_real_fixture_hashes(self) -> None:
        expected = (
            (
                FFMPEG_ISC_NOTICE,
                "28e1d08c3aab06bb2a0bf15365261cf8b371fe1ba8c4427b351e57429dd80e06",
            ),
            (
                X264_ISC_NOTICE,
                "33be636fa577611ee0b64d36abf21538b11ad8ec1deacffb5d31211f6d875ee2",
            ),
            (
                IJG_INT_NOTICE,
                "90da7eecd5d9e83cb5061af38fb56c4b99b975204f98d224249770c31812275a",
            ),
            (
                IJG_FAST_NOTICE,
                "f831f4602bd8c0446d5e26a4b14ddfa4581b95e4b61bb7cbb4697f22558e2e0f",
            ),
            (
                IJG_REV_NOTICE,
                "ee552ade15c696e8e75e9c1aa91193c8299ea3961e3510ab7667f9b3eea17123",
            ),
            (
                LAME_FFTTBL_SOURCE,
                "5ec4d552351881974d78d43b6f49502170ac77f112286c33837111069475ac26",
            ),
        )
        for fixture, digest in expected:
            with self.subTest(sha256=digest):
                self.assertEqual(hashlib.sha256(fixture).hexdigest(), digest)
        self.assertEqual(
            hashlib.sha256(self._lame_unsafe_block()).hexdigest(),
            "87077eb1b86cef850a07bb7b2aa4a87c7947ab245f9b22f769588fb392d4b541",
        )

    def test_exact_locked_first_blocks_reject_single_byte_changes(self) -> None:
        cases = (
            (0, "libavutil/x86/x86inc.asm"),
            (1, "common/x86/x86inc.asm"),
            (0, "libavcodec/jfdctint_template.c"),
            (0, "libavcodec/jfdctfst.c"),
            (0, "libavcodec/jrevdct.c"),
        )
        for root_index, relative in cases:
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as directory_name:
                sources = self.make_sources(Path(directory_name))
                path = sources[root_index] / relative
                changed = bytearray(path.read_bytes())
                position = changed.lower().find(b"copyright")
                self.assertGreaterEqual(position, 0)
                changed[position] ^= 1
                path.write_bytes(changed)
                with self.assertRaisesRegex(generator.NoticeError, "exact first notice"):
                    generator.generate(*sources)

    def test_missing_glumpy_musl_or_fortify_notice_fails_closed(self) -> None:
        cases = (
            (0, "libswscale/filters.c", b"/* no Glumpy attribution */\n"),
            (3, "src/crypt/crypt_blowfish.c", b"/* no musl notice */\n"),
            (4, "include/fortify-headers.h", b"/* no fortify notice */\n"),
        )
        for root_index, relative, replacement in cases:
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as directory_name:
                sources = self.make_sources(Path(directory_name))
                (sources[root_index] / relative).write_bytes(replacement)
                with self.assertRaises(generator.NoticeError):
                    generator.generate(*sources)


if __name__ == "__main__":
    unittest.main()

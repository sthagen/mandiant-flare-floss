import pathlib

import pytest

from floss.results import StaticString, StringEncoding
from floss.language.go.extract import extract_go_strings


@pytest.fixture(scope="module")
def go_strings32():
    n = 6
    path = pathlib.Path(__file__).parent / "data" / "src" / "go-hello" / "bin" / "go-hello.exe"
    return list(extract_go_strings(path, n))


@pytest.fixture(scope="module")
def go_strings64():
    n = 6
    path = pathlib.Path(__file__).parent / "data" / "src" / "go-hello" / "bin" / "go-hello64.exe"
    return list(extract_go_strings(path, n))


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .data:00534944 A0 35 4A 00                       dd offset aAdaptivestacks ; "adaptivestackstart"
        # .data:00534948 12                                db  12h
        pytest.param("adaptivestackstart", 0xA1BA0, StringEncoding.UTF8, "go_strings32"),
        # .data:00534944 A0 35 4A 00                       dd offset aAdaptivestacks ; "adaptivestackstart"
        # .data:00534948 12                                db  12h
        pytest.param("adaptivestackstart", 0xA9E33, StringEncoding.UTF8, "go_strings64"),
    ],
)
def test_data_string_offset(request, string, offset, encoding, go_strings):
    # .data:0000000000541568 33 A8 4A 00 00 00…                dq offset aAdaptivestacks ; "adaptivestackstart"
    # .data:0000000000541570 12                                db  12h
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:0048B12F 8D 05 F8 08 4C 00 lea     eax, off_4C08F8 ; "hello world"
        # .text:0048B135 89 44 24 24       mov     [esp+28h+var_4], eax
        pytest.param("hello world", 0xA03E1, StringEncoding.UTF8, "go_strings32"),
        # .text:000000000048DE46 48 8D 15 13 BB 03 00          lea     rdx, off_4C9960 ; "hello world"
        # .text:000000000048DE4D 48 89 54 24 30                mov     qword ptr [rsp+40h+var_18+8], rdx
        pytest.param("hello world", 0xA873A, StringEncoding.UTF8, "go_strings64"),
    ],
)
def test_lea_mov(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:000000000040428F 48 8D 05 2C 72 0A 00          lea     rax, aWriteOfGoPoint ; "write of Go pointer "
        # .text:0000000000404296 BB 14 00 00 00                mov     ebx, 14h
        # .text:000000000040429B 0F 1F 44 00 00                nop     dword ptr [rax+rax+00h]
        # .text:00000000004042A0 E8 DB 16 03 00                call    runtime_printstring
        pytest.param("write of Go pointer ", 0xAAAC2, StringEncoding.UTF8, "go_strings64"),
        # NOTE: no 32 bit test case for this one
    ],
)
def test_lea_mov2(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:00000000004032EA B9 1C 00 00 00                                mov     ecx, 1Ch
        # .text:00000000004032EF 48 89 C7                                      mov     rdi, rax
        # .text:00000000004032F2 48 89 DE                                      mov     rsi, rbx
        # .text:00000000004032F5 31 C0                                         xor     eax, eax
        # .text:00000000004032F7 48 8D 1D A6 A2 0A 00                          lea     rbx, unk_4AD5A4
        pytest.param("comparing uncomparable type ", 0xACBA4, StringEncoding.UTF8, "go_strings64"),
        # .text:00403276 8D 15 64 63 4A 00                             lea     edx, unk_4A6364
        # .text:0040327C 89 54 24 04                                   mov     [esp+1Ch+var_18], edx
        # .text:00403280 C7 44 24 08 1C 00 00 00                       mov     [esp+1Ch+var_14], 1Ch
        pytest.param("comparing uncomparable type ", 0xA4964, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_mov_lea(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:00000000004467E4 48 8D 05 7E 67 06 00          lea     rax, aOutOfMemorySta ; "out of memory (stackalloc)"
        # .text:00000000004467EB BB 1A 00 00 00                mov     ebx, 1Ah
        # .text:00000000004467F0 E8 4B CF FE FF                call    runtime_throw
        pytest.param("out of memory (stackalloc)", 0xAC569, StringEncoding.UTF8, "go_strings64"),
        # NOTE: no 32 bit test case for this one
    ],
)
def test_lea_mov_call(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .text:0000000000481211 48 C7 40 10 19 00 00 00       mov     qword ptr [rax+10h], 19h
        # .text:0000000000481219 48 8D 0D 71 B6 02 00          lea     rcx, aExpandenvironm ; "ExpandEnvironmentStringsW"
        # .text:0000000000481220 48 89 48 08                   mov     [rax+8], rcx
        pytest.param("ExpandEnvironmentStringsW", 0xABE91, StringEncoding.UTF8, "go_strings64"),
        # .text:0047EACA C7 40 0C 19 00 00 00                          mov     dword ptr [eax+0Ch], 19h
        # .text:0047EAD1 8D 0D 36 56 4A 00                             lea     ecx, unk_4A5636
        # .text:0047EAD7 89 48 08                                      mov     [eax+8], ecx
        pytest.param("ExpandEnvironmentStringsW", 0xA3C36, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_mov_lea_mov(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # .idata:000000000062232A word_62232A     dw 0                    ; DATA XREF: .idata:0000000000622480↓o
        # .idata:000000000062232C                 db 'AddVectoredExceptionHandler',0                mov     [rax+8], rcx
        pytest.param("AddVectoredExceptionHandler", 0x1C5B2C, StringEncoding.UTF8, "go_strings64"),
        # .idata:005E531E word_5E531E     dw 0                    ; DATA XREF: .idata:005E53D4↓o
        # .idata:005E5320                 db 'AddVectoredExceptionHandler',0                                     mov     [eax+8], ecx
        pytest.param("AddVectoredExceptionHandler", 0x1B5120, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_import_data(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # 000000000048F6C0  74 01 09 41 6E 6F 6E 79  6D 6F 75 73 01 09 43 61  t..Anonymous..Ca
        # 000000000048F6D0  6C 6C 53 6C 69 63 65 01  09 43 6C 65 61 72 42 75  llSlice..ClearBu
        pytest.param("CallSlice", 0x8ECCE, StringEncoding.UTF8, "go_strings64"),
        # 0048D680  01 09 43 61 6C 6C 53 6C  69 63 65 01 09 43 6C 65  ..CallSlice..Cle
        # 0048D690  61 72 42 75 66 73 01 09  43 6F 6E 6E 65 63 74 45  arBufs..ConnectE                                    mov     [eax+8], ecx
        pytest.param("CallSlice", 0x8BC82, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_extract_string_blob(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)


@pytest.mark.parametrize(
    "string,offset,encoding,go_strings",
    [
        # 00000000004CDBD0  79 00 72 75 6E 74 69 6D  65 2E 6D 65 6D 65 71 75  y.runtime.memequ
        # 00000000004CDBE0  61 6C 00 72 75 6E 74 69  6D 65 2E 6D 65 6D 65 71  al.runtime.memeq
        pytest.param("runtime.memequal", 0xCD1D2, StringEncoding.UTF8, "go_strings64"),
        # 004C3610  6D 65 71 62 6F 64 79 00  72 75 6E 74 69 6D 65 2E  meqbody.runtime.
        # 004C3620  6D 65 6D 65 71 75 61 6C  00 72 75 6E 74 69 6D 65  memequal.runtime                                  mov     [eax+8], ecx
        pytest.param("runtime.memequal", 0xC1C18, StringEncoding.UTF8, "go_strings32"),
    ],
)
def test_extract_string_blob2(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)

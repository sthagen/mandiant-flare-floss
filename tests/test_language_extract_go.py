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
        pytest.param("adaptivestackstart", 0x534944, StringEncoding.ASCII, "go_strings32"),
        # .data:00534944 A0 35 4A 00                       dd offset aAdaptivestacks ; "adaptivestackstart"
        # .data:00534948 12                                db  12h
        pytest.param("adaptivestackstart", 0x541568, StringEncoding.ASCII, "go_strings64"),
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
        pytest.param("hello world", 0x4C08F8, StringEncoding.ASCII, "go_strings32"),
        # .text:000000000048DE46 48 8D 15 13 BB 03 00          lea     rdx, off_4C9960 ; "hello world"
        # .text:000000000048DE4D 48 89 54 24 30                mov     qword ptr [rsp+40h+var_18+8], rdx
        pytest.param("hello world", 0x4C9960, StringEncoding.ASCII, "go_strings64"),
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
        pytest.param("write of Go pointer ", 0x40428F, StringEncoding.ASCII, "go_strings64"),
        # .text:00403F6C 8D 05 09 42 4A 00                             lea     eax, aWriteOfGoPoint ; "write of Go pointer ws2_32.dll not foun"...
        # .text:00403F72 89 04 24                                      mov     [esp+10h+var_10], eax
        # .text:00403F75 C7 44 24 04 14 00 00 00                       mov     [esp+10h+var_C], 14h
        pytest.param("write of Go pointer ws2_32.dll not foun", 0x404209, StringEncoding.ASCII, "go_strings32"),
    ],
)
def test_lea_mov2(request, string, offset, encoding, go_strings):
    assert StaticString(string=string, offset=offset, encoding=encoding) in request.getfixturevalue(go_strings)



@pytest.mark.skip(reason="not supported yet")
def test_mov_lea(go_strings64):
    """
    .text:00000000004032EA B9 1C 00 00 00                mov     ecx, 1Ch
    .text:00000000004032EF 48 89 C7                      mov     rdi, rax
    .text:00000000004032F2 48 89 DE                      mov     rsi, rbx
    .text:00000000004032F5 31 C0                         xor     eax, eax
    .text:00000000004032F7 48 8D 1D A6 A2 0A 00          lea     rbx, aComparingUncom ; "comparing uncomparable type "
    """
    assert (
        StaticString(string="comparing uncomparable type ", offset=0x4AD5A4, encoding=StringEncoding.ASCII)
        in go_strings64
    )


@pytest.mark.skip(reason="not supported yet")
def test_lea_mov_call(go_strings64):
    """
    .text:00000000004467E4 48 8D 05 7E 67 06 00          lea     rax, aOutOfMemorySta ; "out of memory (stackalloc)"
    .text:00000000004467EB BB 1A 00 00 00                mov     ebx, 1Ah
    .text:00000000004467F0 E8 4B CF FE FF                call    runtime_throw
    """
    assert (
        StaticString(string="out of memory (stackalloc)", offset=0x4ACF69, encoding=StringEncoding.ASCII)
        in go_strings64
    )


# TODO
"""
.text:0000000000481211 48 C7 40 10 19 00 00 00       mov     qword ptr [rax+10h], 19h
.text:0000000000481219 48 8D 0D 71 B6 02 00          lea     rcx, aExpandenvironm ; "ExpandEnvironmentStringsW"
.text:0000000000481220 48 89 48 08                   mov     [rax+8], rcx
"""

import os

import floss.main

EXEFILE = os.path.join(os.path.dirname(__file__), "data", "src", "decode-to-stack", "bin", "test-decode-to-stack.exe")
SCFILE = os.path.join(
    os.path.dirname(__file__), "data", "src", "shellcode-stackstrings", "bin", "shellcode-stackstrings.bin"
)


def test_functions():
    # need both -x and --function
    assert floss.main.main(["floss.exe", EXEFILE, "--function", "0x1111111"]) == -1

    # 0x1111111 is not a function
    assert floss.main.main(["floss.exe", EXEFILE, "-x", "--function", "0x1111111"]) == -1

    # ok
    assert floss.main.main(["floss.exe", EXEFILE, "-x", "--function", "0x401560"]) == 0
    assert floss.main.main(["floss.exe", EXEFILE, "-x", "--function", "0x401560", "0x401000"]) == 0


def test_shellcode():
    # need both -x and --shellcode
    assert floss.main.main(["floss.exe", SCFILE, "--shellcode"]) == -1

    # ok
    assert floss.main.main(["floss.exe", SCFILE, "-x", "--shellcode"]) == 0
    assert floss.main.main(["floss.exe", SCFILE, "-x", "--shellcode", "--shellcode-base", "0x2000"]) == 0
    assert floss.main.main(["floss.exe", SCFILE, "-x", "--shellcode", "--shellcode-entry-point", "0x1001"]) == 0

    # arch should be i386 or amd64
    # and will autodetect
    assert floss.main.main(["floss.exe", SCFILE, "-x", "--shellcode", "--shellcode-arch", "aarch64"]) == -1
    assert floss.main.main(["floss.exe", SCFILE, "-x", "--shellcode", "--shellcode-arch", "i386"]) == 0
    assert floss.main.main(["floss.exe", SCFILE, "-x", "--shellcode", "--shellcode-arch", "amd64"]) == 0

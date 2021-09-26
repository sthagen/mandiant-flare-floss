import os

import floss.main

EXEFILE = os.path.join(os.path.dirname(__file__), "data", "src", "decode-to-stack", "bin", "test-decode-to-stack.exe")
SCFILE = os.path.join(
    os.path.dirname(__file__), "data", "src", "shellcode-stackstrings", "bin", "shellcode-stackstrings.bin"
)


def test_functions():
    # 0x1111111 is not a function
    assert floss.main.main(["floss.exe", EXEFILE, "-x", "--function", "0x1111111"]) == -1

    # ok
    assert floss.main.main(["floss.exe", EXEFILE, "-x", "--function", "0x401560"]) == 0
    assert floss.main.main(["floss.exe", EXEFILE, "--function", "0x401560"]) == 0
    assert floss.main.main(["floss.exe", EXEFILE, "--function", "0x401560", "0x401000"]) == 0


def test_shellcode():
    # ok
    assert floss.main.main(["floss.exe", SCFILE, "-x", "-f", "sc32"]) == 0
    assert floss.main.main(["floss.exe", SCFILE, "--format", "sc32"]) == 0

    # arch should be i386 or amd64
    # and will autodetect
    # assert floss.main.main(["floss.exe", SCFILE, "--format", "pe"]) == -1
    assert floss.main.main(["floss.exe", SCFILE, "--format", "sc32"]) == 0
    assert floss.main.main(["floss.exe", SCFILE, "--format", "sc64"]) == 0

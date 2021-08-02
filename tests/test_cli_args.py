import os

import floss.main

TESTFILE = os.path.join(os.path.dirname(__file__), "data", "src", "decode-to-stack", "bin", "test-decode-to-stack.exe")


def test_functions():
    # need both -x and --function
    assert floss.main.main(["floss.exe", TESTFILE, "--function", "0x1111111"]) == -1

    # 0x1111111 is not a function
    assert floss.main.main(["floss.exe", TESTFILE, "-x", "--function", "0x1111111"]) == -1

    # ok
    assert floss.main.main(["floss.exe", TESTFILE, "-x", "--function", "0x401560"]) == 0
    assert floss.main.main(["floss.exe", TESTFILE, "-x", "--function", "0x401560", "0x401000"]) == 0

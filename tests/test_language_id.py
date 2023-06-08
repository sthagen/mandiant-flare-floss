import os

import pytest

from floss.main import get_static_strings
from floss.language_identifier import Language, identify_language


@pytest.mark.parametrize(
    "binary_file, expected_result",
    [
        ("data/src/go-hello/bin/go-hello.exe", Language.go),
        ("data/src/rust-hello/bin/rust-hello.exe", Language.rust),
        ("data/test-decode-to-stack.exe", Language.unknown),
        ("data/src/dotnet-hello/bin/dotnet-hello.exe", Language.dotnet),
        ("data/src/shellcode-stackstrings/bin/shellcode-stackstrings.bin", Language.unknown),
    ],
)
def test_language_detection(binary_file, expected_result):
    CD = os.path.dirname(__file__)
    abs_path = os.path.normpath(os.path.join(CD, binary_file))
    # check if the file exists
    assert os.path.exists(abs_path), f"File {binary_file} does not exist"

    static_strings = get_static_strings(abs_path, 4)

    language = identify_language(abs_path, static_strings)
    # Check the expected result
    assert language == expected_result, f"Expected: {expected_result.value}, Actual: {language.value}"

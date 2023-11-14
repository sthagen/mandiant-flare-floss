from pathlib import Path

import pytest

from floss.utils import get_static_strings
from floss.language.identify import VERSION_UNKNOWN_OR_NA, Language, identify_language_and_version


@pytest.mark.parametrize(
    "binary_file, expected_result, expected_version",
    [
        ("data/language/go/go-hello/bin/go-hello.exe", Language.GO, "1.20"),
        ("data/language/rust/rust-hello/bin/rust-hello.exe", Language.RUST, "1.69.0"),
        ("data/test-decode-to-stack.exe", Language.UNKNOWN, VERSION_UNKNOWN_OR_NA),
        ("data/language/dotnet/dotnet-hello/bin/dotnet-hello.exe", Language.DOTNET, VERSION_UNKNOWN_OR_NA),
        ("data/src/shellcode-stackstrings/bin/shellcode-stackstrings.bin", Language.UNKNOWN, VERSION_UNKNOWN_OR_NA),
    ],
)
def test_language_detection(binary_file, expected_result, expected_version):
    CD = Path(__file__).resolve().parent
    abs_path = (CD / binary_file).resolve()

    assert abs_path.exists(), f"File {binary_file} does not exist"

    static_strings = get_static_strings(abs_path, 4)

    language, version = identify_language_and_version(abs_path, static_strings)

    assert language == expected_result, f"Expected: {expected_result.value}, Actual: {language.value}"
    assert version == expected_version, f"Expected: {expected_version}, Actual: {version}"

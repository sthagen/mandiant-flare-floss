import textwrap

import floss.main

# floss --no static -j tests/data/src/decode-in-place/bin/test-decode-in-place.exe
RESULTS = textwrap.dedent(
    """
{
    "analysis": {
        "enable_decoded_strings": true,
        "enable_stack_strings": true,
        "enable_static_strings": false,
        "enable_tight_strings": true,
        "functions": {
            "analyzed_decoded_strings": 20,
            "analyzed_stack_strings": 30,
            "analyzed_tight_strings": 2,
            "decoding_function_scores": {
                "4199648": 0.744, "4199776": 0.763, "4199888": 0.617, "4200144": 0.62, "4200304": 0.471,
                "4200336": 0.617, "4200560": 0.44, "4201104": 0.931, "4201200": 0.887, "4201776": 0.576,
                "4202640": 0.539, "4202672": 0.886, "4202992": 0.624, "4203120": 0.686, "4203264": 0.6,
                "4203424": 0.497, "4203584": 0.591, "4203648": 0.727, "4203872": 0.617, "4204416": 0.531
            },
            "discovered": 50,
            "library": 0
        }
    },
    "metadata": {
        "file_path": "tests/data/src/decode-in-place/bin/test-decode-in-place.exe",
        "imagebase": 4194304,
        "min_length": 4,
        "runtime": {
            "decoded_strings": 0.9855,
            "find_features": 0.0546,
            "stack_strings": 0.207,
            "start_date": "2022-06-01T10:58:11.059390Z",
            "static_strings": 0.0,
            "tight_strings": 0.1788,
            "total": 7.2177,
            "vivisect": 5.7918
        },
        "version": "2.0.0"
    },
    "strings": {
        "decoded_strings": [
            {
                "address": 3216244620,
                "address_type": "STACK",
                "decoded_at": 4199986,
                "decoding_routine": 4199776,
                "encoding": "ASCII",
                "string": "hello world"
            }
        ],
        "stack_strings": [
            {
                "encoding": "ASCII",
                "frame_offset": 32,
                "function": 4199888,
                "offset": 32,
                "original_stack_pointer": 3216244656,
                "program_counter": 4199776,
                "stack_pointer": 3216244588,
                "string": "idmmn!vnsme"
            }
        ],
        "static_strings": [],
        "tight_strings": []
    }
}
"""
)


def test_load(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "results.json"
    p.write_text(RESULTS)
    assert (
        floss.main.main(
            [
                "-l",
                str(d.joinpath(p)),
            ]
        )
        == 0
    )

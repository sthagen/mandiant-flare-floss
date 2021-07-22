#!/usr/bin/env python3
"""
render-x64dbg-database.py

Translate a floss result document into an x64dbg database.

Usage:

  $ floss suspicious.exe -j > floss-results.json
  $ python render-x64dbg-database.py floss-results.json > database.json
  # open `database.json` in x64dbg

Copyright (C) 2021 FireEye, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import sys
import json
import logging
import os.path
import argparse

from floss.render.sanitize import sanitize_string_for_script
from floss.render.result_document import AddressType, ResultDocument

logger = logging.getLogger("floss.render-x64dbg-import-script")


def render_x64dbg_database(result_document: ResultDocument) -> str:
    """
    Create x64dbg database/json file contents for file annotations.
    """
    export = {"comments": []}
    module = os.path.basename(result_document.metadata.file_path)
    processed = {}
    for ds in result_document.strings.decoded_strings:
        if ds.string != "":
            sanitized_string = sanitize_string_for_script(ds.string)
            if ds.address_type == AddressType.GLOBAL:
                rva = hex(ds.address - result_document.metadata.imagebase)
                try:
                    processed[rva] += "\t" + sanitized_string
                except BaseException:
                    processed[rva] = "FLOSS: " + sanitized_string
            else:
                rva = hex(ds.decoded_at - result_document.metadata.imagebase)
                try:
                    processed[rva] += "\t" + sanitized_string
                except BaseException:
                    processed[rva] = "FLOSS: " + sanitized_string

    for i in list(processed.keys()):
        comment = {"text": processed[i], "manual": False, "module": module, "address": i}
        export["comments"].append(comment)

    return json.dumps(export, indent=1)


def main():
    parser = argparse.ArgumentParser(description="Generate an x64dbg script to apply FLOSS results.")
    parser.add_argument("/path/to/report.json", help="path to JSON document from `floss --json`")

    logging_group = parser.add_argument_group("logging arguments")

    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q", "--quiet", action="store_true", help="disable all status output except fatal errors"
    )

    args = parser.parse_args()
    args.report_path = getattr(args, "/path/to/report.json")

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    result_document = ResultDocument.parse_file(args.report_path)

    print(render_x64dbg_database(result_document))
    return 0


if __name__ == "__main__":
    sys.exit(main())


# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
import sys
import logging
import pathlib
import argparse
import textwrap

import pefile
import tabulate
from floss.main import get_static_strings
from floss.results import StaticString, StringEncoding
from floss.render.sanitize import sanitize
from floss.language.go.extract import extract_go_strings

logger = logging.getLogger(__name__)

MIN_STR_LEN = 4


def main():
    parser = argparse.ArgumentParser(description="Get Go strings")
    parser.add_argument("path", help="file or path to analyze")
    parser.add_argument(
        "-n",
        "--minimum-length",
        dest="min_length",
        type=int,
        default=MIN_STR_LEN,
        help="minimum string length",
    )
    logging_group = parser.add_argument_group("logging arguments")
    logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    logging_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="disable all status output except fatal errors",
    )
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    try:
        pe = pefile.PE(args.path)
    except pefile.PEFormatError as err:
        logger.debug(f"NOT a valid PE file: {err}")
        return 1

    path = pathlib.Path(args.path)

    static_strings = get_static_strings(path, args.min_length)

    go_strings = extract_go_strings(path, args.min_length)

    get_extract_stats(pe, static_strings, go_strings, "arker")
    get_extract_stats2(pe, static_strings, go_strings)

    with open("extracted-arker.txt", "w", encoding="utf-8") as f:
        for s in go_strings:
            sec = pe.get_section_by_rva(s.offset)
            if sec:
                secname = sec.Name.decode("utf-8").split("\x00")[0]
            else:
                secname = "N/A"
            f.write(f"0x{s.offset:08x} {secname:8s} {s.string}\n")


def get_extract_stats(pe, all_ss_strings, go_strings, suffix):
    target_strings = ""
    for ss in all_ss_strings:
        sec = pe.get_section_by_rva(ss.offset)
        if sec:
            secname = sec.Name.decode("utf-8").split("\x00")[0]
            if secname in (".text", ".data", ".rdata"):
                target_strings += ss.string

    gs_len = 0
    ts_len = len(target_strings)
    target_strings_original = target_strings
    target_strings_replaced = target_strings

    for gs in go_strings:
        gs = gs.string
        if gs and gs in target_strings:
            gs_len += len(gs)
            target_strings = target_strings.replace(gs, "", 1)
            target_strings_replaced = target_strings_replaced.replace(gs, "=" * len(gs), 1)

    with open(f"found-{suffix}.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(textwrap.wrap(target_strings_replaced, width=160)))
    with open(f"origi-{suffix}.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(textwrap.wrap(target_strings_original, width=160)))
    print("len targets  :", ts_len)
    print("len gostrings:", gs_len)
    print("len removed  :", len(target_strings))
    print(f"Percentage of strings extracted: {round(100 * (gs_len / ts_len))}%")
    print(f"Percentage of missed strings   : {round(100 * (len(target_strings) / ts_len))}%")


def get_extract_stats2(pe, all_ss_strings, go_strings):
    all_strings = list()
    for ss in all_ss_strings:
        sec = pe.get_section_by_rva(ss.offset)
        if sec:
            secname = sec.Name.decode("utf-8").split("\x00")[0]
        else:
            secname = ""
        all_strings.append((secname, ss))

    results = list()
    for n, ss in enumerate(all_strings):
        secname, s = ss

        found = False
        cont = False
        msg = ""
        for m, gs in enumerate(go_strings):
            sec = pe.get_section_by_rva(gs.offset)
            gs_sec = None
            if sec:
                gs_sec = sec.Name.decode("utf-8").split("\x00")[0]

            if s.string == gs.string and s.offset == gs.offset:
                msg = "exact string"
                found = True
            elif (
                gs.string
                and gs.string in s.string
                and gs_sec == secname
                and s.offset <= gs.offset <= s.offset + len(s.string)
            ):
                msg = "substring"
                found = True
                if len(s.string.replace(gs.string, "")) >= MIN_STR_LEN:
                    cont = True
                else:
                    cont = False
            elif s.offset == gs.offset:
                msg = "offset"
                found = True

            if found:
                # remove found string data
                fs = all_strings[n][1]
                all_strings[n] = (
                    secname,
                    StaticString(
                        string=fs.string.replace(gs.string, ""),
                        offset=fs.offset,
                        encoding=fs.encoding,
                    ),
                )

                fgs = go_strings[m]
                go_strings[m] = StaticString(
                    string=fgs.string.replace(gs.string, ""),
                    offset=fgs.offset,
                    encoding=fgs.encoding,
                )

                results.append((secname, found, msg, s, gs))
                # results.append((secname, found, msg, all_strings[n][1], gs))
                if not cont:
                    break

        if not found:
            # temp NULL string
            null = StaticString(string="", offset=0, encoding=StringEncoding.UTF8)
            results.append((secname, found, msg, s, null))

    rows = list()
    for r in results:
        secname, found, msg, s, gs = r

        sdata = s.string
        if len(s.string) >= 50:
            sdata = s.string[:23] + "...." + s.string[-23:]

        sdata = sanitize(sdata)

        rows.append(
            (
                f"{secname}",
                f"{s.offset:8x}",
                f"{found}",
                f"{msg}",
                f"{len(s.string)}",
                f"{sdata}",
                f"{sanitize(gs.string) if gs.string else ''}",
                f"{hex(gs.offset) if gs.offset else ''}",
            )
        )

    print(
        tabulate.tabulate(
            rows, headers=["section", "offset", "found", "msg", "slen", "string", "gostring", "gsoff"], tablefmt="psql"
        )
    )


if __name__ == "__main__":
    sys.exit(main())

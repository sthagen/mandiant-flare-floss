import io
import collections
from enum import Enum
from typing import List, Union

import tabulate

import floss.logging
from floss.utils import hex
from floss.results import AddressType, StackString, TightString, DecodedString, ResultDocument, StringEncoding
from floss.render.sanitize import sanitize

tabulate.PRESERVE_WHITESPACE = True


logger = floss.logging.getLogger(__name__)


class Verbosity(int, Enum):
    DEFAULT = 0
    VERBOSE = 1


class StringIO(io.StringIO):
    def writeln(self, s):
        self.write(s)
        self.write("\n")


def width(s: str, character_count: int) -> str:
    """pad the given string to at least `character_count`"""
    if len(s) < character_count:
        return s + " " * (character_count - len(s))
    else:
        return s


def render_meta(results, ostream, verbose):
    if verbose == Verbosity.DEFAULT:
        # TODO tweak
        rows = [
            (width("file_path", 22), width(results.metadata.file_path, 82)),
            ("# libs", len(results.metadata.analysis.get("library_functions"))),
            ("static strings", results.metadata.enable_static_strings),
            ("stack strings", results.metadata.enable_stack_strings),
            ("tight strings", results.metadata.enable_tight_strings),
            ("decoded strings", results.metadata.enable_decoded_strings),
        ]
        ostream.write(tabulate.tabulate(rows, tablefmt="psql"))

    else:
        rows = [
            (width("file_path", 22), width(results.metadata.file_path, 82)),
            ("imagebase", f"0x{results.metadata.imagebase:x}"),
            ("date", results.metadata.date),
            ("# libs", len(results.metadata.analysis.get("library_functions"))),
            ("static strings", results.metadata.enable_static_strings),
            ("stack strings", results.metadata.enable_stack_strings),
            ("tight strings", results.metadata.enable_tight_strings),
            ("decoded strings", results.metadata.enable_decoded_strings),
        ]
        ostream.write(tabulate.tabulate(rows, tablefmt="psql"))

    ostream.write("\n")


def render_staticstrings(strings, ostream, verbose, quiet):
    render_heading("STATIC STRINGS", len(strings), ostream, quiet)

    ascii_strings = list(filter(lambda s: s.encoding == StringEncoding.ASCII, strings))
    unicode_strings = list(filter(lambda s: s.encoding == StringEncoding.UTF16LE, strings))

    render_heading("ASCII STRINGS", len(ascii_strings), ostream, quiet)

    for s in ascii_strings[:8]:  # TODO
        if verbose == Verbosity.DEFAULT:
            ostream.writeln(s.string)
        else:
            # TODO adjust format based on filesize
            ostream.writeln(f"0x{s.offset:08x} {s.string}")
    ostream.write("")

    render_heading("UTF-16LE STRINGS", len(unicode_strings), ostream, quiet)
    for s in unicode_strings[:8]:  # TODO
        if verbose == Verbosity.DEFAULT:
            ostream.writeln(s.string)
        else:
            ostream.writeln(f"0x{s.offset:x} {s.string}")


def render_stackstrings(strings: Union[List[StackString], List[TightString]], ostream, verbose: bool, quiet: bool):
    if verbose == Verbosity.DEFAULT:
        for s in strings:
            ostream.writeln(sanitize(s.string))
    else:
        ostream.write(
            tabulate.tabulate(
                [(hex(s.function), hex(s.frame_offset), sanitize(s.string)) for s in strings],
                headers=("Function", "Frame Offset", "String") if not quiet else (),
            )
        )


def render_heading(heading, n, ostream, quiet):
    if quiet:
        return
    ostream.write(f"[ {heading} ({n}) ]")
    ostream.write("\n")


def render(results, verbose, disable_headers):
    ostream = StringIO()

    if not disable_headers:
        ostream.write("\n\n[ FLARE FLOSS RESULTS ]\n")
        render_meta(results, ostream, verbose)
        ostream.writeln("")

    if results.metadata.enable_static_strings:
        render_staticstrings(results.strings.static_strings, ostream, verbose, disable_headers)

    if results.metadata.enable_decoded_strings:
        render_heading("DECODED STRINGS", len(results.strings.decoded_strings), ostream, disable_headers)
        render_decoded_strings(results.strings.decoded_strings, ostream, verbose, disable_headers)
        ostream.writeln("")

    if results.metadata.enable_stack_strings:
        render_heading("STACK STRINGS", len(results.strings.stack_strings), ostream, disable_headers)
        render_stackstrings(results.strings.stack_strings, ostream, verbose, disable_headers)
        ostream.writeln("")

    if results.metadata.enable_tight_strings:
        render_heading("TIGHT STRINGS", len(results.strings.tight_strings), ostream, disable_headers)
        render_stackstrings(results.strings.tight_strings, ostream, verbose, disable_headers)
        ostream.writeln("")

    return ostream.getvalue()


def render_decoded_strings(decoded_strings: List[DecodedString], ostream, verbose, quiet):
    """
    Render results of string decoding phase.
    """
    if verbose == Verbosity.DEFAULT:
        for ds in decoded_strings:
            ostream.writeln(sanitize(ds.string))
    else:
        strings_by_functions = collections.defaultdict(list)
        for ds in decoded_strings:
            strings_by_functions[ds.decoding_routine].append(ds)

        for fva, data in strings_by_functions.items():
            render_heading(f" FUNCTION at 0x{fva:x}", len(data), ostream, quiet)
            rows = []
            for ds in data:
                if ds.address_type in (AddressType.HEAP, AddressType.STACK):
                    offset_string = f"[{ds.address_type}]"
                else:
                    offset_string = hex(ds.address or 0)
                rows.append((offset_string, hex(ds.decoded_at), sanitize(ds.string)))

            ostream.write(tabulate.tabulate(rows, headers=("Offset", "Called At", "String") if not quiet else ()))
            ostream.writeln("\n")

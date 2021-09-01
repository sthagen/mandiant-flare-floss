# FireEye Labs Obfuscated String Solver

## Usage

You can use FLOSS just like you'd use `strings.exe`:
 to extract human readable strings from binary data.
The enhancement that FLOSS provides is that it statically
 analyzes executable files and decodes obfuscated strings.
These include strings encrypted in global memory,
 deobfuscated onto the heap, or manually created on the
 stack (stackstrings).
Since FLOSS also extracts static strings (like `strings.exe`),
 you should consider replacing `strings.exe` with FLOSS
 within your analysis workflow.

Here's a summary of the command line flags and options you
 can provide to FLOSS to modify its behavior.

See `floss -h` for all supported arguments and usage examples. This displays the most used arguments only.

To see all supported arguments run `floss -h -x` to enable the eXpert mode.

### Extract static, obfuscated, and stack strings (default mode)

    floss.exe malware.bin

The default mode for FLOSS is to extract the following string types from an executable file:
- static ASCII and UTF16LE strings
- obfuscated strings
- stackstrings

See the section on [Shellcode analysis](#shellcode) below on how to analyze raw binary files
containing shellcode.

By default FLOSS uses a minimum string length of four.


### Disable string type extraction (`--no-<STRING-TYPE>-strings`)

When FLOSS searches for static strings, it looks for
 human-readable ASCII and UTF-16 strings across the
 entire binary contents of the file.
This means you may be able to replace `strings.exe` with
 FLOSS in your analysis workflow. However, you may disable
 the extraction of static strings via the `--no-static-strings` switch.

    floss.exe --no-static-strings malware.bin

Analogous, you can disable the extraction of obfuscated strings or stackstrings.

    floss.exe --no-decoded-strings malware.bin
    floss.exe --no-stack-strings malware.bin


### Write output as JSON (`-j/--json`)

Write FLOSS results to `stdout` structured in JSON to make it easy to ingest by a script.

    floss.exe -j malware.bin


### Quiet mode (`-q/--quiet`)

You can suppress the formatting of FLOSS output by providing
 the flags `-q` or `--quiet`.
These flags are appropriate if you will pipe the results of FLOSS
 into a filtering or searching program such as grep, and
 want to avoid matches on the section headers.
In quiet mode, each recovered string is printed on its
 own line.
The "type" of the string (static, decoded, or stackstring)
 is not included.

     floss.exe -q malware.bin


### Minimum string length (`-n/--minimum-length`)

By default, FLOSS searches for human-readable strings
 with a length of at least four characters.
You can use the `-n` or `--minimum-length` options to
 specific a different minimum length.
Supplying a larger minimum length reduces the chances
 of identifying random data that appears to be ASCII;
 however, FLOSS may then pass over short legitimate
 human-readable strings

    floss.exe -n 10 malware.bin


### Decoding function specification (`--functions`)

You can instruct FLOSS to decode the strings provided
 to specific functions by using the `--functions`
 option.
By default, FLOSS uses heuristics to identify decoding
 routines in malware.
This mode circumvents the identification phase and skips
 directly to the decoding phase.
If you've previously done analysis on an executable program
 and manually identified the decoding routines, use
 this mode.
This can improve performance as FLOSS by perhaps one-third
 (on the order of seconds, so it is usually _not_ worth it
  to always manually identify decoding routines).
Specify functions by using their hex-encoded virtual address.

    floss.exe --functions 0x401000 0x402000 malware.bin


### Do not filter deobfuscated strings (`--no-filter`)

The FLOSS emulation process can result in many false positive deobfuscated
strings. By default, various filters are applied to remove most strings
stemming from vivisect's memory initializations as well as taint and pointer
handling, among other things. Use the `--no-filter` option to obtain the
raw and unfiltered deobfuscated strings.


## <a name="shellcode"></a>Shellcode analysis options

Malicious shellcode often times contains obfuscated strings or stackstrings.
FLOSS can analyze raw binary files containing shellcode via the `-s/--shellcode` switch. All
options mentioned above can also be applied when analyzing shellcode.

    floss.exe -s malware.bin

If you want to specify a base address for the shellcode, use the `--shellcode_base` switch.

    floss.exe -s malware.bin --shellcode_base 0x1000000

You can specify an entry point for the shellcode with the `--shellcode-entry-point`
option. The `entry point` value is the relative offset from `base` where the shellcode starts executing. Although vivisect does a good job identifying code, providing an entry point might improve code analysis.

    floss.exe -s malware.bin --shellcode_base 0x1000000 --shellcode-entry-point 0x100

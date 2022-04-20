# FLARE Obfuscated String Solver

## Usage

You can use FLOSS just like you'd use `strings.exe`:
 to extract human-readable strings from binary data.
The enhancement that FLOSS provides is that it statically
 analyzes executable files and decodes obfuscated strings.
These include:
* strings encrypted in global memory, deobfuscated onto the heap
* strings manually created on the stack (stackstrings)
* strings created on the stack and then further modified (tight strings)

Since FLOSS also extracts static strings (like `strings.exe`),
 you should consider replacing `strings.exe` with FLOSS
 within your analysis workflow.

Here's a summary of the command line flags and options you
 can provide to FLOSS to modify its behavior.

See `floss -h` for all supported arguments and usage examples. This displays the most used arguments only.

To see all supported arguments run `floss -H`.

### Extract static, obfuscated, and stack strings (default mode)

    floss.exe malware.bin

The default mode for FLOSS is to extract the following string types from an executable file:
- static ASCII and UTF16LE strings
- stack strings
- tight strings
- obfuscated strings

See the section on [Shellcode analysis](#shellcode) below on how to analyze raw binary files
containing shellcode.

By default, FLOSS uses a minimum string length of four.


### Disable string type extraction (`--no {static,decoded,stack,tight}`)

When FLOSS searches for static strings, it looks for
 human-readable ASCII and UTF-16 strings across the
 entire binary contents of the file.
This means you may be able to replace `strings.exe` with
 FLOSS in your analysis workflow. However, you may disable
 the extraction of static strings via the `--no static` switch.

    floss.exe --no static -- malware.bin

Since `--no` supports multiple arguments, end the command options with a double dash `--`.

Analogous, you can disable the extraction of obfuscated strings, stackstrings or any combination.

    floss.exe --no decoded -- malware.bin
    floss.exe --no stack tight -- malware.bin


### Enable string type extraction (`--only {static,decoded,stack,tight}`)

Sometimes it's easier to specify only the string type(s) you want to extract.
Use the `--only` option for that.

    floss.exe --only decoded -- malware.bin

Please note that `--no` and `--only` cannot be used at the same time.

### Write output as JSON (`-j/--json`)

Write FLOSS results to `stdout` structured in JSON to make it easy to ingest by a script.

    floss.exe -j malware.bin


### Write output to a file (`-o/--output`)

Write FLOSS results to a provided output file path instead of `stdout`.

    floss.exe -o malware_floss_results.txt malware.bin
    floss.exe -j -o malware_floss_results.json malware.bin


### Verbose results (`-v`)

Enable verbose results output, e.g. including function offsets and string encoding.
This does not affect the JSON output.

    floss.exe -v malware.bin


### Quiet mode (`-q/--quiet`)

You can suppress the formatting of FLOSS output by providing
 the flags `-q` or `--quiet`.
These flags are appropriate if you will pipe the results of FLOSS
 into a filtering or searching program such as grep, and
 want to avoid matches on the section headers.
In quiet mode, each recovered string is printed on its
 own line.
The "type" of the string (static, decoded, stackstring, tightstring)
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


## <a name="shellcode"></a>Shellcode analysis options

Malicious shellcode often times contains obfuscated strings or stackstrings.
FLOSS can analyze raw binary files containing shellcode via the `-f/--format` switch. All
options mentioned above can also be applied when analyzing shellcode.

    floss.exe -f sc32 malware.raw32
    floss.exe -f sc64 malware.raw64

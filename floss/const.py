KILOBYTE = 1024
MEGABYTE = 1024 * KILOBYTE
MAX_FILE_SIZE = 16 * MEGABYTE
SUPPORTED_FILE_MAGIC = {b"MZ"}
DEFAULT_MIN_LENGTH = 4
MAX_STRING_LENGTH = 2048

# Decoded String (DS)
# shortcut decoding of a function if only few strings are found...
DS_FUNCTION_MIN_DECODED_STRINGS = 5
# ... after emulating at least these function contexts
DS_FUNCTION_CTX_SHORTCUT_THRESHOLD = 15

# Tight String (TS)
# max instruction count to emulate in a tight loop
TS_MAX_INSTR_COUNT = 10000
# max basic blocks per tight function (that basically just wraps a tight loop)
TIGHT_FUNCTION_MAX_BLOCKS = 10

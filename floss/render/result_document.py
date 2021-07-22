import datetime
from enum import Enum
from typing import List
from dataclasses import field

# we use pydantic for dataclasses so that we can
# easily load and validate JSON reports.
#
# pydantic checks all the JSON fields look as they should
# while using the nice and familiar dataclass syntax.
#
# really, you should just pretend we're using stock dataclasses.
from pydantic.dataclasses import dataclass


@dataclass(frozen=True)
class StackString:
    """
    here's what the following members represent:
        
        
        [smaller addresses]
       
        +---------------+  <- stack_pointer (top of stack)
        |               | \
        +---------------+  | offset
        |               | /
        +---------------+
        | "abc"         | \
        +---------------+  |
        |               |  |
        +---------------+  | frame_offset
        |               |  |
        +---------------+  |
        |               | /
        +---------------+  <- original_stack_pointer (bottom of stack, probably bp)
        
        [bigger addresses]


    Attributes:
      function: the address of the function from which the stackstring was extracted
      string: the extracted string
      program_counter: the program counter at the moment the string was extracted
      stack_pointer: the stack counter at the moment the string was extracted
      original_stack_pointer: the initial stack counter when the function was entered
      offset: the offset into the stack from at which the stack string was found
      frame_offset: the offset from the function frame at which the stack string was found
    """

    function: int
    string: str
    program_counter: int
    stack_pointer: int
    original_stack_pointer: int
    offset: int
    frame_offset: int


class AddressType(str, Enum):
    STACK = "STACK"
    GLOBAL = "GLOBAL"
    HEAP = "HEAP"


@dataclass(frozen=True)
class DecodedString:
    """
    A decoding string and details about where it was found.

    Attributes:
        address: address of the string in memory
        address_type: type of the address of the string in memory
        string: the decoded string
        decoded_at: the address at which the decoding routine is called
        decoding_routine: the address of the decoding routine
    """

    address: int
    address_type: AddressType
    string: str
    decoded_at: int
    decoding_routine: int


@dataclass(frozen=True)
class StaticString:
    """
    A string extracted from the raw bytes of the input.

    Attributes:
        string: the string
        offset: the offset into the input where the string is found
    """

    string: str
    offset: int


@dataclass
class Metadata:
    file_path: str
    imagebase: int = 0
    date: datetime.datetime = datetime.datetime.now()
    enable_stack_strings: bool = True
    enable_decoded_strings: bool = True
    enable_static_strings: bool = True


@dataclass
class Strings:
    stack_strings: List[StackString] = field(default_factory=list)
    decoded_strings: List[DecodedString] = field(default_factory=list)
    static_strings: List[StaticString] = field(default_factory=list)


@dataclass
class ResultDocument:
    metadata: Metadata
    strings: Strings = field(default_factory=Strings)

    @classmethod
    def parse_file(cls, path):
        return cls.__pydantic_model__.parse_file(path)

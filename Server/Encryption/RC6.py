from random import randbytes
import sys
import os

__all__ = ["RC6Encryption", "pkcs5_7padding"]

from base64 import (
    b85encode,
    b64encode,
    b32encode,
    b16encode,
    b85decode,
    b64decode,
    b32decode,
    b16decode,
)
from argparse import Namespace, ArgumentParser, FileType, BooleanOptionalAction
from locale import getpreferredencoding
from typing import Tuple, List, Union
from collections.abc import Iterator
from sys import exit, stdin, stdout
from warnings import simplefilter
from contextlib import suppress
from os import device_encoding
from functools import partial
from hashlib import sha256
from os import urandom

try:
    from binascii import a2b_hqx, b2a_hqx
except ImportError:
    uu_encoding = False
else:
    uu_encoding = True

basetwo = partial(int, base=2)
unblock = partial(int.to_bytes, length=4, byteorder="little")


class RC6Encryption:

    """
    This class implements the RC6 encryption.

    Rounds possible values: {12, 16, 20}
    """

    P32 = 0xB7E15163
    Q32 = 0x9E3779B9

    def __init__(
        self, key: bytes, rounds: int = 20, w_bit: int = 32, lgw: int = 5
    ):
        self.key_bytes = key
        self.rounds = rounds
        self.w_bit = w_bit
        self.lgw = lgw

        self.round2_2 = rounds * 2 + 2
        self.round2_3 = self.round2_2 + 1
        self.round2_4 = self.round2_3 + 1

        self.modulo = 2**w_bit

        (
            self.key_binary_blocks,
            self.key_integer_reverse_blocks,
        ) = self.get_blocks(key)
        self.key_blocks_number = len(self.key_binary_blocks)

        self.rc6_key = [self.P32]

        self.key_generation()

    @staticmethod
    def enumerate_blocks(data: bytes) -> Iterator[Tuple[int, int, int, int]]:
        """
        This function returns a tuple of 4 integers for each blocks.
        """

        _, blocks = RC6Encryption.get_blocks(data)

        while blocks:
            a, b, c, d, *blocks = blocks
            yield a, b, c, d

    @staticmethod
    def get_blocks(data: bytes) -> Tuple[List[str], List[int]]:
        """
        This function returns blocks (binary strings and integers) from data.
        """

        binary_blocks = []
        integer_blocks = []
        block = ""

        for i, char in enumerate(data):
            if i and not i % 4:
                binary_blocks.append(block)
                integer_blocks.append(basetwo(block))
                block = ""
            block = f"{char:0>8b}{block}"

        binary_blocks.append(block)
        integer_blocks.append(basetwo(block))

        return binary_blocks, integer_blocks

    @staticmethod
    def blocks_to_data(blocks: List[int]) -> bytes:
        """
        This function returns data from blocks (binary strings).
        """

        data = b""

        for block in blocks:
            data += unblock(block)

        return data

    def right_rotation(self, x: int, n: int) -> int:
        """
        This function perform a right rotation.
        """

        mask = (2**n) - 1
        mask_bits = x & mask
        return (x >> n) | (mask_bits << (self.w_bit - n))

    def left_rotation(self, x: int, n: int) -> int:
        """
        This function perform a left rotation (based on right rotation).
        """

        return self.right_rotation(x, self.w_bit - n)

    def key_generation(self) -> List[int]:
        """
        This function generate the key.
        """

        for i in range(0, self.round2_3):
            self.rc6_key.append((self.rc6_key[i] + self.Q32) % self.modulo)

        a = b = i = j = 0
        v = 3 * (
            self.key_blocks_number
            if self.key_blocks_number > self.round2_4
            else self.round2_4
        )

        for i_ in range(v):
            a = self.rc6_key[i] = self.left_rotation(
                (self.rc6_key[i] + a + b) % self.modulo, 3
            )
            b = self.key_integer_reverse_blocks[j] = self.left_rotation(
                (self.key_integer_reverse_blocks[j] + a + b) % self.modulo,
                (a + b) % 32,
            )
            i = (i + 1) % (self.round2_4)
            j = (j + 1) % self.key_blocks_number

        return self.rc6_key

    def data_encryption_ECB(self, data: bytes) -> bytes:
        """
        This function performs full encryption using ECB mode:
            - add PKCS (5/7) padding
            - get blocks
            - encrypt all blocks using ECB mode
            - convert blocks in bytes
            - returns bytes
        """

        data = pkcs5_7padding(data)
        encrypted = []

        for block in self.enumerate_blocks(data):
            encrypted.extend(self.encrypt(block))

        return self.blocks_to_data(encrypted)

    def data_decryption_ECB(self, data: bytes) -> bytes:
        """
        This function performs full decryption using ECB mode:
            - get blocks
            - decrypt all blocks using ECB mode
            - convert blocks in bytes
            - remove PKCS (5/7) padding
            - returns bytes
        """

        decrypted = []

        for block in self.enumerate_blocks(data):
            decrypted.extend(self.decrypt(block))

        return remove_pkcs_padding(self.blocks_to_data(decrypted))

    def data_encryption_CBC(
        self, data: bytes, iv: bytes = None
    ) -> Tuple[bytes, bytes]:
        """
        This function performs full encryption using CBC mode:
            - get/generate the IV
            - add PKCS (5/7) padding
            - get blocks
            - encrypt all blocks using CBC mode
            - convert blocks in bytes
            - returns bytes
        """

        if iv is None:
            _iv = urandom(16)
        else:
            iv_length = len(iv)
            _iv = bytes(iv[i % iv_length] for i in range(16))

        _, iv = self.get_blocks(_iv)

        data = pkcs5_7padding(data)
        encrypted = []

        for block in self.enumerate_blocks(data):
            block = (
                block[0] ^ iv[0],
                block[1] ^ iv[1],
                block[2] ^ iv[2],
                block[3] ^ iv[3],
            )
            iv = self.encrypt(block)
            encrypted.extend(iv)

        return _iv, self.blocks_to_data(encrypted)

    def data_decryption_CBC(self, data: bytes, iv: bytes) -> bytes:
        """
        This function performs full decryption using CBC mode:
            - get blocks
            - decrypt all blocks using CBC mode
            - convert blocks in bytes
            - remove PKCS (5/7) padding
            - returns bytes
        """

        _, iv = self.get_blocks(iv)
        decrypted = []

        for block in self.enumerate_blocks(data):
            decrypted_block = self.decrypt(block)
            decrypted.extend(
                (
                    decrypted_block[0] ^ iv[0],
                    decrypted_block[1] ^ iv[1],
                    decrypted_block[2] ^ iv[2],
                    decrypted_block[3] ^ iv[3],
                )
            )
            iv = block

        return remove_pkcs_padding(self.blocks_to_data(decrypted))

    def encrypt(
        self, data: Union[bytes, Tuple[int, int, int, int]]
    ) -> List[int]:
        """
        This functions performs RC6 encryption on only one block.

        This function returns a list of 4 integers.
        """

        if isinstance(data, bytes):
            _, data = self.get_blocks(data)
        a, b, c, d = data

        b = (b + self.rc6_key[0]) % self.modulo
        d = (d + self.rc6_key[1]) % self.modulo

        for i in range(1, self.rounds + 1):
            t = self.left_rotation(b * (2 * b + 1) % self.modulo, self.lgw)
            u = self.left_rotation(d * (2 * d + 1) % self.modulo, self.lgw)
            tmod = t % self.w_bit
            umod = u % self.w_bit
            a = (
                self.left_rotation(a ^ t, umod) + self.rc6_key[2 * i]
            ) % self.modulo
            c = (
                self.left_rotation(c ^ u, tmod) + self.rc6_key[2 * i + 1]
            ) % self.modulo
            a, b, c, d = b, c, d, a

        a = (a + self.rc6_key[self.round2_2]) % self.modulo
        c = (c + self.rc6_key[self.round2_3]) % self.modulo

        return [a, b, c, d]

    def decrypt(self, data: bytes) -> List[int]:
        """
        This function performs a RC6 decryption.
        """

        if isinstance(data, bytes):
            _, data = self.get_blocks(data)
        a, b, c, d = data

        c = (c - self.rc6_key[self.round2_3]) % self.modulo
        a = (a - self.rc6_key[self.round2_2]) % self.modulo

        for i in range(self.rounds, 0, -1):
            (a, b, c, d) = (d, a, b, c)
            u = self.left_rotation(d * (2 * d + 1) % self.modulo, self.lgw)
            t = self.left_rotation(b * (2 * b + 1) % self.modulo, self.lgw)
            tmod = t % self.w_bit
            umod = u % self.w_bit
            c = (
                self.right_rotation(
                    (c - self.rc6_key[2 * i + 1]) % self.modulo, tmod
                )
                ^ u
            )
            a = (
                self.right_rotation(
                    (a - self.rc6_key[2 * i]) % self.modulo, umod
                )
                ^ t
            )

        d = (d - self.rc6_key[1]) % self.modulo
        b = (b - self.rc6_key[0]) % self.modulo

        return [a, b, c, d]


def remove_pkcs_padding(data: bytes) -> bytes:
    """
    This function implements PKCS 5/7 padding.
    """

    return data[: data[-1] * -1]


def pkcs5_7padding(data: bytes, size: int = 16) -> bytes:
    """
    This function implements PKCS 5/7 padding.
    """

    mod = len(data) % size
    padding = size - mod
    data = data + padding.to_bytes() * padding
    return data


def parse_args() -> Namespace:
    """
    This function parse command line arguments.
    """

    parser = ArgumentParser(description="This script performs RC6 encryption.")

    parser.add_argument(
        "--mode",
        "-m",
        help=(
            "Ecryption mode, for CBC encryption IV"
            " is write on the first 16 bytes of the encrypted data."
        ),
        default="ECB",
        choices={"ECB", "CBC"},
    )

    parser.add_argument(
        "--decryption", "-d", help="Data decryption.", action="store_true"
    )

    input_ = parser.add_mutually_exclusive_group(required=True)
    input_.add_argument(
        "--input-file",
        "--i-file",
        "-i",
        type=FileType("rb"),
        default=stdin.buffer,
        help="The file to be encrypted.",
        nargs="?",
    )
    input_.add_argument(
        "--input-string", "--string", "-s", help="The string to be encrypted."
    )

    parser.add_argument(
        "--output-file",
        "--o-file",
        "-o",
        type=FileType("wb"),
        default=stdout.buffer,
        help="The output file.",
    )

    output_encoding = parser.add_mutually_exclusive_group()
    output_encoding.add_argument(
        "--base85",
        "--85",
        "-8",
        help="Base85 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--base64",
        "--64",
        "-6",
        help="Base64 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--base32",
        "--32",
        "-3",
        help="Base32 encoding as output format",
        action="store_true",
    )
    output_encoding.add_argument(
        "--base16",
        "--16",
        "-1",
        help="Base16 encoding as output format",
        action="store_true",
    )
    if uu_encoding:
        output_encoding.add_argument(
            "--uu",
            "-u",
            help="UU encoding as output format",
            action="store_true",
        )
    output_encoding.add_argument(
        "--output-encoding",
        "--o-encoding",
        "-e",
        help="Output encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"}
        if uu_encoding
        else {"base85", "base64", "base32", "base16"},
    )

    parser.add_argument(
        "--input-encoding",
        "--i-encoding",
        "-n",
        help="Input encoding.",
        choices={"base85", "base64", "base32", "base16", "uu"}
        if uu_encoding
        else {"base85", "base64", "base32", "base16"},
    )

    parser.add_argument(
        "--rounds", "-r", type=int, help="RC6 rounds", default=20
    )
    parser.add_argument(
        "--w-bit", "-b", type=int, help="RC6 w-bit", default=32
    )
    parser.add_argument(
        "--iv",
        "-I",
        help=(
            "IV for CBC mode only, for decryption"
            " if IV is not set the 16 first bytes are used instead."
        ),
    )
    parser.add_argument("--lgw", "-l", type=int, help="RC6 lgw", default=5)

    parser.add_argument(
        "--sha256",
        help="Use the sha256 hash of the key as the key.",
        action=BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("key", help="Encryption key.")

    arguments = parser.parse_args()

    if arguments.input_file is None:
        arguments.input_file = stdin

    return arguments


def output_encoding(data: bytes, arguments: Namespace) -> bytes:
    """
    This function returns encoded data.
    """

    if arguments.base85 or arguments.output_encoding == "base85":
        encoding = b85encode
    elif arguments.base64 or arguments.output_encoding == "base64":
        encoding = b64encode
    elif arguments.base32 or arguments.output_encoding == "base32":
        encoding = b32encode
    elif arguments.base16 or arguments.output_encoding == "base16":
        encoding = b16encode
    elif uu_encoding and (arguments.uu or arguments.output_encoding == "uu"):
        simplefilter("ignore")
        data = b2a_hqx(data)
        simplefilter("default")
        return data
    else:
        raise ValueError("Invalid encoding algorithm value")

    return encoding(data)


def input_encoding(data: bytes, encoding: str) -> bytes:
    """
    This function returns decoded data.
    """

    if encoding == "base85":
        decoding = b85decode
    elif encoding == "base64":
        decoding = b64decode
    elif encoding == "base32":
        decoding = b32decode
    elif encoding == "base16":
        decoding = b16decode
    elif uu_encoding and encoding == "uu":
        simplefilter("ignore")
        data = a2b_hqx(data)
        simplefilter("default")
        return data
    else:
        raise ValueError("Invalid encoding algorithm value")

    return decoding(data)


def get_key(arguments: Namespace) -> bytes:
    """
    This function returns the key (256 bits) using sha256
    by default or PKCS 5/7 for padding.
    """

    if arguments.sha256:
        return sha256(arguments.key.encode()).digest()
    else:
        return pkcs5_7padding(arguments.key.encode(), 16)[:16]


def get_data(arguments: Namespace) -> bytes:
    """
    This function returns data for encryption from arguments.
    """

    if arguments.input_string:
        data = arguments.input_string
    else:
        data = arguments.input_file.read()

    if arguments.input_encoding:
        data = input_encoding(data, arguments.input_encoding)

    return data


def get_encodings():
    """
    This function returns the probable encodings.
    """

    encoding = getpreferredencoding()
    if encoding is not None:
        yield encoding

    encoding = device_encoding(0)
    if encoding is not None:
        yield encoding

    yield "utf-8"  # Default for Linux
    yield "cp1252"  # Default for Windows
    yield "latin-1"  # Can read all files


def decode_output(data: bytes) -> str:
    """
    This function decode outputs (try somes encoding).
    """

    output = None
    for encoding in get_encodings():
        with suppress(UnicodeDecodeError):
            output = data.decode(encoding)
            return output


def main() -> int:
    """
    This function executes this file from the command line.
    """

    arguments = parse_args()

    if arguments.input_string:
        arguments.input_string = arguments.input_string.encode("utf-8")

    rc6 = RC6Encryption(
        get_key(arguments), arguments.rounds, arguments.w_bit, arguments.lgw
    )
    format_output = any(
        [
            arguments.base85,
            arguments.base64,
            arguments.base32,
            arguments.base16,
            arguments.uu if uu_encoding else None,
            arguments.output_encoding,
        ]
    )

    if arguments.mode == "ECB":
        function = (
            rc6.data_decryption_ECB
            if arguments.decryption
            else rc6.data_encryption_ECB
        )
        data = function(get_data(arguments))
    elif arguments.mode == "CBC":
        function = (
            rc6.data_decryption_CBC
            if arguments.decryption
            else rc6.data_encryption_CBC
        )
        if arguments.decryption and not arguments.iv:
            data = get_data(arguments)
            iv = data[:16]
            data = data[16:]
        else:
            iv = arguments.iv.encode()
            data = get_data(arguments)

        data = function(data, iv)

        if isinstance(data, tuple):
            data = b"".join(data)

    if format_output:
        data = output_encoding(data, arguments)

    arguments.output_file.write(data)
    return 0


def encrypt(message:str,key_length=128,round_count=20)->list[bytes,str]:
    key=randbytes(key_length//8)

    rc6 = RC6Encryption(key,rounds=round_count)
    
    res=rc6.data_encryption_ECB(bytes(message,encoding="utf-8"))
    return [key.hex(),res.hex()]

def decrypt(message:str,key:bytes,round_count=20)->str:

    rc6 = RC6Encryption(bytes.fromhex(key),rounds=round_count)
    res = rc6.data_decryption_ECB(bytes.fromhex(message))    
    return res.decode("utf-8")

if __name__ == '__main__':
    type = str(sys.argv[1])  # Takes number from command line argument
    
    if type=="encrypt":
        key,res=encrypt(sys.argv[2])
        print(key,res)
    else:
        res=decrypt(sys.argv[2],sys.argv[3])
        print(res)
    sys.stdout.flush()
"""Chrome Native Messaging framing: 4-byte little-endian length + UTF-8 JSON.

https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
Chrome -> host messages may be up to 64 MiB; host -> Chrome messages must stay under 1 MB.
"""

import json
import struct
from typing import BinaryIO

MAX_INCOMING = 64 * 1024 * 1024
MAX_OUTGOING = 1024 * 1024


class ProtocolError(Exception):
    pass


def read_message(stream: BinaryIO) -> dict | None:
    """Return the next message, or None when Chrome closed the pipe."""
    header = stream.read(4)
    if not header:
        return None
    if len(header) < 4:
        raise ProtocolError("truncated length header")
    (length,) = struct.unpack("<I", header)
    if length > MAX_INCOMING:
        raise ProtocolError(f"message too large: {length} bytes")
    payload = stream.read(length)
    if len(payload) < length:
        raise ProtocolError("truncated message body")
    msg = json.loads(payload.decode("utf-8"))
    if not isinstance(msg, dict):
        raise ProtocolError("message must be a JSON object")
    return msg


def encode_message(msg: dict) -> bytes:
    payload = json.dumps(msg, ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_OUTGOING:
        raise ProtocolError(f"reply too large: {len(payload)} bytes")
    return struct.pack("<I", len(payload)) + payload


def write_message(stream: BinaryIO, msg: dict) -> None:
    stream.write(encode_message(msg))
    stream.flush()

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


METHOD_NAMES = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

ACCESS_NAMES = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_ACCESS",
    2: "FILE_WRITE_ACCESS",
    3: "FILE_READ_WRITE_ACCESS",
}


@dataclass(slots=True)
class DecodedIoctl:
    device_type: int
    function: int
    method: int
    access: int
    method_name: str
    access_name: str
    is_vendor_device_type: bool
    is_vendor_function: bool

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["device_type"] = hex(self.device_type)
        payload["function"] = hex(self.function)
        return payload


def decode_ioctl(value: int) -> DecodedIoctl:
    method = value & 0x3
    function = (value >> 2) & 0xFFF
    access = (value >> 14) & 0x3
    device_type = (value >> 16) & 0xFFFF
    return DecodedIoctl(
        device_type=device_type,
        function=function,
        method=method,
        access=access,
        method_name=METHOD_NAMES.get(method, f"METHOD_{method}"),
        access_name=ACCESS_NAMES.get(access, f"ACCESS_{access}"),
        is_vendor_device_type=device_type >= 0x8000,
        is_vendor_function=function >= 0x800,
    )


def looks_like_ioctl(value: int) -> bool:
    # CTL_CODE packs DeviceType in bits 16-31, Access in bits 14-15,
    # Function in bits 2-13, Method in bits 0-1.
    if value <= 0xFFFF:
        return False
    decoded = decode_ioctl(value)
    return decoded.function != 0 and decoded.device_type != 0


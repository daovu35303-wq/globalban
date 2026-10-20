from __future__ import annotations

import ctypes
import ntpath
from typing import Literal


def _get_windows_system_directory() -> str:
    if not hasattr(ctypes, "WinDLL"):
        raise OSError("Windows system directory is available only on Windows")
    buffer = ctypes.create_unicode_buffer(32768)
    get_system_directory = getattr(ctypes, "WinDLL")(
        "kernel32", use_last_error=True
    ).GetSystemDirectoryW
    get_system_directory.argtypes = (ctypes.POINTER(ctypes.c_wchar), ctypes.c_uint)
    get_system_directory.restype = ctypes.c_uint
    length = get_system_directory(buffer, len(buffer))
    if length == 0:
        raise OSError(ctypes.get_last_error(), "GetSystemDirectoryW failed")
    if length >= len(buffer):
        raise OSError("Windows system directory path exceeds the supported length")
    return buffer.value


def windows_executable_path(name: Literal["netsh", "powershell.exe"]) -> str:
    system_directory = _get_windows_system_directory()
    if not ntpath.isabs(system_directory):
        raise OSError("Windows returned a non-absolute system directory")
    if name == "netsh":
        relative_path = ("netsh.exe",)
    elif name == "powershell.exe":
        relative_path = ("WindowsPowerShell", "v1.0", "powershell.exe")
    else:
        raise ValueError(f"Unsupported Windows executable: {name}")
    return ntpath.join(system_directory, *relative_path)

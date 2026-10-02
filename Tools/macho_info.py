#!/usr/bin/env python3
"""Report platform / minOS / sdk / arch slices of Mach-O files (fat or thin).

Usage: macho_info.py FILE...
"""
import struct
import sys

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_IPHONEOS = 0x25
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30

CPU_NAMES = {7: "i386", 12: "arm", 0x0100000C: "arm64", 0x01000007: "x86_64", 0x0200000C: "arm64_32"}
PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS", 6: "macCatalyst", 7: "iOSSimulator",
             8: "tvOSSimulator", 9: "watchOSSimulator", 10: "driverKit", 11: "visionOS", 12: "visionOSSimulator"}


def version_string(v):
    return "%d.%d.%d" % ((v >> 16) & 0xFFFF, (v >> 8) & 0xFF, v & 0xFF)


def read_slice(data, off):
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from("<IiiIIII", data, off)
    is64 = magic == MH_MAGIC_64
    out = {
        "arch": CPU_NAMES.get(cputype, hex(cputype)),
        "cpusubtype": cpusubtype & 0x00FFFFFF,
        "caps": hex(cpusubtype & 0xFF000000),
        "filetype": filetype,
        "platform": None,
        "minos": None,
        "sdk": None,
        "signature_off": None,
    }
    p = off + (32 if is64 else 28)
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, p)
        if cmd == LC_BUILD_VERSION:
            platform, minos, sdk, ntools = struct.unpack_from("<IIII", data, p + 8)
            out["platform"] = PLATFORMS.get(platform, platform)
            out["minos"] = version_string(minos)
            out["sdk"] = version_string(sdk)
        elif cmd == LC_VERSION_MIN_IPHONEOS:
            version, sdk = struct.unpack_from("<II", data, p + 8)
            out["platform"] = "iOS"
            out["minos"] = version_string(version)
            out["sdk"] = version_string(sdk)
        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            out["signature_off"] = struct.unpack_from("<II", data, p + 8)[0]
        p += cmdsize
    return out


def slices(data):
    if len(data) < 8:
        return []
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        nfat = struct.unpack_from(">I", data, 4)[0]
        is64 = magic == FAT_MAGIC_64
        out = []
        for i in range(nfat):
            base = 8 + i * (32 if is64 else 20)
            off, = struct.unpack_from(">I", data, base + 8)
            out.append(read_slice(data, off))
        return out
    return [read_slice(data, 0)]


def main():
    rc = 0
    for path in sys.argv[1:]:
        with open(path, "rb") as fh:
            data = fh.read()
        try:
            sl = slices(data)
        except Exception as exc:  # noqa: BLE001
            print("%s: not a Mach-O (%s)" % (path, exc))
            rc = 1
            continue
        print(path)
        for s in sl:
            print("  %-8s subtype=%d caps=%s filetype=%d platform=%s minos=%s sdk=%s sig@%s" % (
                s["arch"], s["cpusubtype"], s["caps"], s["filetype"], s["platform"], s["minos"],
                s["sdk"], s["signature_off"]))
    return rc


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Compact survey of an extracted kext: user-client classes + lifecycle strings."""
import re
import sys
import kx
import resolve as R

KEYS = ("externalMethod", "getTargetAndMethodForIndex", "IOExternalMethodDispatch",
        "sessionOpen", "sessionClose", "clientClose", "clientDied", "destroyClient",
        "clientHasPrivilege", "clientHasAuthorization", "entitle", "Entitle",
        "::free", "::stop", "::terminate", "release", "retain", "terminate",
        "IOUserClient", "UserClient", "selector", "payload", "copyBuffer",
        "IOBufferMemoryDescriptor", "IOMemoryDescriptor", "free()", "destroy")


def main():
    name = sys.argv[1]
    m = kx.MachO(kx.EXTRACT / name)
    syms = kx.load_symjson()
    print(f"===== {name} =====")
    print("-- user client-ish vtables in this kext --")
    # only the member's own writable segments (shared regions would match everything)
    own = [(s["vmaddr"], s["vmaddr"] + s["vmsize"]) for s in m.segments
           if s["name"] in ("__DATA", "__DATA_CONST")]
    for a, n in sorted(syms.items()):
        if any(lo <= a < hi for lo, hi in own) and ("UserClient" in n or "userClient" in n):
            print(f"   {a:#018x} {n}")
    print("-- selected cstrings --")
    for va, t in m.cstrings():
        if any(k in t for k in KEYS):
            print(f"   {va:#018x} {t}")


if __name__ == "__main__":
    main()

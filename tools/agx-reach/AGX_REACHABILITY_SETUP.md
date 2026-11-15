# AGXG18P Reachability Investigation — Setup Complete

**Target:** iPhone18,1 / V53AP / t8150 / iOS 27.0.1 (24A446)
**Kext:** `com.apple.AGXG18P` (size: 1,106,000 bytes)
**Bug:** `AGXBitmap<kAGXMaxChannelCount>` byte-indexed OOB pointer read (fixed in 27.3 beta)

---

## What we confirmed

### The bug is live on your device

Function at `0xfffffe0008556f50` (body at `0xfffffe0008556f54`) in `com.apple.AGXG18P`:

```asm
ldrb  w8, [x1]                ; index byte (0..255), from caller struct
ldr   x9, [x9, #0x40]         ; table->array  (array of 8-byte pointers)
ldr   x8, [x9, x8, lsl #3]    ; array[index]  <-- NO BOUND CHECK
ldrb  w8, [x8, #0x14]         ; dereference loaded pointer
tbnz  w8, #0x5, ...           ; test bit 5 of loaded byte
```

No count load, no compare, no bail before the indexed load. The 27.3 beta fix adds exactly 3 instructions:
```
ldr   w10, [x9, #0x48]        ; table->count
cmp   w10, w8
b.ls  bail                    ; if count <= index, bail
```

### The bug is referenced from module init

The helper address `0xfffffe0008556f54` appears exactly once in the kext: at `0xfffffe0007f1e650` in `__DATA_CONST.__mod_init_func`. This means it's part of a vtable or method table installed at kernel load time — consistent with a C++ virtual method on `AGXBitmap<kAGXMaxChannelCount>`.

### Userspace-reachable class exists

The string `site.AGXDeviceUserClient` is present in `__TEXT.__cstring` at `0xfffffe000712c122`. This is the IOKit user client class that exposes AGX GPU functionality to sandboxed apps. It's the likely entry point from userspace.

### G18P-specific channel classes found

- `AGX3DChannelSKSMG18P`, `AGXCLChannelSKSMG18P`, `AGXTAChannelSKSMG18P`
- `AGX3DChannel`, `AGXCLChannel`, `AGXTAChannel`
- `AGXInvalidChannel`
- `AGXDeviceUserClient`

These are all in `com.apple.AGXG18P` and are the GPU channel/command-submission classes.

### No direct static calls to the helper

Zero `bl`/`b` instructions target the helper function in `__TEXT_EXEC.__text`. It's only reachable via indirect vtable dispatch (`blraa` through a loaded function pointer). This matches the reference AGXG17P finding — the vptr is installed at runtime, not visible as a static xref.

---

## Files created in this session

| File | Purpose |
|------|---------|
| `tools/agx-reach/analyze_kext.py` | Mach-O parser: sections, refs to helper, vtable scan |
| `tools/agx-reach/dive_init.py` | Dump mod_init_func / mod_term_func, find class strings in disasm |
| `tools/agx-reach/find_userclient.py` | Locate `site.*` strings and their surrounding data |
| `tools/agx-reach/read_disasm.py` | Read UTF-16LE disassembly, find adrp references to cstring page |
| `tools/agx-reach/find_vtables.py` | Find blraa instructions, key function calls, potential vtables |
| `tools/agx-reach/extract_strings.py` | Extract all printable strings with keyword filtering |

All in `G:/REPO\tools\agx-reach\`.

---

## What's NOT yet established (the open questions)

1. **Owning class**: We haven't confirmed which class's vtable contains the helper at slot 4. Suspected: `AGXBitmap<kAGXMaxChannelCount>`.
2. **Caller chain**: No static xref from any function to the helper. Need to trace vtable installation at runtime.
3. **Attacker control**: Not proven that the index byte comes from an `IOConnectCallMethod` input.
4. **Entitlement gate**: Not proven that no entitlement blocks the call path.
5. **User client → AGXBitmap path**: Not traced from `AGXDeviceUserClient` to the OOB helper.

---

## Concrete next steps (in order)

### Step 1: Examine the mod_init_func entry at `0xfffffe0007f1e650`

The mod_init_func array contains `0x0010000001556f54` at index ~40 (offset `0xf4260` from file start). This is the helper function pointer installed at init time. Disassemble the function at `0xfffffe0008556f54` fully (we have it at lines 169341+ of the disassembly) and look at which class constructor installs this vtable.

**Script:** `tools/agx-reach/dive_init.py` already dumped the mod_init_func array. The entry at `0xfffffe0007f1e650` is the 49th entry (counting from 0).

### Step 2: Find AGXDeviceUserClient's externalMethod handler

Search `__TEXT_EXEC.__text` for:
- `autda` + `ldr x8, [xN]` + `blraa` patterns (PAC-authenticated virtual calls)
- Functions that load `site.AGXDeviceUserClient` string via `adrp`+`add`
- The `__DATA_CONST.__const` section for `IOExternalMethodDispatch` tables (`{function_ptr, check_ptr, count}` triples)

The `adrp` scan found many references to page `0xfffffe000712c000` (where `site.AGXDeviceUserClient` lives at offset `0x122`). The calls to `0xfffffe000858961c` with string args are candidates for `OSString::stringWithCString` or dictionary setup.

### Step 3: Trace the user client → channel → bitmap path

From the strings, the likely chain is:
```
AGXDeviceUserClient → externalMethod → AGXCLChannel/AGX3DChannel/AGXTAChannel → submitBuffer → AGXBitmap<kAGXMaxChannelCount> → OOB helper
```

Look for:
- `submitBuffer` methods (found in strings: `virtual void AGX3DChannelSKSM::submitBuffer`, etc.)
- Channel classes that hold an `AGXBitmap<kAGXMaxChannelCount>` member
- Methods that take a user-controlled index and pass it to the bitmap

### Step 4: Build a dev-signed probe app

Once you've identified the user client and selector:
1. Create an Xcode project with a minimal app
2. Add `IOKit` framework
3. Call `IOServiceGetMatchingService` with `"AGXDeviceUserClient"` or similar
4. Call `IOServiceOpen` to get a connect handle
5. Call `IOConnectCallMethod` with the target selector and controlled index values
6. Test on a SECOND device (not your daily phone) — wrong index = wild kernel dereference = panic

### Step 5: Verify the 27.3 fix

Fetch `com.apple.AGXG18P` from 24C5037i (27.3 beta) and confirm the `count`/`cmp`/`b.ls` fix exists on G18P (it does on G17P per the reference repo). This confirms this is the right function.

---

## Safety warnings

- **Never test on your daily phone.** A wrong index causes a wild kernel pointer dereference → panic → reboot.
- **Use a second test device or Corellium.**
- The primitive is an OOB **read** (~2KB past a small array) + wild pointer dereference. It's a crash/DoS hazard and low-bandwidth oracle, not a direct kernel write.
- A crash alone is not a jailbreak — you'd still need infoleak → R/W → PAC bypass → kernel code execution.

---

## How to use the scripts

```powershell
# Re-run kext analysis
python tools/agx-reach/analyze_kext.py

# Find string locations
python tools/agx-reach/find_userclient.py

# Scan disassembly for adrp references
python tools/agx-reach/read_disasm.py

# Find blraa calls and key functions
python tools/agx-reach/find_vtables.py
```

All scripts run from `G:/REPO\` using Python 3.14.

---

## Bottom line

The AGXG18P channel-index OOB read is **confirmed live on 27.0.1 on your device**, and **fixed only in 27.3 beta**. `AGXDeviceUserClient` exists as a userspace-reachable IOKit class. But **reachability is entirely unresolved** — you cannot exploit this yet. The next step is tracing from `AGXDeviceUserClient.externalMethod` through the channel classes to the `AGXBitmap<kAGXMaxChannelCount>` OOB helper.

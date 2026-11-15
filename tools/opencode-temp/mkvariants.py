#!/usr/bin/env python3
"""Generate syntax-bisect variants of ContentView-v96.swift."""
import io

src = io.open('ContentView-v96.swift', encoding='utf-8').read()

def w(name, text):
    io.open(name, 'w', encoding='utf-8', newline='\n').write(text)
    print('wrote', name, len(text))

# T1: remove the literal braces that sit inside the interpolated string
t1 = src.replace('out={outSet.0},\\(outSet.1),\\(outSet.2)}',
                 'out=[\\(outSet.0),\\(outSet.1),\\(outSet.2)]')
assert t1 != src, 'T1 no-op'
w('t1.swift', t1)

# T2: remove the .map { } closure that lives inside a string interpolation
old2 = 'emit("IOConnectCallMethod  = 0x\\(String(UInt64(bitPattern: infoIOK.dli_saddr), radix: 16))  (name \\(infoIOK.dli_sname.map { String(cString: $0) } ?? "?"))")'
new2 = 'emit("IOConnectCallMethod  = 0x\\(String(UInt64(bitPattern: infoIOK.dli_saddr), radix: 16))")'
t2 = src.replace(old2, new2)
assert t2 != src, 'T2 no-op'
w('t2.swift', t2)

# T3: drop the @_silgen_name method declarations
i = src.index('    // ---- IOKit entry points')
j = src.index('    typealias SetWrap')
t3 = src[:i] + src[j:]
w('t3.swift', t3)

# T4: flatten the nested withUnsafePointer closures
old4 = '''        let krSet = withUnsafePointer(to: &inSet) { ip in
            withUnsafeMutablePointer(to: &outSet) { op in
                withUnsafeMutablePointer(to: &outSize) { sp in
                    setWrap(conn, 0x11, UInt64(port), UnsafeRawPointer(ip), 3, 0, 0,
                            UnsafeMutableRawPointer(op), sp)
                }
            }
        }'''
new4 = '        let krSet = setWrap(conn, 0x11, UInt64(port), nil, 3, 0, 0, nil, 0)'
t4 = src.replace(old4, new4)
assert t4 != src, 'T4 no-op'
w('t4.swift', t4)

0xfffffe000b2c8050  7f2303d5 pacibsp  
0xfffffe000b2c8054  ff4301d1 sub      sp, sp, #0x50
0xfffffe000b2c8058  f65702a9 stp      x22, x21, [sp, #0x20]
0xfffffe000b2c805c  f44f03a9 stp      x20, x19, [sp, #0x30]
0xfffffe000b2c8060  fd7b04a9 stp      x29, x30, [sp, #0x40]
0xfffffe000b2c8064  fd030191 add      x29, sp, #0x40
0xfffffe000b2c8068  350c40f9 ldr      x21, [x1, #0x18]
0xfffffe000b2c806c  a80240f9 ldr      x8, [x21]
0xfffffe000b2c8070  093282d2 mov      x9, #0x1190
0xfffffe000b2c8074  2998abf2 movk     x9, #0x5cc1, lsl #16
0xfffffe000b2c8078  49f5c5f2 movk     x9, #0x2faa, lsl #32
0xfffffe000b2c807c  495ffef2 movk     x9, #0xf2fa, lsl #48
0xfffffe000b2c8080  1f0109eb cmp      x8, x9
0xfffffe000b2c8084  0c030054 b.gt     #0xfffffe000b2c80e4; -> 0xfffffe000b2c80e4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8088  e90d89d2 mov      x9, #0x486f
0xfffffe000b2c808c  0959a6f2 movk     x9, #0x32c8, lsl #16
0xfffffe000b2c8090  29b1d7f2 movk     x9, #0xbd89, lsl #32
0xfffffe000b2c8094  695ef9f2 movk     x9, #0xcaf3, lsl #48
0xfffffe000b2c8098  1f0109eb cmp      x8, x9
0xfffffe000b2c809c  40090054 b.eq     #0xfffffe000b2c81c4; -> 0xfffffe000b2c81c4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c80a0  295f92d2 mov      x9, #0x92f9
0xfffffe000b2c80a4  a973aef2 movk     x9, #0x739d, lsl #16
0xfffffe000b2c80a8  c933d9f2 movk     x9, #0xc99e, lsl #32
0xfffffe000b2c80ac  09fcf9f2 movk     x9, #0xcfe0, lsl #48
0xfffffe000b2c80b0  1f0109eb cmp      x8, x9
0xfffffe000b2c80b4  e1070054 b.ne     #0xfffffe000b2c81b0; -> 0xfffffe000b2c81b0 FUNC 0xfffffe000b2c8050
0xfffffe000b2c80b8  200440ad ldp      q0, q1, [x1]
0xfffffe000b2c80bc  e00700ad stp      q0, q1, [sp]
0xfffffe000b2c80c0  100700f0 adrp     x16, #0xfffffe000b3ab000; page 0xfffffe000b3ab000
0xfffffe000b2c80c4  10e20291 add      x16, x16, #0xb8; 0xfffffe000b3ab0b8 FUNC 0xfffffe000b3ab0b8
0xfffffe000b2c80c8  916e95d2 mov      x17, #0xab74
0xfffffe000b2c80cc  3002c1da pacia    x16, x17
0xfffffe000b2c80d0  e20310aa mov      x2, x16
0xfffffe000b2c80d4  e10300aa mov      x1, x0
0xfffffe000b2c80d8  e0030091 mov      x0, sp
0xfffffe000b2c80dc  83000094 bl       #0xfffffe000b2c82e8; CALL 0xfffffe000b2c82e8 sz=0x250 
0xfffffe000b2c80e0  7d000014 b        #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c80e4  89888cd2 mov      x9, #0x6444
0xfffffe000b2c80e8  8920b9f2 movk     x9, #0xc904, lsl #16
0xfffffe000b2c80ec  8926def2 movk     x9, #0xf134, lsl #32
0xfffffe000b2c80f0  29c1fef2 movk     x9, #0xf609, lsl #48
0xfffffe000b2c80f4  1f0109eb cmp      x8, x9
0xfffffe000b2c80f8  40080054 b.eq     #0xfffffe000b2c8200; -> 0xfffffe000b2c8200 FUNC 0xfffffe000b2c8050
0xfffffe000b2c80fc  293282d2 mov      x9, #0x1191
0xfffffe000b2c8100  2998abf2 movk     x9, #0x5cc1, lsl #16
0xfffffe000b2c8104  49f5c5f2 movk     x9, #0x2faa, lsl #32
0xfffffe000b2c8108  495ffef2 movk     x9, #0xf2fa, lsl #48
0xfffffe000b2c810c  1f0109eb cmp      x8, x9
0xfffffe000b2c8110  01050054 b.ne     #0xfffffe000b2c81b0; -> 0xfffffe000b2c81b0 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8114  e80300aa mov      x8, x0
0xfffffe000b2c8118  e0578052 mov      w0, #0x2bf
0xfffffe000b2c811c  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b2c8120  290040f9 ldr      x9, [x1]
0xfffffe000b2c8124  292140b9 ldr      w9, [x9, #0x20]
0xfffffe000b2c8128  3f050071 cmp      w9, #1
0xfffffe000b2c812c  410d0054 b.ne     #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8130  a90a40f9 ldr      x9, [x21, #0x10]
0xfffffe000b2c8134  3f0500f1 cmp      x9, #1
0xfffffe000b2c8138  e10c0054 b.ne     #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c813c  291040b9 ldr      w9, [x1, #0x10]
0xfffffe000b2c8140  3fb10971 cmp      w9, #0x26c
0xfffffe000b2c8144  830c0054 b.lo     #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8148  291440b9 ldr      w9, [x1, #0x14]
0xfffffe000b2c814c  3f510171 cmp      w9, #0x54
0xfffffe000b2c8150  230c0054 b.lo     #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8154  330440f9 ldr      x19, [x1, #8]
0xfffffe000b2c8158  a92a40b9 ldr      w9, [x21, #0x28]
0xfffffe000b2c815c  2281cc11 .byte    0x22, 0x81, 0xcc, 0x11
0xfffffe000b2c8160  a11240f9 ldr      x1, [x21, #0x20]
0xfffffe000b2c8164  a3e20091 add      x3, x21, #0x38
0xfffffe000b2c8168  64320191 add      x4, x19, #0x4c
0xfffffe000b2c816c  e00308aa mov      x0, x8
0xfffffe000b2c8170  32530394 bl       #0xfffffe000b39ce38; CALL 0xfffffe000b39ce38 sz=0xd8 
0xfffffe000b2c8174  000b0035 cbnz     w0, #0xfffffe000b2c82d4
0xfffffe000b2c8178  48eafd90 adrp     x8, #0xfffffe0007010000; page 0xfffffe0007010000
0xfffffe000b2c817c  0009c03d ldr      q0, [x8, #0x20]; [0xfffffe0007010020] ?
0xfffffe000b2c8180  6042833c stur     q0, [x19, #0x34]
0xfffffe000b2c8184  880a8052 mov      w8, #0x54
0xfffffe000b2c8188  680600b9 str      w8, [x19, #4]
0xfffffe000b2c818c  28eafdd0 adrp     x8, #0xfffffe000700e000; page 0xfffffe000700e000
0xfffffe000b2c8190  003943fd ldr      d0, [x8, #0x670]; [0xfffffe000700e670] ?
0xfffffe000b2c8194  60c201fc stur     d0, [x19, #0x1c]
0xfffffe000b2c8198  28008052 mov      w8, #1
0xfffffe000b2c819c  684204f8 stur     x8, [x19, #0x44]
0xfffffe000b2c81a0  682e40b9 ldr      w8, [x19, #0x2c]
0xfffffe000b2c81a4  085d0012 and      w8, w8, #0xffffff
0xfffffe000b2c81a8  682e00b9 str      w8, [x19, #0x2c]
0xfffffe000b2c81ac  4a000014 b        #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c81b0  200440ad ldp      q0, q1, [x1]
0xfffffe000b2c81b4  e00700ad stp      q0, q1, [sp]
0xfffffe000b2c81b8  e1030091 mov      x1, sp
0xfffffe000b2c81bc  04e4ff97 bl       #0xfffffe000b2c11cc; CALL 0xfffffe000b2c11cc sz=0x1b34 
0xfffffe000b2c81c0  45000014 b        #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c81c4  e0578052 mov      w0, #0x2bf
0xfffffe000b2c81c8  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b2c81cc  280040f9 ldr      x8, [x1]
0xfffffe000b2c81d0  082140b9 ldr      w8, [x8, #0x20]; [0xfffffe000700e020] ?
0xfffffe000b2c81d4  1f050071 cmp      w8, #1
0xfffffe000b2c81d8  e1070054 b.ne     #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c81dc  29204229 ldp      w9, w8, [x1, #0x10]
0xfffffe000b2c81e0  aa0a40f9 ldr      x10, [x21, #0x10]
0xfffffe000b2c81e4  5f0500f1 cmp      x10, #1
0xfffffe000b2c81e8  286dc81a .byte    0x28, 0x6d, 0xc8, 0x1a
0xfffffe000b2c81ec  890a8052 mov      w9, #0x54
0xfffffe000b2c81f0  0001497a ccmp     w8, w9, #0, eq
0xfffffe000b2c81f4  08200011 add      w8, w0, #8
0xfffffe000b2c81f8  0030881a csel     w0, w0, w8, lo
0xfffffe000b2c81fc  36000014 b        #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8200  e0578052 mov      w0, #0x2bf
0xfffffe000b2c8204  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b2c8208  280040f9 ldr      x8, [x1]
0xfffffe000b2c820c  082140b9 ldr      w8, [x8, #0x20]; [0xfffffe000700e020] ?
0xfffffe000b2c8210  1f090071 cmp      w8, #2
0xfffffe000b2c8214  01060054 b.ne     #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8218  a80a40f9 ldr      x8, [x21, #0x10]
0xfffffe000b2c821c  1f0900f1 cmp      x8, #2
0xfffffe000b2c8220  a1050054 b.ne     #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8224  281040b9 ldr      w8, [x1, #0x10]
0xfffffe000b2c8228  1f110471 cmp      w8, #0x104
0xfffffe000b2c822c  43050054 b.lo     #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8230  290440f9 ldr      x9, [x1, #8]
0xfffffe000b2c8234  a8ba40b9 ldr      w8, [x21, #0xb8]
0xfffffe000b2c8238  890000b4 cbz      x9, #0xfffffe000b2c8248
0xfffffe000b2c823c  291440b9 ldr      w9, [x1, #0x14]
0xfffffe000b2c8240  3ff10071 cmp      w9, #0x3c
0xfffffe000b2c8244  83040054 b.lo     #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8248  1341cc11 .byte    0x13, 0x41, 0xcc, 0x11
0xfffffe000b2c824c  b41240f9 ldr      x20, [x21, #0x20]
0xfffffe000b2c8250  b40200b4 cbz      x20, #0xfffffe000b2c82a4
0xfffffe000b2c8254  900240f9 ldr      x16, [x20]
0xfffffe000b2c8258  f10314aa mov      x17, x20
0xfffffe000b2c825c  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b2c8260  301ac1da autda    x16, x17
0xfffffe000b2c8264  088e43f8 ldr      x8, [x16, #0x38]!; [0xfffffe000b3ab0f0] ?
0xfffffe000b2c8268  e00314aa mov      x0, x20
0xfffffe000b2c826c  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b2c8270  10093fd7 blraa    x8, x16
0xfffffe000b2c8274  48270090 adrp     x8, #0xfffffe000b7b0000; page 0xfffffe000b7b0000
0xfffffe000b2c8278  08212991 add      x8, x8, #0xa48; 0xfffffe000b7b0a48 ?
0xfffffe000b2c827c  1f0008eb cmp      x0, x8
0xfffffe000b2c8280  a0010054 b.eq     #0xfffffe000b2c82b4; -> 0xfffffe000b2c82b4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c8284  000840f9 ldr      x0, [x0, #0x10]
0xfffffe000b2c8288  a0ffffb5 cbnz     x0, #0xfffffe000b2c827c
0xfffffe000b2c828c  a81240f9 ldr      x8, [x21, #0x20]
0xfffffe000b2c8290  e0578052 mov      w0, #0x2bf
0xfffffe000b2c8294  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b2c8298  680000b4 cbz      x8, #0xfffffe000b2c82a4
0xfffffe000b2c829c  000c0011 add      w0, w0, #3
0xfffffe000b2c82a0  0d000014 b        #0xfffffe000b2c82d4; -> 0xfffffe000b2c82d4 FUNC 0xfffffe000b2c8050
0xfffffe000b2c82a4  a12a40b9 ldr      w1, [x21, #0x28]
0xfffffe000b2c82a8  08028052 mov      w8, #0x10
0xfffffe000b2c82ac  080140f9 ldr      x8, [x8]; [0xfffffe000b7b0a48] ?
0xfffffe000b2c82b0  03000014 b        #0xfffffe000b2c82bc; -> 0xfffffe000b2c82bc FUNC 0xfffffe000b2c8050
0xfffffe000b2c82b4  a12a40b9 ldr      w1, [x21, #0x28]
0xfffffe000b2c82b8  880a40f9 ldr      x8, [x20, #0x10]
0xfffffe000b2c82bc  001940f9 ldr      x0, [x8, #0x30]; [0xfffffe000b7b0a78] ?
0xfffffe000b2c82c0  a2e20091 add      x2, x21, #0x38
0xfffffe000b2c82c4  e30313aa mov      x3, x19
0xfffffe000b2c82c8  04008052 mov      w4, #0
0xfffffe000b2c82cc  e1ca0294 bl       #0xfffffe000b37ae50; CALL 0xfffffe000b37ae50 sz=0x28c 'static IOReturn IOUserClient::_sendAsyncResult64(io_user_reference_t *, IOReturn, io_user_reference_t *, UInt32, IOOptio'
0xfffffe000b2c82d0  00008052 mov      w0, #0
0xfffffe000b2c82d4  fd7b44a9 ldp      x29, x30, [sp, #0x40]
0xfffffe000b2c82d8  f44f43a9 ldp      x20, x19, [sp, #0x30]
0xfffffe000b2c82dc  f65742a9 ldp      x22, x21, [sp, #0x20]
0xfffffe000b2c82e0  ff430191 add      sp, sp, #0x50
0xfffffe000b2c82e4  ff0f5fd6 retab    

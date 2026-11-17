0xfffffe000b31e234  7f2303d5 pacibsp  
0xfffffe000b31e238  ff4301d1 sub      sp, sp, #0x50
0xfffffe000b31e23c  f65702a9 stp      x22, x21, [sp, #0x20]
0xfffffe000b31e240  f44f03a9 stp      x20, x19, [sp, #0x30]
0xfffffe000b31e244  fd7b04a9 stp      x29, x30, [sp, #0x40]
0xfffffe000b31e248  fd030191 add      x29, sp, #0x40
0xfffffe000b31e24c  350c40f9 ldr      x21, [x1, #0x18]
0xfffffe000b31e250  a80240f9 ldr      x8, [x21]
0xfffffe000b31e254  093282d2 mov      x9, #0x1190
0xfffffe000b31e258  2998abf2 movk     x9, #0x5cc1, lsl #16
0xfffffe000b31e25c  49f5c5f2 movk     x9, #0x2faa, lsl #32
0xfffffe000b31e260  495ffef2 movk     x9, #0xf2fa, lsl #48
0xfffffe000b31e264  1f0109eb cmp      x8, x9
0xfffffe000b31e268  0c030054 b.gt     #0xfffffe000b31e2c8; -> 0xfffffe000b31e2c8 FUNC 0xfffffe000b31e234
0xfffffe000b31e26c  e90d89d2 mov      x9, #0x486f
0xfffffe000b31e270  0959a6f2 movk     x9, #0x32c8, lsl #16
0xfffffe000b31e274  29b1d7f2 movk     x9, #0xbd89, lsl #32
0xfffffe000b31e278  695ef9f2 movk     x9, #0xcaf3, lsl #48
0xfffffe000b31e27c  1f0109eb cmp      x8, x9
0xfffffe000b31e280  60090054 b.eq     #0xfffffe000b31e3ac; -> 0xfffffe000b31e3ac FUNC 0xfffffe000b31e234
0xfffffe000b31e284  295f92d2 mov      x9, #0x92f9
0xfffffe000b31e288  a973aef2 movk     x9, #0x739d, lsl #16
0xfffffe000b31e28c  c933d9f2 movk     x9, #0xc99e, lsl #32
0xfffffe000b31e290  09fcf9f2 movk     x9, #0xcfe0, lsl #48
0xfffffe000b31e294  1f0109eb cmp      x8, x9
0xfffffe000b31e298  01080054 b.ne     #0xfffffe000b31e398; -> 0xfffffe000b31e398 FUNC 0xfffffe000b31e234
0xfffffe000b31e29c  200440ad ldp      q0, q1, [x1]
0xfffffe000b31e2a0  e00700ad stp      q0, q1, [sp]
0xfffffe000b31e2a4  100700f0 adrp     x16, #0xfffffe000b401000; page 0xfffffe000b401000
0xfffffe000b31e2a8  10e21c91 add      x16, x16, #0x738; 0xfffffe000b401738 FUNC 0xfffffe000b401738
0xfffffe000b31e2ac  916e95d2 mov      x17, #0xab74
0xfffffe000b31e2b0  3002c1da pacia    x16, x17
0xfffffe000b31e2b4  e20310aa mov      x2, x16
0xfffffe000b31e2b8  e10300aa mov      x1, x0
0xfffffe000b31e2bc  e0030091 mov      x0, sp
0xfffffe000b31e2c0  88000094 bl       #0xfffffe000b31e4e0; CALL 0xfffffe000b31e4e0 sz=0x25c 
0xfffffe000b31e2c4  82000014 b        #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e2c8  89888cd2 mov      x9, #0x6444
0xfffffe000b31e2cc  8920b9f2 movk     x9, #0xc904, lsl #16
0xfffffe000b31e2d0  8926def2 movk     x9, #0xf134, lsl #32
0xfffffe000b31e2d4  29c1fef2 movk     x9, #0xf609, lsl #48
0xfffffe000b31e2d8  1f0109eb cmp      x8, x9
0xfffffe000b31e2dc  c0080054 b.eq     #0xfffffe000b31e3f4; -> 0xfffffe000b31e3f4 FUNC 0xfffffe000b31e234
0xfffffe000b31e2e0  293282d2 mov      x9, #0x1191
0xfffffe000b31e2e4  2998abf2 movk     x9, #0x5cc1, lsl #16
0xfffffe000b31e2e8  49f5c5f2 movk     x9, #0x2faa, lsl #32
0xfffffe000b31e2ec  495ffef2 movk     x9, #0xf2fa, lsl #48
0xfffffe000b31e2f0  1f0109eb cmp      x8, x9
0xfffffe000b31e2f4  21050054 b.ne     #0xfffffe000b31e398; -> 0xfffffe000b31e398 FUNC 0xfffffe000b31e234
0xfffffe000b31e2f8  e80300aa mov      x8, x0
0xfffffe000b31e2fc  e0578052 mov      w0, #0x2bf
0xfffffe000b31e300  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b31e304  2b4c40a9 ldp      x11, x19, [x1]
0xfffffe000b31e308  2a244229 ldp      w10, w9, [x1, #0x10]
0xfffffe000b31e30c  ac0640f9 ldr      x12, [x21, #8]
0xfffffe000b31e310  8cf97792 and      x12, x12, #0xfffffffffffffeff
0xfffffe000b31e314  ac0600f9 str      x12, [x21, #8]
0xfffffe000b31e318  6b2140b9 ldr      w11, [x11, #0x20]
0xfffffe000b31e31c  7f050071 cmp      w11, #1
0xfffffe000b31e320  610d0054 b.ne     #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e324  ab0a40f9 ldr      x11, [x21, #0x10]
0xfffffe000b31e328  7f0500f1 cmp      x11, #1
0xfffffe000b31e32c  010d0054 b.ne     #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e330  5fb10971 cmp      w10, #0x26c
0xfffffe000b31e334  c30c0054 b.lo     #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e338  3f510171 cmp      w9, #0x54
0xfffffe000b31e33c  830c0054 b.lo     #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e340  a92a40b9 ldr      w9, [x21, #0x28]
0xfffffe000b31e344  2281cc11 .byte    0x22, 0x81, 0xcc, 0x11
0xfffffe000b31e348  a11240f9 ldr      x1, [x21, #0x20]
0xfffffe000b31e34c  a3e20091 add      x3, x21, #0x38
0xfffffe000b31e350  64320191 add      x4, x19, #0x4c
0xfffffe000b31e354  e00308aa mov      x0, x8
0xfffffe000b31e358  d1530394 bl       #0xfffffe000b3f329c; CALL 0xfffffe000b3f329c sz=0xd8 
0xfffffe000b31e35c  800b0035 cbnz     w0, #0xfffffe000b31e4cc
0xfffffe000b31e360  88e7fdd0 adrp     x8, #0xfffffe0007010000; page 0xfffffe0007010000
0xfffffe000b31e364  000dc03d ldr      q0, [x8, #0x30]; [0xfffffe0007010030] ?
0xfffffe000b31e368  6042833c stur     q0, [x19, #0x34]
0xfffffe000b31e36c  880a8052 mov      w8, #0x54
0xfffffe000b31e370  680600b9 str      w8, [x19, #4]
0xfffffe000b31e374  88e7fd90 adrp     x8, #0xfffffe000700e000; page 0xfffffe000700e000
0xfffffe000b31e378  003943fd ldr      d0, [x8, #0x670]; [0xfffffe000700e670] ?
0xfffffe000b31e37c  60c201fc stur     d0, [x19, #0x1c]
0xfffffe000b31e380  28008052 mov      w8, #1
0xfffffe000b31e384  684204f8 stur     x8, [x19, #0x44]
0xfffffe000b31e388  682e40b9 ldr      w8, [x19, #0x2c]
0xfffffe000b31e38c  085d0012 and      w8, w8, #0xffffff
0xfffffe000b31e390  682e00b9 str      w8, [x19, #0x2c]
0xfffffe000b31e394  4e000014 b        #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e398  200440ad ldp      q0, q1, [x1]
0xfffffe000b31e39c  e00700ad stp      q0, q1, [sp]
0xfffffe000b31e3a0  e1030091 mov      x1, sp
0xfffffe000b31e3a4  d2e3ff97 bl       #0xfffffe000b3172ec; CALL 0xfffffe000b3172ec sz=0x18a4 
0xfffffe000b31e3a8  49000014 b        #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e3ac  e0578052 mov      w0, #0x2bf
0xfffffe000b31e3b0  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b31e3b4  2a0040f9 ldr      x10, [x1]
0xfffffe000b31e3b8  28244229 ldp      w8, w9, [x1, #0x10]
0xfffffe000b31e3bc  ab0640f9 ldr      x11, [x21, #8]
0xfffffe000b31e3c0  6bf97792 and      x11, x11, #0xfffffffffffffeff
0xfffffe000b31e3c4  ab0600f9 str      x11, [x21, #8]
0xfffffe000b31e3c8  4a2140b9 ldr      w10, [x10, #0x20]
0xfffffe000b31e3cc  5f050071 cmp      w10, #1
0xfffffe000b31e3d0  e1070054 b.ne     #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e3d4  aa0a40f9 ldr      x10, [x21, #0x10]
0xfffffe000b31e3d8  5f0500f1 cmp      x10, #1
0xfffffe000b31e3dc  086dc91a .byte    0x08, 0x6d, 0xc9, 0x1a
0xfffffe000b31e3e0  890a8052 mov      w9, #0x54
0xfffffe000b31e3e4  0001497a ccmp     w8, w9, #0, eq
0xfffffe000b31e3e8  08200011 add      w8, w0, #8
0xfffffe000b31e3ec  0030881a csel     w0, w0, w8, lo
0xfffffe000b31e3f0  37000014 b        #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e3f4  e0578052 mov      w0, #0x2bf
0xfffffe000b31e3f8  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b31e3fc  2b2440a9 ldp      x11, x9, [x1]
0xfffffe000b31e400  2a204229 ldp      w10, w8, [x1, #0x10]
0xfffffe000b31e404  ac0640f9 ldr      x12, [x21, #8]
0xfffffe000b31e408  8cf97792 and      x12, x12, #0xfffffffffffffeff
0xfffffe000b31e40c  ac0600f9 str      x12, [x21, #8]
0xfffffe000b31e410  6b2140b9 ldr      w11, [x11, #0x20]
0xfffffe000b31e414  7f090071 cmp      w11, #2
0xfffffe000b31e418  a1050054 b.ne     #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e41c  ab0a40f9 ldr      x11, [x21, #0x10]
0xfffffe000b31e420  7f0900f1 cmp      x11, #2
0xfffffe000b31e424  41050054 b.ne     #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e428  5f110471 cmp      w10, #0x104
0xfffffe000b31e42c  03050054 b.lo     #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e430  aaba40b9 ldr      w10, [x21, #0xb8]
0xfffffe000b31e434  690000b4 cbz      x9, #0xfffffe000b31e440
0xfffffe000b31e438  1ff10071 cmp      w8, #0x3c
0xfffffe000b31e43c  83040054 b.lo     #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e440  5341cc11 .byte    0x53, 0x41, 0xcc, 0x11
0xfffffe000b31e444  b41240f9 ldr      x20, [x21, #0x20]
0xfffffe000b31e448  b40200b4 cbz      x20, #0xfffffe000b31e49c
0xfffffe000b31e44c  900240f9 ldr      x16, [x20]
0xfffffe000b31e450  f10314aa mov      x17, x20
0xfffffe000b31e454  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b31e458  301ac1da autda    x16, x17
0xfffffe000b31e45c  088e43f8 ldr      x8, [x16, #0x38]!; [0xfffffe000b401770] ?
0xfffffe000b31e460  e00314aa mov      x0, x20
0xfffffe000b31e464  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b31e468  10093fd7 blraa    x8, x16
0xfffffe000b31e46c  482700d0 adrp     x8, #0xfffffe000b808000; page 0xfffffe000b808000
0xfffffe000b31e470  08212e91 add      x8, x8, #0xb88; 0xfffffe000b808b88 ?
0xfffffe000b31e474  1f0008eb cmp      x0, x8
0xfffffe000b31e478  a0010054 b.eq     #0xfffffe000b31e4ac; -> 0xfffffe000b31e4ac FUNC 0xfffffe000b31e234
0xfffffe000b31e47c  000840f9 ldr      x0, [x0, #0x10]
0xfffffe000b31e480  a0ffffb5 cbnz     x0, #0xfffffe000b31e474
0xfffffe000b31e484  a81240f9 ldr      x8, [x21, #0x20]
0xfffffe000b31e488  e0578052 mov      w0, #0x2bf
0xfffffe000b31e48c  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b31e490  680000b4 cbz      x8, #0xfffffe000b31e49c
0xfffffe000b31e494  000c0011 add      w0, w0, #3
0xfffffe000b31e498  0d000014 b        #0xfffffe000b31e4cc; -> 0xfffffe000b31e4cc FUNC 0xfffffe000b31e234
0xfffffe000b31e49c  a12a40b9 ldr      w1, [x21, #0x28]
0xfffffe000b31e4a0  08028052 mov      w8, #0x10
0xfffffe000b31e4a4  080140f9 ldr      x8, [x8]; [0xfffffe000b808b88] ?
0xfffffe000b31e4a8  03000014 b        #0xfffffe000b31e4b4; -> 0xfffffe000b31e4b4 FUNC 0xfffffe000b31e234
0xfffffe000b31e4ac  a12a40b9 ldr      w1, [x21, #0x28]
0xfffffe000b31e4b0  880a40f9 ldr      x8, [x20, #0x10]
0xfffffe000b31e4b4  001940f9 ldr      x0, [x8, #0x30]; [0xfffffe000b808bb8] ?
0xfffffe000b31e4b8  a2e20091 add      x2, x21, #0x38
0xfffffe000b31e4bc  e30313aa mov      x3, x19
0xfffffe000b31e4c0  04008052 mov      w4, #0
0xfffffe000b31e4c4  7ecb0294 bl       #0xfffffe000b3d12bc; CALL 0xfffffe000b3d12bc sz=0x28c 'static IOReturn IOUserClient::_sendAsyncResult64(io_user_reference_t *, IOReturn, io_user_reference_t *, UInt32, IOOptio'
0xfffffe000b31e4c8  00008052 mov      w0, #0
0xfffffe000b31e4cc  fd7b44a9 ldp      x29, x30, [sp, #0x40]
0xfffffe000b31e4d0  f44f43a9 ldp      x20, x19, [sp, #0x30]
0xfffffe000b31e4d4  f65742a9 ldp      x22, x21, [sp, #0x20]
0xfffffe000b31e4d8  ff430191 add      sp, sp, #0x50
0xfffffe000b31e4dc  ff0f5fd6 retab    

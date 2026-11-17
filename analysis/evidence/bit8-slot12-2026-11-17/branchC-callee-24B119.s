0xfffffe000b31e4e0  7f2303d5 pacibsp  
0xfffffe000b31e4e4  ff0302d1 sub      sp, sp, #0x80
0xfffffe000b31e4e8  fa6703a9 stp      x26, x25, [sp, #0x30]
0xfffffe000b31e4ec  f85f04a9 stp      x24, x23, [sp, #0x40]
0xfffffe000b31e4f0  f65705a9 stp      x22, x21, [sp, #0x50]
0xfffffe000b31e4f4  f44f06a9 stp      x20, x19, [sp, #0x60]
0xfffffe000b31e4f8  fd7b07a9 stp      x29, x30, [sp, #0x70]
0xfffffe000b31e4fc  fdc30191 add      x29, sp, #0x70
0xfffffe000b31e500  4a588052 mov      w10, #0x2c2
0xfffffe000b31e504  0a00bc72 movk     w10, #0xe000, lsl #16
0xfffffe000b31e508  0b6040a9 ldp      x11, x24, [x0]
0xfffffe000b31e50c  09204229 ldp      w9, w8, [x0, #0x10]
0xfffffe000b31e510  190c40f9 ldr      x25, [x0, #0x18]
0xfffffe000b31e514  2c0740f9 ldr      x12, [x25, #8]
0xfffffe000b31e518  8cf97792 and      x12, x12, #0xfffffffffffffeff
0xfffffe000b31e51c  2c0700f9 str      x12, [x25, #8]
0xfffffe000b31e520  3a335a29 ldp      w26, w12, [x25, #0xd0]
0xfffffe000b31e524  8c41cc11 .byte    0x8c, 0x41, 0xcc, 0x11
0xfffffe000b31e528  ec2f00b9 str      w12, [sp, #0x2c]
0xfffffe000b31e52c  6b2140b9 ldr      w11, [x11, #0x20]
0xfffffe000b31e530  400d0051 sub      w0, w10, #3
0xfffffe000b31e534  7f150071 cmp      w11, #5
0xfffffe000b31e538  410f0054 b.ne     #0xfffffe000b31e720; -> 0xfffffe000b31e720 FUNC 0xfffffe000b31e4e0
0xfffffe000b31e53c  2a0b40f9 ldr      x10, [x25, #0x10]
0xfffffe000b31e540  5f1500f1 cmp      x10, #5
0xfffffe000b31e544  e10e0054 b.ne     #0xfffffe000b31e720; -> 0xfffffe000b31e720 FUNC 0xfffffe000b31e4e0
0xfffffe000b31e548  3f510571 cmp      w9, #0x154
0xfffffe000b31e54c  a30e0054 b.lo     #0xfffffe000b31e720; -> 0xfffffe000b31e720 FUNC 0xfffffe000b31e4e0
0xfffffe000b31e550  1f910371 cmp      w8, #0xe4
0xfffffe000b31e554  630e0054 b.lo     #0xfffffe000b31e720; -> 0xfffffe000b31e720 FUNC 0xfffffe000b31e4e0
0xfffffe000b31e558  f30302aa mov      x19, x2
0xfffffe000b31e55c  f40301aa mov      x20, x1
0xfffffe000b31e560  201340f9 ldr      x0, [x25, #0x20]
0xfffffe000b31e564  e00100b4 cbz      x0, #0xfffffe000b31e5a0
0xfffffe000b31e568  100040f9 ldr      x16, [x0]
0xfffffe000b31e56c  f10300aa mov      x17, x0
0xfffffe000b31e570  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b31e574  301ac1da autda    x16, x17
0xfffffe000b31e578  088e43f8 ldr      x8, [x16, #0x38]!
0xfffffe000b31e57c  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b31e580  10093fd7 blraa    x8, x16
0xfffffe000b31e584  482700d0 adrp     x8, #0xfffffe000b808000; page 0xfffffe000b808000
0xfffffe000b31e588  08a10c91 add      x8, x8, #0x328; 0xfffffe000b808328 ?
0xfffffe000b31e58c  1f0008eb cmp      x0, x8
0xfffffe000b31e590  80000054 b.eq     #0xfffffe000b31e5a0; -> 0xfffffe000b31e5a0 FUNC 0xfffffe000b31e4e0
0xfffffe000b31e594  000840f9 ldr      x0, [x0, #0x10]
0xfffffe000b31e598  a0ffffb5 cbnz     x0, #0xfffffe000b31e58c
0xfffffe000b31e59c  24000014 b        #0xfffffe000b31e62c; -> 0xfffffe000b31e62c FUNC 0xfffffe000b31e4e0
0xfffffe000b31e5a0  351740f9 ldr      x21, [x25, #0x28]
0xfffffe000b31e5a4  572700f0 adrp     x23, #0xfffffe000b809000; page 0xfffffe000b809000
0xfffffe000b31e5a8  f7422291 add      x23, x23, #0x890; 0xfffffe000b809890 ?
0xfffffe000b31e5ac  150200b4 cbz      x21, #0xfffffe000b31e5ec
0xfffffe000b31e5b0  b00240f9 ldr      x16, [x21]
0xfffffe000b31e5b4  f10315aa mov      x17, x21
0xfffffe000b31e5b8  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b31e5bc  301ac1da autda    x16, x17
0xfffffe000b31e5c0  088e43f8 ldr      x8, [x16, #0x38]!
0xfffffe000b31e5c4  e00315aa mov      x0, x21
0xfffffe000b31e5c8  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b31e5cc  10093fd7 blraa    x8, x16
0xfffffe000b31e5d0  1f0017eb cmp      x0, x23
0xfffffe000b31e5d4  c0000054 b.eq     #0xfffffe000b31e5ec; -> 0xfffffe000b31e5ec FUNC 0xfffffe000b31e4e0
0xfffffe000b31e5d8  000840f9 ldr      x0, [x0, #0x10]
0xfffffe000b31e5dc  a0ffffb5 cbnz     x0, #0xfffffe000b31e5d0
0xfffffe000b31e5e0  281740f9 ldr      x8, [x25, #0x28]
0xfffffe000b31e5e4  480200b5 cbnz     x8, #0xfffffe000b31e62c
0xfffffe000b31e5e8  150080d2 mov      x21, #0
0xfffffe000b31e5ec  361b40f9 ldr      x22, [x25, #0x30]
0xfffffe000b31e5f0  760200b4 cbz      x22, #0xfffffe000b31e63c
0xfffffe000b31e5f4  d00240f9 ldr      x16, [x22]
0xfffffe000b31e5f8  f10316aa mov      x17, x22
0xfffffe000b31e5fc  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b31e600  301ac1da autda    x16, x17
0xfffffe000b31e604  088e43f8 ldr      x8, [x16, #0x38]!
0xfffffe000b31e608  e00316aa mov      x0, x22
0xfffffe000b31e60c  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b31e610  10093fd7 blraa    x8, x16
0xfffffe000b31e614  1f0017eb cmp      x0, x23
0xfffffe000b31e618  20010054 b.eq     #0xfffffe000b31e63c; -> 0xfffffe000b31e63c FUNC 0xfffffe000b31e4e0
0xfffffe000b31e61c  000840f9 ldr      x0, [x0, #0x10]
0xfffffe000b31e620  a0ffffb5 cbnz     x0, #0xfffffe000b31e614
0xfffffe000b31e624  281b40f9 ldr      x8, [x25, #0x30]
0xfffffe000b31e628  880000b4 cbz      x8, #0xfffffe000b31e638
0xfffffe000b31e62c  40588052 mov      w0, #0x2c2
0xfffffe000b31e630  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b31e634  3b000014 b        #0xfffffe000b31e720; -> 0xfffffe000b31e720 FUNC 0xfffffe000b31e4e0
0xfffffe000b31e638  160080d2 mov      x22, #0
0xfffffe000b31e63c  371f40f9 ldr      x23, [x25, #0x38]
0xfffffe000b31e640  970200b4 cbz      x23, #0xfffffe000b31e690
0xfffffe000b31e644  f00240f9 ldr      x16, [x23]; [0xfffffe000b809890] ?
0xfffffe000b31e648  f10317aa mov      x17, x23
0xfffffe000b31e64c  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b31e650  301ac1da autda    x16, x17
0xfffffe000b31e654  088e43f8 ldr      x8, [x16, #0x38]!
0xfffffe000b31e658  e00317aa mov      x0, x23
0xfffffe000b31e65c  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b31e660  10093fd7 blraa    x8, x16
0xfffffe000b31e664  482700d0 adrp     x8, #0xfffffe000b808000; page 0xfffffe000b808000
0xfffffe000b31e668  08c12e91 add      x8, x8, #0xbb0; 0xfffffe000b808bb0 ?
0xfffffe000b31e66c  1f0008eb cmp      x0, x8
0xfffffe000b31e670  00010054 b.eq     #0xfffffe000b31e690; -> 0xfffffe000b31e690 FUNC 0xfffffe000b31e4e0
0xfffffe000b31e674  000840f9 ldr      x0, [x0, #0x10]
0xfffffe000b31e678  a0ffffb5 cbnz     x0, #0xfffffe000b31e66c
0xfffffe000b31e67c  281f40f9 ldr      x8, [x25, #0x38]
0xfffffe000b31e680  40588052 mov      w0, #0x2c2
0xfffffe000b31e684  0000bc72 movk     w0, #0xe000, lsl #16
0xfffffe000b31e688  c80400b5 cbnz     x8, #0xfffffe000b31e720
0xfffffe000b31e68c  170080d2 mov      x23, #0
0xfffffe000b31e690  4343cc11 .byte    0x43, 0x43, 0xcc, 0x11
0xfffffe000b31e694  212340f9 ldr      x1, [x25, #0x40]
0xfffffe000b31e698  241340f9 ldr      x4, [x25, #0x20]
0xfffffe000b31e69c  08330191 add      x8, x24, #0x4c
0xfffffe000b31e6a0  296f40f9 ldr      x9, [x25, #0xd8]
0xfffffe000b31e6a4  f65f01a9 stp      x22, x23, [sp, #0x10]
0xfffffe000b31e6a8  22430191 add      x2, x25, #0x50
0xfffffe000b31e6ac  06730191 add      x6, x24, #0x5c
0xfffffe000b31e6b0  e7b30091 add      x7, sp, #0x2c
0xfffffe000b31e6b4  e92300a9 stp      x9, x8, [sp]
0xfffffe000b31e6b8  e00314aa mov      x0, x20
0xfffffe000b31e6bc  e50315aa mov      x5, x21
0xfffffe000b31e6c0  916e95d2 mov      x17, #0xab74
0xfffffe000b31e6c4  710a3fd7 blraa    x19, x17
0xfffffe000b31e6c8  c0020035 cbnz     w0, #0xfffffe000b31e720
0xfffffe000b31e6cc  88e7fdd0 adrp     x8, #0xfffffe0007010000; page 0xfffffe0007010000
0xfffffe000b31e6d0  0011c03d ldr      q0, [x8, #0x40]; [0xfffffe0007010040] ?
0xfffffe000b31e6d4  0043833c stur     q0, [x24, #0x34]
0xfffffe000b31e6d8  881c8052 mov      w8, #0xe4
0xfffffe000b31e6dc  080700b9 str      w8, [x24, #4]
0xfffffe000b31e6e0  88e7fd90 adrp     x8, #0xfffffe000700e000; page 0xfffffe000700e000
0xfffffe000b31e6e4  003943fd ldr      d0, [x8, #0x670]; [0xfffffe000700e670] ?
0xfffffe000b31e6e8  00c301fc stur     d0, [x24, #0x1c]
0xfffffe000b31e6ec  28008052 mov      w8, #1
0xfffffe000b31e6f0  084304f8 stur     x8, [x24, #0x44]
0xfffffe000b31e6f4  e82f40b9 ldr      w8, [sp, #0x2c]
0xfffffe000b31e6f8  08df00b9 str      w8, [x24, #0xdc]
0xfffffe000b31e6fc  10930091 add      x16, x24, #0x24
0xfffffe000b31e700  082f40b9 ldr      w8, [x24, #0x2c]
0xfffffe000b31e704  089d0012 and      w8, w8, #0xff00ff
0xfffffe000b31e708  08810832 orr      w8, w8, #0x1000100
0xfffffe000b31e70c  08ff0529 stp      w8, wzr, [x24, #0x2c]
0xfffffe000b31e710  f0a9ebf2 movk     x16, #0x5d4f, lsl #48
0xfffffe000b31e714  11038052 mov      w17, #0x18
0xfffffe000b31e718  110ac1da pacda    x17, x16
0xfffffe000b31e71c  114302f8 stur     x17, [x24, #0x24]
0xfffffe000b31e720  fd7b47a9 ldp      x29, x30, [sp, #0x70]
0xfffffe000b31e724  f44f46a9 ldp      x20, x19, [sp, #0x60]
0xfffffe000b31e728  f65745a9 ldp      x22, x21, [sp, #0x50]
0xfffffe000b31e72c  f85f44a9 ldp      x24, x23, [sp, #0x40]
0xfffffe000b31e730  fa6743a9 ldp      x26, x25, [sp, #0x30]
0xfffffe000b31e734  ff030291 add      sp, sp, #0x80
0xfffffe000b31e738  ff0f5fd6 retab    

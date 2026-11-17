0xfffffe000b3a5fd0  7f2303d5 pacibsp  
0xfffffe000b3a5fd4  ff8303d1 sub      sp, sp, #0xe0
0xfffffe000b3a5fd8  fc6f08a9 stp      x28, x27, [sp, #0x80]
0xfffffe000b3a5fdc  fa6709a9 stp      x26, x25, [sp, #0x90]
0xfffffe000b3a5fe0  f85f0aa9 stp      x24, x23, [sp, #0xa0]
0xfffffe000b3a5fe4  f6570ba9 stp      x22, x21, [sp, #0xb0]
0xfffffe000b3a5fe8  f44f0ca9 stp      x20, x19, [sp, #0xc0]
0xfffffe000b3a5fec  fd7b0da9 stp      x29, x30, [sp, #0xd0]
0xfffffe000b3a5ff0  fd430391 add      x29, sp, #0xd0
0xfffffe000b3a5ff4  f50306aa mov      x21, x6
0xfffffe000b3a5ff8  f60304aa mov      x22, x4
0xfffffe000b3a5ffc  f80302aa mov      x24, x2
0xfffffe000b3a6000  f40301aa mov      x20, x1
0xfffffe000b3a6004  f70300aa mov      x23, x0
0xfffffe000b3a6008  e00302aa mov      x0, x2
0xfffffe000b3a600c  bf4eff97 bl       #0xfffffe000b379b08; CALL 0xfffffe000b379b08 sz=0x4c 
0xfffffe000b3a6010  f30300aa mov      x19, x0
0xfffffe000b3a6014  000600b4 cbz      x0, #0xfffffe000b3a60d4
0xfffffe000b3a6018  e1e4fdd0 adrp     x1, #0xfffffe0007044000; page 0xfffffe0007044000
0xfffffe000b3a601c  21681f91 add      x1, x1, #0x7da; 0xfffffe00070447da STR "root"
0xfffffe000b3a6020  e00318aa mov      x0, x24
0xfffffe000b3a6024  e44cff97 bl       #0xfffffe000b3793b4; CALL 0xfffffe000b3793b4 sz=0x534 'consolesession'; 'secureprocess'; 'foreground'
0xfffffe000b3a6028  e0010035 cbnz     w0, #0xfffffe000b3a6064
0xfffffe000b3a602c  88250090 adrp     x8, #0xfffffe000b856000; page 0xfffffe000b856000
0xfffffe000b3a6030  02bd40f9 ldr      x2, [x8, #0x178]; [0xfffffe000b856178] ?
0xfffffe000b3a6034  700240f9 ldr      x16, [x19]
0xfffffe000b3a6038  f10313aa mov      x17, x19
0xfffffe000b3a603c  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a6040  301ac1da autda    x16, x17
0xfffffe000b3a6044  112080d2 mov      x17, #0x100
0xfffffe000b3a6048  1002118b add      x16, x16, x17
0xfffffe000b3a604c  080240f9 ldr      x8, [x16]
0xfffffe000b3a6050  01e9fdb0 adrp     x1, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a6054  21543791 add      x1, x1, #0xdd5; 0xfffffe00070c7dd5 STR "com.apple.developer.driverkit.administrator"
0xfffffe000b3a6058  e00313aa mov      x0, x19
0xfffffe000b3a605c  7064f8f2 movk     x16, #0xc323, lsl #48
0xfffffe000b3a6060  10093fd7 blraa    x8, x16
0xfffffe000b3a6064  2394e297 bl       #0xfffffe000ac4b0f0; CALL 0xfffffe000ac4b0f0 sz=0x98 
0xfffffe000b3a6068  080c40f9 ldr      x8, [x0, #0x18]
0xfffffe000b3a606c  080600b4 cbz      x8, #0xfffffe000b3a612c
0xfffffe000b3a6070  895afed0 adrp     x9, #0xfffffe0007ef8000; page 0xfffffe0007ef8000
0xfffffe000b3a6074  295947f9 ldr      x9, [x9, #0xeb0]; [0xfffffe0007ef8eb0] ?
0xfffffe000b3a6078  1f0109eb cmp      x8, x9
0xfffffe000b3a607c  80050054 b.eq     #0xfffffe000b3a612c; -> 0xfffffe000b3a612c FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a6080  006140b9 ldr      w0, [x8, #0x60]; [0xfffffe000b856060] ?
0xfffffe000b3a6084  4abafc97 bl       #0xfffffe000b2d49ac; CALL 0xfffffe000b2d49ac sz=0x134 'pid %d, '
0xfffffe000b3a6088  800500b4 cbz      x0, #0xfffffe000b3a6138
0xfffffe000b3a608c  f90300aa mov      x25, x0
0xfffffe000b3a6090  700240f9 ldr      x16, [x19]
0xfffffe000b3a6094  f10313aa mov      x17, x19
0xfffffe000b3a6098  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a609c  301ac1da autda    x16, x17
0xfffffe000b3a60a0  112080d2 mov      x17, #0x100
0xfffffe000b3a60a4  1002118b add      x16, x16, x17
0xfffffe000b3a60a8  080240f9 ldr      x8, [x16]
0xfffffe000b3a60ac  01e9fdb0 adrp     x1, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a60b0  21043891 add      x1, x1, #0xe01; 0xfffffe00070c7e01 STR "IOUserClientCreator"
0xfffffe000b3a60b4  e00313aa mov      x0, x19
0xfffffe000b3a60b8  e20319aa mov      x2, x25
0xfffffe000b3a60bc  7064f8f2 movk     x16, #0xc323, lsl #48
0xfffffe000b3a60c0  10093fd7 blraa    x8, x16
0xfffffe000b3a60c4  e80319aa mov      x8, x25
0xfffffe000b3a60c8  28b4f9f2 movk     x8, #0xcda1, lsl #48
0xfffffe000b3a60cc  3a008052 mov      w26, #1
0xfffffe000b3a60d0  23000014 b        #0xfffffe000b3a615c; -> 0xfffffe000b3a615c FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a60d4  402000d0 adrp     x0, #0xfffffe000b7b0000; page 0xfffffe000b7b0000
0xfffffe000b3a60d8  00400891 add      x0, x0, #0x210; 0xfffffe000b7b0210 ?
0xfffffe000b3a60dc  100040f9 ldr      x16, [x0]; [0xfffffe000b7b0210] ?
0xfffffe000b3a60e0  f10300aa mov      x17, x0
0xfffffe000b3a60e4  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a60e8  301ac1da autda    x16, x17
0xfffffe000b3a60ec  088e46f8 ldr      x8, [x16, #0x68]!
0xfffffe000b3a60f0  30c0e2f2 movk     x16, #0x1601, lsl #48
0xfffffe000b3a60f4  10093fd7 blraa    x8, x16
0xfffffe000b3a60f8  400200b4 cbz      x0, #0xfffffe000b3a6140
0xfffffe000b3a60fc  f90300aa mov      x25, x0
0xfffffe000b3a6100  100040f9 ldr      x16, [x0]; [0xfffffe000b7b0210] ?
0xfffffe000b3a6104  f10300aa mov      x17, x0
0xfffffe000b3a6108  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a610c  301ac1da autda    x16, x17
0xfffffe000b3a6110  080e4df8 ldr      x8, [x16, #0xd0]!
0xfffffe000b3a6114  01018052 mov      w1, #8
0xfffffe000b3a6118  5080f3f2 movk     x16, #0x9c02, lsl #48
0xfffffe000b3a611c  10093fd7 blraa    x8, x16
0xfffffe000b3a6120  60010034 cbz      w0, #0xfffffe000b3a614c
0xfffffe000b3a6124  f30319aa mov      x19, x25
0xfffffe000b3a6128  bcffff17 b        #0xfffffe000b3a6018; -> 0xfffffe000b3a6018 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a612c  00008052 mov      w0, #0
0xfffffe000b3a6130  1fbafc97 bl       #0xfffffe000b2d49ac; CALL 0xfffffe000b2d49ac sz=0x134 'pid %d, '
0xfffffe000b3a6134  c0faffb5 cbnz     x0, #0xfffffe000b3a608c
0xfffffe000b3a6138  3a008052 mov      w26, #1
0xfffffe000b3a613c  0e000014 b        #0xfffffe000b3a6174; -> 0xfffffe000b3a6174 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a6140  1a008052 mov      w26, #0
0xfffffe000b3a6144  130080d2 mov      x19, #0
0xfffffe000b3a6148  0b000014 b        #0xfffffe000b3a6174; -> 0xfffffe000b3a6174 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a614c  1a008052 mov      w26, #0
0xfffffe000b3a6150  130080d2 mov      x19, #0
0xfffffe000b3a6154  e80319aa mov      x8, x25
0xfffffe000b3a6158  28b4f9f2 movk     x8, #0xcda1, lsl #48
0xfffffe000b3a615c  300340f9 ldr      x16, [x25]
0xfffffe000b3a6160  1019c1da autda    x16, x8
0xfffffe000b3a6164  088e42f8 ldr      x8, [x16, #0x28]!
0xfffffe000b3a6168  e00319aa mov      x0, x25
0xfffffe000b3a616c  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3a6170  10093fd7 blraa    x8, x16
0xfffffe000b3a6174  bf831af8 stur     xzr, [x29, #-0x58]
0xfffffe000b3a6178  bf0200f9 str      xzr, [x21]
0xfffffe000b3a617c  a36301d1 sub      x3, x29, #0x58
0xfffffe000b3a6180  e00314aa mov      x0, x20
0xfffffe000b3a6184  e10316aa mov      x1, x22
0xfffffe000b3a6188  e20313aa mov      x2, x19
0xfffffe000b3a618c  040080d2 mov      x4, #0
0xfffffe000b3a6190  f181fc97 bl       #0xfffffe000b2c6954; CALL 0xfffffe000b2c6954 sz=0x1bc 
0xfffffe000b3a6194  f90300aa mov      x25, x0
0xfffffe000b3a6198  b6835af8 ldur     x22, [x29, #-0x58]
0xfffffe000b3a619c  a0040035 cbnz     w0, #0xfffffe000b3a6230
0xfffffe000b3a61a0  960400b4 cbz      x22, #0xfffffe000b3a6230
0xfffffe000b3a61a4  d00240f9 ldr      x16, [x22]
0xfffffe000b3a61a8  fb0316aa mov      x27, x22
0xfffffe000b3a61ac  3bb4f9f2 movk     x27, #0xcda1, lsl #48
0xfffffe000b3a61b0  f10316aa mov      x17, x22
0xfffffe000b3a61b4  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a61b8  301ac1da autda    x16, x17
0xfffffe000b3a61bc  088e43f8 ldr      x8, [x16, #0x38]!
0xfffffe000b3a61c0  e00316aa mov      x0, x22
0xfffffe000b3a61c4  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b3a61c8  10093fd7 blraa    x8, x16
0xfffffe000b3a61cc  68200090 adrp     x8, #0xfffffe000b7b2000; page 0xfffffe000b7b2000
0xfffffe000b3a61d0  08e11e91 add      x8, x8, #0x7b8; 0xfffffe000b7b27b8 ?
0xfffffe000b3a61d4  1f0008eb cmp      x0, x8
0xfffffe000b3a61d8  40050054 b.eq     #0xfffffe000b3a6280; -> 0xfffffe000b3a6280 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a61dc  000840f9 ldr      x0, [x0, #0x10]; [0xfffffe000b7b0220] ?
0xfffffe000b3a61e0  a0ffffb5 cbnz     x0, #0xfffffe000b3a61d4
0xfffffe000b3a61e4  f9588052 mov      w25, #0x2c7
0xfffffe000b3a61e8  1900bc72 movk     w25, #0xe000, lsl #16
0xfffffe000b3a61ec  d00240f9 ldr      x16, [x22]
0xfffffe000b3a61f0  701bc1da autda    x16, x27
0xfffffe000b3a61f4  115e80d2 mov      x17, #0x2f0
0xfffffe000b3a61f8  1002118b add      x16, x16, x17
0xfffffe000b3a61fc  080240f9 ldr      x8, [x16]
0xfffffe000b3a6200  e00316aa mov      x0, x22
0xfffffe000b3a6204  01208052 mov      w1, #0x100
0xfffffe000b3a6208  b0d8ebf2 movk     x16, #0x5ec5, lsl #48
0xfffffe000b3a620c  10093fd7 blraa    x8, x16
0xfffffe000b3a6210  e00316aa mov      x0, x22
0xfffffe000b3a6214  e10314aa mov      x1, x20
0xfffffe000b3a6218  02008052 mov      w2, #0
0xfffffe000b3a621c  2472fd97 bl       #0xfffffe000b302aac; CALL 0xfffffe000b302aac sz=0x114 
0xfffffe000b3a6220  d00240f9 ldr      x16, [x22]
0xfffffe000b3a6224  701bc1da autda    x16, x27
0xfffffe000b3a6228  088e42f8 ldr      x8, [x16, #0x28]!
0xfffffe000b3a622c  07000014 b        #0xfffffe000b3a6248; -> 0xfffffe000b3a6248 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a6230  360100b4 cbz      x22, #0xfffffe000b3a6254
0xfffffe000b3a6234  d00240f9 ldr      x16, [x22]
0xfffffe000b3a6238  f10316aa mov      x17, x22
0xfffffe000b3a623c  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a6240  301ac1da autda    x16, x17
0xfffffe000b3a6244  088e42f8 ldr      x8, [x16, #0x28]!
0xfffffe000b3a6248  e00316aa mov      x0, x22
0xfffffe000b3a624c  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3a6250  10093fd7 blraa    x8, x16
0xfffffe000b3a6254  bf831af8 stur     xzr, [x29, #-0x58]
0xfffffe000b3a6258  1a310034 cbz      w26, #0xfffffe000b3a6878
0xfffffe000b3a625c  700240f9 ldr      x16, [x19]
0xfffffe000b3a6260  f10313aa mov      x17, x19
0xfffffe000b3a6264  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a6268  301ac1da autda    x16, x17
0xfffffe000b3a626c  088e42f8 ldr      x8, [x16, #0x28]!
0xfffffe000b3a6270  e00313aa mov      x0, x19
0xfffffe000b3a6274  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3a6278  10093fd7 blraa    x8, x16
0xfffffe000b3a627c  7f010014 b        #0xfffffe000b3a6878; -> 0xfffffe000b3a6878 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a6280  e00318aa mov      x0, x24
0xfffffe000b3a6284  c4e4e197 bl       #0xfffffe000ac1f594; CALL 0xfffffe000ac1f594 sz=0x90 
0xfffffe000b3a6288  d86e00f9 str      x24, [x22, #0xd8]
0xfffffe000b3a628c  0859feb0 adrp     x8, #0xfffffe0007ec7000; page 0xfffffe0007ec7000
0xfffffe000b3a6290  08454e39 ldrb     w8, [x8, #0x391]; [0xfffffe0007ec7391] ?
0xfffffe000b3a6294  08283837 tbnz     w8, #7, #0xfffffe000b3a6794
0xfffffe000b3a6298  9a050034 cbz      w26, #0xfffffe000b3a6348
0xfffffe000b3a629c  68200090 adrp     x8, #0xfffffe000b7b2000; page 0xfffffe000b7b2000
0xfffffe000b3a62a0  01c143f9 ldr      x1, [x8, #0x780]; [0xfffffe000b7b2780] ?
0xfffffe000b3a62a4  700240f9 ldr      x16, [x19]
0xfffffe000b3a62a8  f10313aa mov      x17, x19
0xfffffe000b3a62ac  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a62b0  301ac1da autda    x16, x17
0xfffffe000b3a62b4  112580d2 mov      x17, #0x128
0xfffffe000b3a62b8  1002118b add      x16, x16, x17
0xfffffe000b3a62bc  080240f9 ldr      x8, [x16]
0xfffffe000b3a62c0  e00313aa mov      x0, x19
0xfffffe000b3a62c4  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3a62c8  10093fd7 blraa    x8, x16
0xfffffe000b3a62cc  e00300b4 cbz      x0, #0xfffffe000b3a6348
0xfffffe000b3a62d0  100040f9 ldr      x16, [x0]; [0xfffffe000b7b0210] ?
0xfffffe000b3a62d4  f10300aa mov      x17, x0
0xfffffe000b3a62d8  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a62dc  301ac1da autda    x16, x17
0xfffffe000b3a62e0  080e42f8 ldr      x8, [x16, #0x20]!
0xfffffe000b3a62e4  f80300aa mov      x24, x0
0xfffffe000b3a62e8  50c9e5f2 movk     x16, #0x2e4a, lsl #48
0xfffffe000b3a62ec  10093fd7 blraa    x8, x16
0xfffffe000b3a62f0  e07640f9 ldr      x0, [x23, #0xe8]
0xfffffe000b3a62f4  e10318aa mov      x1, x24
0xfffffe000b3a62f8  020080d2 mov      x2, #0
0xfffffe000b3a62fc  030080d2 mov      x3, #0
0xfffffe000b3a6300  dae4ff97 bl       #0xfffffe000b39f668; CALL 0xfffffe000b39f668 sz=0x22c 
0xfffffe000b3a6304  80220037 tbnz     w0, #0, #0xfffffe000b3a6754
0xfffffe000b3a6308  d00240f9 ldr      x16, [x22]
0xfffffe000b3a630c  701bc1da autda    x16, x27
0xfffffe000b3a6310  113d80d2 mov      x17, #0x1e8
0xfffffe000b3a6314  1002118b add      x16, x16, x17
0xfffffe000b3a6318  080240f9 ldr      x8, [x16]
0xfffffe000b3a631c  e00316aa mov      x0, x22
0xfffffe000b3a6320  010080d2 mov      x1, #0
0xfffffe000b3a6324  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3a6328  10093fd7 blraa    x8, x16
0xfffffe000b3a632c  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3a6330  480000b4 cbz      x8, #0xfffffe000b3a6338
0xfffffe000b3a6334  080540f9 ldr      x8, [x8, #8]; [0xfffffe000b7b2008] ?
0xfffffe000b3a6338  e02300a9 stp      x0, x8, [sp]
0xfffffe000b3a633c  00e9fdb0 adrp     x0, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a6340  00543891 add      x0, x0, #0xe15; 0xfffffe00070c7e15 ?
0xfffffe000b3a6344  d9b8fc97 bl       #0xfffffe000b2d46a8; CALL 0xfffffe000b2d46a8 sz=0x118 
0xfffffe000b3a6348  e8824439 ldrb     w8, [x23, #0x120]
0xfffffe000b3a634c  480a0036 tbz      w8, #0, #0xfffffe000b3a6494
0xfffffe000b3a6350  e07640f9 ldr      x0, [x23, #0xe8]
0xfffffe000b3a6354  a00100b4 cbz      x0, #0xfffffe000b3a6388
0xfffffe000b3a6358  68200090 adrp     x8, #0xfffffe000b7b2000; page 0xfffffe000b7b2000
0xfffffe000b3a635c  01cd43f9 ldr      x1, [x8, #0x798]; [0xfffffe000b7b2798] ?
0xfffffe000b3a6360  100040f9 ldr      x16, [x0]; [0xfffffe00070c7e15] ?
0xfffffe000b3a6364  f10300aa mov      x17, x0
0xfffffe000b3a6368  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a636c  301ac1da autda    x16, x17
0xfffffe000b3a6370  112580d2 mov      x17, #0x128
0xfffffe000b3a6374  1002118b add      x16, x16, x17
0xfffffe000b3a6378  080240f9 ldr      x8, [x16]
0xfffffe000b3a637c  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3a6380  10093fd7 blraa    x8, x16
0xfffffe000b3a6384  801e00b5 cbnz     x0, #0xfffffe000b3a6754
0xfffffe000b3a6388  68200090 adrp     x8, #0xfffffe000b7b2000; page 0xfffffe000b7b2000
0xfffffe000b3a638c  01bd43f9 ldr      x1, [x8, #0x778]; [0xfffffe000b7b2778] ?
0xfffffe000b3a6390  900240f9 ldr      x16, [x20]
0xfffffe000b3a6394  f10314aa mov      x17, x20
0xfffffe000b3a6398  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a639c  301ac1da autda    x16, x17
0xfffffe000b3a63a0  112780d2 mov      x17, #0x138
0xfffffe000b3a63a4  1002118b add      x16, x16, x17
0xfffffe000b3a63a8  080240f9 ldr      x8, [x16]
0xfffffe000b3a63ac  e00314aa mov      x0, x20
0xfffffe000b3a63b0  d076f6f2 movk     x16, #0xb3b6, lsl #48
0xfffffe000b3a63b4  10093fd7 blraa    x8, x16
0xfffffe000b3a63b8  f70300aa mov      x23, x0
0xfffffe000b3a63bc  1f0000f1 cmp      x0, #0
0xfffffe000b3a63c0  e8039a1a csel     w8, wzr, w26, eq
0xfffffe000b3a63c4  1f050071 cmp      w8, #1
0xfffffe000b3a63c8  c10c0054 b.ne     #0xfffffe000b3a6560; -> 0xfffffe000b3a6560 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a63cc  68200090 adrp     x8, #0xfffffe000b7b2000; page 0xfffffe000b7b2000
0xfffffe000b3a63d0  01d143f9 ldr      x1, [x8, #0x7a0]; [0xfffffe000b7b27a0] ?
0xfffffe000b3a63d4  700240f9 ldr      x16, [x19]
0xfffffe000b3a63d8  f10313aa mov      x17, x19
0xfffffe000b3a63dc  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a63e0  301ac1da autda    x16, x17
0xfffffe000b3a63e4  112580d2 mov      x17, #0x128
0xfffffe000b3a63e8  1002118b add      x16, x16, x17
0xfffffe000b3a63ec  080240f9 ldr      x8, [x16]
0xfffffe000b3a63f0  e00313aa mov      x0, x19
0xfffffe000b3a63f4  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3a63f8  10093fd7 blraa    x8, x16
0xfffffe000b3a63fc  400b00b4 cbz      x0, #0xfffffe000b3a6564
0xfffffe000b3a6400  e8630191 add      x8, sp, #0x58
0xfffffe000b3a6404  ffa305a9 stp      xzr, x8, [sp, #0x58]
0xfffffe000b3a6408  29e3fdf0 adrp     x9, #0xfffffe000700d000; page 0xfffffe000700d000
0xfffffe000b3a640c  20f144fd ldr      d0, [x9, #0x9e0]; [0xfffffe000700d9e0] ?
0xfffffe000b3a6410  e03700fd str      d0, [sp, #0x68]
0xfffffe000b3a6414  ffc30139 strb     wzr, [sp, #0x70]
0xfffffe000b3a6418  e9a30091 add      x9, sp, #0x28
0xfffffe000b3a641c  702000b0 adrp     x16, #0xfffffe000b7b3000; page 0xfffffe000b7b3000
0xfffffe000b3a6420  10820e91 add      x16, x16, #0x3a0; 0xfffffe000b7b33a0 ?
0xfffffe000b3a6424  f10309aa mov      x17, x9
0xfffffe000b3a6428  315cedf2 movk     x17, #0x6ae1, lsl #48
0xfffffe000b3a642c  300ac1da pacda    x16, x17
0xfffffe000b3a6430  f01700f9 str      x16, [sp, #0x28]
0xfffffe000b3a6434  2ae3fdf0 adrp     x10, #0xfffffe000700d000; page 0xfffffe000700d000
0xfffffe000b3a6438  40f544fd ldr      d0, [x10, #0x9e8]; [0xfffffe000700d9e8] ?
0xfffffe000b3a643c  e01b00fd str      d0, [sp, #0x30]
0xfffffe000b3a6440  2a410091 add      x10, x9, #0x10; 0xfffffe000700d010 ?
0xfffffe000b3a6444  10000090 adrp     x16, #0xfffffe000b3a6000; page 0xfffffe000b3a6000
0xfffffe000b3a6448  10e22391 add      x16, x16, #0x8f8; 0xfffffe000b3a68f8 FUNC 0xfffffe000b3a68f8
0xfffffe000b3a644c  5001c1da pacia    x16, x10
0xfffffe000b3a6450  f01f00f9 str      x16, [sp, #0x38]
0xfffffe000b3a6454  29610091 add      x9, x9, #0x18; 0xfffffe000700d018 ?
0xfffffe000b3a6458  505afed0 adrp     x16, #0xfffffe0007ef0000; page 0xfffffe0007ef0000
0xfffffe000b3a645c  10423291 add      x16, x16, #0xc90; 0xfffffe0007ef0c90 ?
0xfffffe000b3a6460  f10309aa mov      x17, x9
0xfffffe000b3a6464  7117f8f2 movk     x17, #0xc0bb, lsl #48
0xfffffe000b3a6468  300ac1da pacda    x16, x17
0xfffffe000b3a646c  f02304a9 stp      x16, x8, [sp, #0x40]
0xfffffe000b3a6470  f72b00f9 str      x23, [sp, #0x50]
0xfffffe000b3a6474  e1a30091 add      x1, sp, #0x28
0xfffffe000b3a6478  2f0afb97 bl       #0xfffffe000b268d34; CALL 0xfffffe000b268d34 sz=0x8c 
0xfffffe000b3a647c  e83340f9 ldr      x8, [sp, #0x60]
0xfffffe000b3a6480  18614039 ldrb     w24, [x8, #0x18]; [0xfffffe000b7b2018] ?
0xfffffe000b3a6484  e0630191 add      x0, sp, #0x58
0xfffffe000b3a6488  01018052 mov      w1, #8
0xfffffe000b3a648c  6966fc97 bl       #0xfffffe000b2bfe30; CALL 0xfffffe000b2bfe30 sz=0xdc 
0xfffffe000b3a6490  a8000014 b        #0xfffffe000b3a6730; -> 0xfffffe000b3a6730 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a6494  e89640f9 ldr      x8, [x23, #0x128]
0xfffffe000b3a6498  680200b5 cbnz     x8, #0xfffffe000b3a64e4
0xfffffe000b3a649c  f00240f9 ldr      x16, [x23]
0xfffffe000b3a64a0  f10317aa mov      x17, x23
0xfffffe000b3a64a4  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a64a8  301ac1da autda    x16, x17
0xfffffe000b3a64ac  113d80d2 mov      x17, #0x1e8
0xfffffe000b3a64b0  1002118b add      x16, x16, x17; 0xfffffe0007ef0d7b ?
0xfffffe000b3a64b4  080240f9 ldr      x8, [x16]; [0xfffffe0007ef0d7b] ?
0xfffffe000b3a64b8  e00317aa mov      x0, x23
0xfffffe000b3a64bc  010080d2 mov      x1, #0
0xfffffe000b3a64c0  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3a64c4  10093fd7 blraa    x8, x16
0xfffffe000b3a64c8  e80a40f9 ldr      x8, [x23, #0x10]
0xfffffe000b3a64cc  480000b4 cbz      x8, #0xfffffe000b3a64d4
0xfffffe000b3a64d0  080540f9 ldr      x8, [x8, #8]; [0xfffffe000b7b2008] ?
0xfffffe000b3a64d4  e02300a9 stp      x0, x8, [sp]
0xfffffe000b3a64d8  00e9fdb0 adrp     x0, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a64dc  00203991 add      x0, x0, #0xe48; 0xfffffe00070c7e48 ?
0xfffffe000b3a64e0  72b8fc97 bl       #0xfffffe000b2d46a8; CALL 0xfffffe000b2d46a8 sz=0x118 
0xfffffe000b3a64e4  78200090 adrp     x24, #0xfffffe000b7b2000; page 0xfffffe000b7b2000
0xfffffe000b3a64e8  1a020034 cbz      w26, #0xfffffe000b3a6528
0xfffffe000b3a64ec  01c743f9 ldr      x1, [x24, #0x788]; [0xfffffe000b7b2788] ?
0xfffffe000b3a64f0  700240f9 ldr      x16, [x19]
0xfffffe000b3a64f4  f10313aa mov      x17, x19
0xfffffe000b3a64f8  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a64fc  301ac1da autda    x16, x17
0xfffffe000b3a6500  112580d2 mov      x17, #0x128
0xfffffe000b3a6504  1002118b add      x16, x16, x17; 0xfffffe0007ef0e66 ?
0xfffffe000b3a6508  080240f9 ldr      x8, [x16]; [0xfffffe0007ef0e66] ?
0xfffffe000b3a650c  e00313aa mov      x0, x19
0xfffffe000b3a6510  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3a6514  10093fd7 blraa    x8, x16
0xfffffe000b3a6518  99250090 adrp     x25, #0xfffffe000b856000; page 0xfffffe000b856000
0xfffffe000b3a651c  28bf40f9 ldr      x8, [x25, #0x178]; [0xfffffe000b856178] ?
0xfffffe000b3a6520  1f0008eb cmp      x0, x8
0xfffffe000b3a6524  e0050054 b.eq     #0xfffffe000b3a65e0; -> 0xfffffe000b3a65e0 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a6528  d00240f9 ldr      x16, [x22]
0xfffffe000b3a652c  701bc1da autda    x16, x27
0xfffffe000b3a6530  113d80d2 mov      x17, #0x1e8
0xfffffe000b3a6534  1002118b add      x16, x16, x17; 0xfffffe0007ef0f51 ?
0xfffffe000b3a6538  080240f9 ldr      x8, [x16]; [0xfffffe0007ef0f51] ?
0xfffffe000b3a653c  e00316aa mov      x0, x22
0xfffffe000b3a6540  010080d2 mov      x1, #0
0xfffffe000b3a6544  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3a6548  10093fd7 blraa    x8, x16
0xfffffe000b3a654c  f50300aa mov      x21, x0
0xfffffe000b3a6550  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3a6554  880200b4 cbz      x8, #0xfffffe000b3a65a4
0xfffffe000b3a6558  170540f9 ldr      x23, [x8, #8]; [0xfffffe000b7b2008] ?
0xfffffe000b3a655c  13000014 b        #0xfffffe000b3a65a8; -> 0xfffffe000b3a65a8 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a6560  f70100b4 cbz      x23, #0xfffffe000b3a659c
0xfffffe000b3a6564  f00240f9 ldr      x16, [x23]
0xfffffe000b3a6568  f10317aa mov      x17, x23
0xfffffe000b3a656c  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a6570  301ac1da autda    x16, x17
0xfffffe000b3a6574  088e43f8 ldr      x8, [x16, #0x38]!; [0xfffffe0007ef0f89] ?
0xfffffe000b3a6578  e00317aa mov      x0, x23
0xfffffe000b3a657c  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b3a6580  10093fd7 blraa    x8, x16
0xfffffe000b3a6584  482000d0 adrp     x8, #0xfffffe000b7b0000; page 0xfffffe000b7b0000
0xfffffe000b3a6588  08011291 add      x8, x8, #0x480; 0xfffffe000b7b0480 ?
0xfffffe000b3a658c  1f0008eb cmp      x0, x8
0xfffffe000b3a6590  a0080054 b.eq     #0xfffffe000b3a66a4; -> 0xfffffe000b3a66a4 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a6594  000840f9 ldr      x0, [x0, #0x10]; [0xfffffe00070c7e58] ?
0xfffffe000b3a6598  a0ffffb5 cbnz     x0, #0xfffffe000b3a658c
0xfffffe000b3a659c  180080d2 mov      x24, #0
0xfffffe000b3a65a0  42000014 b        #0xfffffe000b3a66a8; -> 0xfffffe000b3a66a8 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a65a4  170080d2 mov      x23, #0
0xfffffe000b3a65a8  00c743f9 ldr      x0, [x24, #0x788]; [0xfffffe000b7b2788] ?
0xfffffe000b3a65ac  100040f9 ldr      x16, [x0]; [0xfffffe00070c7e48] ?
0xfffffe000b3a65b0  f10300aa mov      x17, x0
0xfffffe000b3a65b4  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a65b8  301ac1da autda    x16, x17
0xfffffe000b3a65bc  088e4af8 ldr      x8, [x16, #0xa8]!; [0xfffffe0007ef0ff9] ?
0xfffffe000b3a65c0  f030e5f2 movk     x16, #0x2987, lsl #48
0xfffffe000b3a65c4  10093fd7 blraa    x8, x16
0xfffffe000b3a65c8  f78300a9 stp      x23, x0, [sp, #8]
0xfffffe000b3a65cc  f50300f9 str      x21, [sp]
0xfffffe000b3a65d0  00e9fdb0 adrp     x0, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a65d4  00143b91 add      x0, x0, #0xec5; 0xfffffe00070c7ec5 ?
0xfffffe000b3a65d8  34b8fc97 bl       #0xfffffe000b2d46a8; CALL 0xfffffe000b2d46a8 sz=0x118 
0xfffffe000b3a65dc  7a000014 b        #0xfffffe000b3a67c4; -> 0xfffffe000b3a67c4 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a65e0  c492e297 bl       #0xfffffe000ac4b0f0; CALL 0xfffffe000ac4b0f0 sz=0x98 
0xfffffe000b3a65e4  000c40f9 ldr      x0, [x0, #0x18]; [0xfffffe00070c7edd] ?
0xfffffe000b3a65e8  201800b4 cbz      x0, #0xfffffe000b3a68ec
0xfffffe000b3a65ec  4347f497 bl       #0xfffffe000b0b82f8; CALL 0xfffffe000b0b82f8 sz=0xa0 
0xfffffe000b3a65f0  f80300aa mov      x24, x0
0xfffffe000b3a65f4  e09640f9 ldr      x0, [x23, #0x128]
0xfffffe000b3a65f8  a00100b4 cbz      x0, #0xfffffe000b3a662c
0xfffffe000b3a65fc  980100b4 cbz      x24, #0xfffffe000b3a662c
0xfffffe000b3a6600  100040f9 ldr      x16, [x0]; [0xfffffe00070c7ec5] ?
0xfffffe000b3a6604  f10300aa mov      x17, x0
0xfffffe000b3a6608  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a660c  301ac1da autda    x16, x17
0xfffffe000b3a6610  088e4af8 ldr      x8, [x16, #0xa8]!; [0xfffffe0007ef0ff9] ?
0xfffffe000b3a6614  f030e5f2 movk     x16, #0x2987, lsl #48
0xfffffe000b3a6618  10093fd7 blraa    x8, x16
0xfffffe000b3a661c  e10318aa mov      x1, x24
0xfffffe000b3a6620  02088052 mov      w2, #0x40
0xfffffe000b3a6624  5b8fde97 bl       #0xfffffe000ab4a390; CALL 0xfffffe000ab4a390 sz=0x1c0 
0xfffffe000b3a6628  60090034 cbz      w0, #0xfffffe000b3a6754
0xfffffe000b3a662c  e07640f9 ldr      x0, [x23, #0xe8]
0xfffffe000b3a6630  e00100b4 cbz      x0, #0xfffffe000b3a666c
0xfffffe000b3a6634  68200090 adrp     x8, #0xfffffe000b7b2000; page 0xfffffe000b7b2000
0xfffffe000b3a6638  01c943f9 ldr      x1, [x8, #0x790]; [0xfffffe000b7b2790] ?
0xfffffe000b3a663c  100040f9 ldr      x16, [x0]; [0xfffffe00070c7ec5] ?
0xfffffe000b3a6640  f10300aa mov      x17, x0
0xfffffe000b3a6644  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a6648  301ac1da autda    x16, x17
0xfffffe000b3a664c  112580d2 mov      x17, #0x128
0xfffffe000b3a6650  1002118b add      x16, x16, x17; 0xfffffe0007ef103c ?
0xfffffe000b3a6654  080240f9 ldr      x8, [x16]; [0xfffffe0007ef103c] ?
0xfffffe000b3a6658  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3a665c  10093fd7 blraa    x8, x16
0xfffffe000b3a6660  28bf40f9 ldr      x8, [x25, #0x178]; [0xfffffe000b856178] ?
0xfffffe000b3a6664  1f0008eb cmp      x0, x8
0xfffffe000b3a6668  60070054 b.eq     #0xfffffe000b3a6754; -> 0xfffffe000b3a6754 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a666c  d00240f9 ldr      x16, [x22]
0xfffffe000b3a6670  701bc1da autda    x16, x27
0xfffffe000b3a6674  113d80d2 mov      x17, #0x1e8
0xfffffe000b3a6678  1002118b add      x16, x16, x17; 0xfffffe0007ef1127 ?
0xfffffe000b3a667c  080240f9 ldr      x8, [x16]; [0xfffffe0007ef1127] ?
0xfffffe000b3a6680  e00316aa mov      x0, x22
0xfffffe000b3a6684  010080d2 mov      x1, #0
0xfffffe000b3a6688  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3a668c  10093fd7 blraa    x8, x16
0xfffffe000b3a6690  f50300aa mov      x21, x0
0xfffffe000b3a6694  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3a6698  281000b4 cbz      x8, #0xfffffe000b3a689c
0xfffffe000b3a669c  190540f9 ldr      x25, [x8, #8]; [0xfffffe000b7b2008] ?
0xfffffe000b3a66a0  80000014 b        #0xfffffe000b3a68a0; -> 0xfffffe000b3a68a0 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a66a4  f80317aa mov      x24, x23
0xfffffe000b3a66a8  d00240f9 ldr      x16, [x22]
0xfffffe000b3a66ac  701bc1da autda    x16, x27
0xfffffe000b3a66b0  113d80d2 mov      x17, #0x1e8
0xfffffe000b3a66b4  1002118b add      x16, x16, x17; 0xfffffe0007ef1212 ?
0xfffffe000b3a66b8  080240f9 ldr      x8, [x16]; [0xfffffe0007ef1212] ?
0xfffffe000b3a66bc  e00316aa mov      x0, x22
0xfffffe000b3a66c0  010080d2 mov      x1, #0
0xfffffe000b3a66c4  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3a66c8  10093fd7 blraa    x8, x16
0xfffffe000b3a66cc  f90300aa mov      x25, x0
0xfffffe000b3a66d0  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3a66d4  680000b4 cbz      x8, #0xfffffe000b3a66e0
0xfffffe000b3a66d8  1c0540f9 ldr      x28, [x8, #8]; [0xfffffe000b7b2008] ?
0xfffffe000b3a66dc  02000014 b        #0xfffffe000b3a66e4; -> 0xfffffe000b3a66e4 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a66e0  1c0080d2 mov      x28, #0
0xfffffe000b3a66e4  580100b4 cbz      x24, #0xfffffe000b3a670c
0xfffffe000b3a66e8  100340f9 ldr      x16, [x24]; [0xfffffe000b7b2000] ?
0xfffffe000b3a66ec  f10318aa mov      x17, x24
0xfffffe000b3a66f0  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a66f4  301ac1da autda    x16, x17
0xfffffe000b3a66f8  088e4af8 ldr      x8, [x16, #0xa8]!; [0xfffffe0007ef12ba] ?
0xfffffe000b3a66fc  e00318aa mov      x0, x24
0xfffffe000b3a6700  f030e5f2 movk     x16, #0x2987, lsl #48
0xfffffe000b3a6704  10093fd7 blraa    x8, x16
0xfffffe000b3a6708  03000014 b        #0xfffffe000b3a6714; -> 0xfffffe000b3a6714 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a670c  00e9fdb0 adrp     x0, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a6710  00342191 add      x0, x0, #0x84d; 0xfffffe00070c784d STR "(null)"
0xfffffe000b3a6714  fc8300a9 stp      x28, x0, [sp, #8]
0xfffffe000b3a6718  f90300f9 str      x25, [sp]
0xfffffe000b3a671c  00e9fdb0 adrp     x0, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a6720  00443c91 add      x0, x0, #0xf11; 0xfffffe00070c7f11 ?
0xfffffe000b3a6724  e1b7fc97 bl       #0xfffffe000b2d46a8; CALL 0xfffffe000b2d46a8 sz=0x118 
0xfffffe000b3a6728  f70400b4 cbz      x23, #0xfffffe000b3a67c4
0xfffffe000b3a672c  18008052 mov      w24, #0
0xfffffe000b3a6730  f00240f9 ldr      x16, [x23]
0xfffffe000b3a6734  f10317aa mov      x17, x23
0xfffffe000b3a6738  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a673c  301ac1da autda    x16, x17
0xfffffe000b3a6740  088e42f8 ldr      x8, [x16, #0x28]!; [0xfffffe0007ef123a] ?
0xfffffe000b3a6744  e00317aa mov      x0, x23
0xfffffe000b3a6748  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3a674c  10093fd7 blraa    x8, x16
0xfffffe000b3a6750  b8030036 tbz      w24, #0, #0xfffffe000b3a67c4
0xfffffe000b3a6754  68200090 adrp     x8, #0xfffffe000b7b2000; page 0xfffffe000b7b2000
0xfffffe000b3a6758  018944f9 ldr      x1, [x8, #0x910]; [0xfffffe000b7b2910] ?
0xfffffe000b3a675c  d00240f9 ldr      x16, [x22]
0xfffffe000b3a6760  701bc1da autda    x16, x27
0xfffffe000b3a6764  112780d2 mov      x17, #0x138
0xfffffe000b3a6768  1002118b add      x16, x16, x17; 0xfffffe0007ef12fd ?
0xfffffe000b3a676c  080240f9 ldr      x8, [x16]; [0xfffffe0007ef12fd] ?
0xfffffe000b3a6770  e00316aa mov      x0, x22
0xfffffe000b3a6774  d076f6f2 movk     x16, #0xb3b6, lsl #48
0xfffffe000b3a6778  10093fd7 blraa    x8, x16
0xfffffe000b3a677c  e10300aa mov      x1, x0
0xfffffe000b3a6780  e00313aa mov      x0, x19
0xfffffe000b3a6784  020080d2 mov      x2, #0
0xfffffe000b3a6788  030080d2 mov      x3, #0
0xfffffe000b3a678c  b7e3ff97 bl       #0xfffffe000b39f668; CALL 0xfffffe000b39f668 sz=0x22c 
0xfffffe000b3a6790  a0010036 tbz      w0, #0, #0xfffffe000b3a67c4
0xfffffe000b3a6794  3a010034 cbz      w26, #0xfffffe000b3a67b8
0xfffffe000b3a6798  700240f9 ldr      x16, [x19]
0xfffffe000b3a679c  f10313aa mov      x17, x19
0xfffffe000b3a67a0  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a67a4  301ac1da autda    x16, x17
0xfffffe000b3a67a8  088e42f8 ldr      x8, [x16, #0x28]!; [0xfffffe0007ef1325] ?
0xfffffe000b3a67ac  e00313aa mov      x0, x19
0xfffffe000b3a67b0  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3a67b4  10093fd7 blraa    x8, x16
0xfffffe000b3a67b8  19008052 mov      w25, #0
0xfffffe000b3a67bc  b60200f9 str      x22, [x21]
0xfffffe000b3a67c0  2e000014 b        #0xfffffe000b3a6878; -> 0xfffffe000b3a6878 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a67c4  d00240f9 ldr      x16, [x22]
0xfffffe000b3a67c8  701bc1da autda    x16, x27
0xfffffe000b3a67cc  113d80d2 mov      x17, #0x1e8
0xfffffe000b3a67d0  1002118b add      x16, x16, x17; 0xfffffe0007ef13e8 ?
0xfffffe000b3a67d4  080240f9 ldr      x8, [x16]; [0xfffffe0007ef13e8] ?
0xfffffe000b3a67d8  e00316aa mov      x0, x22
0xfffffe000b3a67dc  010080d2 mov      x1, #0
0xfffffe000b3a67e0  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3a67e4  10093fd7 blraa    x8, x16
0xfffffe000b3a67e8  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3a67ec  480000b4 cbz      x8, #0xfffffe000b3a67f4
0xfffffe000b3a67f0  080540f9 ldr      x8, [x8, #8]; [0xfffffe000b7b2008] ?
0xfffffe000b3a67f4  f6588052 mov      w22, #0x2c7
0xfffffe000b3a67f8  1600bc72 movk     w22, #0xe000, lsl #16
0xfffffe000b3a67fc  e02300a9 stp      x0, x8, [sp]
0xfffffe000b3a6800  00e9fdb0 adrp     x0, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a6804  00583d91 add      x0, x0, #0xf56; 0xfffffe00070c7f56 ?
0xfffffe000b3a6808  a8b7fc97 bl       #0xfffffe000b2d46a8; CALL 0xfffffe000b2d46a8 sz=0x118 
0xfffffe000b3a680c  b5835af8 ldur     x21, [x29, #-0x58]
0xfffffe000b3a6810  f10315aa mov      x17, x21
0xfffffe000b3a6814  b00240f9 ldr      x16, [x21]
0xfffffe000b3a6818  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a681c  301ac1da autda    x16, x17
0xfffffe000b3a6820  08c20b91 add      x8, x16, #0x2f0; 0xfffffe0007ef16d8 ?
0xfffffe000b3a6824  097a41f9 ldr      x9, [x16, #0x2f0]; [0xfffffe0007ef16d8] ?
0xfffffe000b3a6828  e00315aa mov      x0, x21
0xfffffe000b3a682c  01208052 mov      w1, #0x100
0xfffffe000b3a6830  f10308aa mov      x17, x8
0xfffffe000b3a6834  b1d8ebf2 movk     x17, #0x5ec5, lsl #48
0xfffffe000b3a6838  31093fd7 blraa    x9, x17
0xfffffe000b3a683c  e00315aa mov      x0, x21
0xfffffe000b3a6840  e10314aa mov      x1, x20
0xfffffe000b3a6844  02008052 mov      w2, #0
0xfffffe000b3a6848  9970fd97 bl       #0xfffffe000b302aac; CALL 0xfffffe000b302aac sz=0x114 
0xfffffe000b3a684c  b00240f9 ldr      x16, [x21]
0xfffffe000b3a6850  f10315aa mov      x17, x21
0xfffffe000b3a6854  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a6858  301ac1da autda    x16, x17
0xfffffe000b3a685c  088e42f8 ldr      x8, [x16, #0x28]!; [0xfffffe0007ef1410] ?
0xfffffe000b3a6860  e00315aa mov      x0, x21
0xfffffe000b3a6864  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3a6868  10093fd7 blraa    x8, x16
0xfffffe000b3a686c  bf831af8 stur     xzr, [x29, #-0x58]
0xfffffe000b3a6870  d96e0011 add      w25, w22, #0x1b
0xfffffe000b3a6874  5acfff35 cbnz     w26, #0xfffffe000b3a625c
0xfffffe000b3a6878  e00319aa mov      x0, x25
0xfffffe000b3a687c  fd7b4da9 ldp      x29, x30, [sp, #0xd0]
0xfffffe000b3a6880  f44f4ca9 ldp      x20, x19, [sp, #0xc0]
0xfffffe000b3a6884  f6574ba9 ldp      x22, x21, [sp, #0xb0]
0xfffffe000b3a6888  f85f4aa9 ldp      x24, x23, [sp, #0xa0]
0xfffffe000b3a688c  fa6749a9 ldp      x26, x25, [sp, #0x90]
0xfffffe000b3a6890  fc6f48a9 ldp      x28, x27, [sp, #0x80]
0xfffffe000b3a6894  ff830391 add      sp, sp, #0xe0
0xfffffe000b3a6898  ff0f5fd6 retab    
0xfffffe000b3a689c  190080d2 mov      x25, #0
0xfffffe000b3a68a0  00e9fdb0 adrp     x0, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a68a4  00342191 add      x0, x0, #0x84d; 0xfffffe00070c784d STR "(null)"
0xfffffe000b3a68a8  1f0300f1 cmp      x24, #0
0xfffffe000b3a68ac  1813809a csel     x24, x24, x0, ne
0xfffffe000b3a68b0  e89640f9 ldr      x8, [x23, #0x128]
0xfffffe000b3a68b4  280100b4 cbz      x8, #0xfffffe000b3a68d8
0xfffffe000b3a68b8  100140f9 ldr      x16, [x8]; [0xfffffe0007ef16d8] ?
0xfffffe000b3a68bc  f10308aa mov      x17, x8
0xfffffe000b3a68c0  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3a68c4  301ac1da autda    x16, x17
0xfffffe000b3a68c8  098e4af8 ldr      x9, [x16, #0xa8]!; [0xfffffe0007ef1490] ?
0xfffffe000b3a68cc  e00308aa mov      x0, x8
0xfffffe000b3a68d0  f030e5f2 movk     x16, #0x2987, lsl #48
0xfffffe000b3a68d4  30093fd7 blraa    x9, x16
0xfffffe000b3a68d8  f80301a9 stp      x24, x0, [sp, #0x10]
0xfffffe000b3a68dc  f56700a9 stp      x21, x25, [sp]
0xfffffe000b3a68e0  00e9fdb0 adrp     x0, #0xfffffe00070c7000; page 0xfffffe00070c7000
0xfffffe000b3a68e4  00fc3991 add      x0, x0, #0xe7f; 0xfffffe00070c7e7f ?
0xfffffe000b3a68e8  3cffff17 b        #0xfffffe000b3a65d8; -> 0xfffffe000b3a65d8 FUNC 0xfffffe000b3a5fd0
0xfffffe000b3a68ec  885afed0 adrp     x8, #0xfffffe0007ef8000; page 0xfffffe0007ef8000
0xfffffe000b3a68f0  005947f9 ldr      x0, [x8, #0xeb0]; [0xfffffe0007ef8eb0] ?
0xfffffe000b3a68f4  3effff17 b        #0xfffffe000b3a65ec; -> 0xfffffe000b3a65ec FUNC 0xfffffe000b3a5fd0

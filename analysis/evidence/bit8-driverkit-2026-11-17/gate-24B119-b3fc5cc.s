0xfffffe000b3fc5cc  7f2303d5 pacibsp  
0xfffffe000b3fc5d0  ff8303d1 sub      sp, sp, #0xe0
0xfffffe000b3fc5d4  fc6f08a9 stp      x28, x27, [sp, #0x80]
0xfffffe000b3fc5d8  fa6709a9 stp      x26, x25, [sp, #0x90]
0xfffffe000b3fc5dc  f85f0aa9 stp      x24, x23, [sp, #0xa0]
0xfffffe000b3fc5e0  f6570ba9 stp      x22, x21, [sp, #0xb0]
0xfffffe000b3fc5e4  f44f0ca9 stp      x20, x19, [sp, #0xc0]
0xfffffe000b3fc5e8  fd7b0da9 stp      x29, x30, [sp, #0xd0]
0xfffffe000b3fc5ec  fd430391 add      x29, sp, #0xd0
0xfffffe000b3fc5f0  f50306aa mov      x21, x6
0xfffffe000b3fc5f4  f60304aa mov      x22, x4
0xfffffe000b3fc5f8  f80302aa mov      x24, x2
0xfffffe000b3fc5fc  f40301aa mov      x20, x1
0xfffffe000b3fc600  f70300aa mov      x23, x0
0xfffffe000b3fc604  e00302aa mov      x0, x2
0xfffffe000b3fc608  5b4eff97 bl       #0xfffffe000b3cff74; CALL 0xfffffe000b3cff74 sz=0x4c 
0xfffffe000b3fc60c  f30300aa mov      x19, x0
0xfffffe000b3fc610  000600b4 cbz      x0, #0xfffffe000b3fc6d0
0xfffffe000b3fc614  41e2fd90 adrp     x1, #0xfffffe0007044000; page 0xfffffe0007044000
0xfffffe000b3fc618  21a82291 add      x1, x1, #0x8aa; 0xfffffe00070448aa STR "root"
0xfffffe000b3fc61c  e00318aa mov      x0, x24
0xfffffe000b3fc620  804cff97 bl       #0xfffffe000b3cf820; CALL 0xfffffe000b3cf820 sz=0x534 'consolesession'; 'secureprocess'; 'foreground'
0xfffffe000b3fc624  e0010035 cbnz     w0, #0xfffffe000b3fc660
0xfffffe000b3fc628  882500d0 adrp     x8, #0xfffffe000b8ae000; page 0xfffffe000b8ae000
0xfffffe000b3fc62c  02bd41f9 ldr      x2, [x8, #0x378]; [0xfffffe000b8ae378] ?
0xfffffe000b3fc630  700240f9 ldr      x16, [x19]
0xfffffe000b3fc634  f10313aa mov      x17, x19
0xfffffe000b3fc638  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc63c  301ac1da autda    x16, x17
0xfffffe000b3fc640  112080d2 mov      x17, #0x100
0xfffffe000b3fc644  1002118b add      x16, x16, x17
0xfffffe000b3fc648  080240f9 ldr      x8, [x16]
0xfffffe000b3fc64c  61e6fd90 adrp     x1, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fc650  21242891 add      x1, x1, #0xa09; 0xfffffe00070c8a09 STR "com.apple.developer.driverkit.administrator"
0xfffffe000b3fc654  e00313aa mov      x0, x19
0xfffffe000b3fc658  7064f8f2 movk     x16, #0xc323, lsl #48
0xfffffe000b3fc65c  10093fd7 blraa    x8, x16
0xfffffe000b3fc660  ef7fe297 bl       #0xfffffe000ac9c61c; CALL 0xfffffe000ac9c61c sz=0x98 
0xfffffe000b3fc664  080c40f9 ldr      x8, [x0, #0x18]
0xfffffe000b3fc668  080600b4 cbz      x8, #0xfffffe000b3fc728
0xfffffe000b3fc66c  6958fe90 adrp     x9, #0xfffffe0007f08000; page 0xfffffe0007f08000
0xfffffe000b3fc670  29d547f9 ldr      x9, [x9, #0xfa8]; [0xfffffe0007f08fa8] ?
0xfffffe000b3fc674  1f0109eb cmp      x8, x9
0xfffffe000b3fc678  80050054 b.eq     #0xfffffe000b3fc728; -> 0xfffffe000b3fc728 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fc67c  006140b9 ldr      w0, [x8, #0x60]; [0xfffffe000b8ae060] ?
0xfffffe000b3fc680  ceb9fc97 bl       #0xfffffe000b32adb8; CALL 0xfffffe000b32adb8 sz=0x134 'pid %d, '
0xfffffe000b3fc684  800500b4 cbz      x0, #0xfffffe000b3fc734
0xfffffe000b3fc688  f90300aa mov      x25, x0
0xfffffe000b3fc68c  700240f9 ldr      x16, [x19]
0xfffffe000b3fc690  f10313aa mov      x17, x19
0xfffffe000b3fc694  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc698  301ac1da autda    x16, x17
0xfffffe000b3fc69c  112080d2 mov      x17, #0x100
0xfffffe000b3fc6a0  1002118b add      x16, x16, x17
0xfffffe000b3fc6a4  080240f9 ldr      x8, [x16]
0xfffffe000b3fc6a8  61e6fd90 adrp     x1, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fc6ac  21d42891 add      x1, x1, #0xa35; 0xfffffe00070c8a35 STR "IOUserClientCreator"
0xfffffe000b3fc6b0  e00313aa mov      x0, x19
0xfffffe000b3fc6b4  e20319aa mov      x2, x25
0xfffffe000b3fc6b8  7064f8f2 movk     x16, #0xc323, lsl #48
0xfffffe000b3fc6bc  10093fd7 blraa    x8, x16
0xfffffe000b3fc6c0  e80319aa mov      x8, x25
0xfffffe000b3fc6c4  28b4f9f2 movk     x8, #0xcda1, lsl #48
0xfffffe000b3fc6c8  3a008052 mov      w26, #1
0xfffffe000b3fc6cc  23000014 b        #0xfffffe000b3fc758; -> 0xfffffe000b3fc758 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fc6d0  60200090 adrp     x0, #0xfffffe000b808000; page 0xfffffe000b808000
0xfffffe000b3fc6d4  00400d91 add      x0, x0, #0x350; 0xfffffe000b808350 ?
0xfffffe000b3fc6d8  100040f9 ldr      x16, [x0]; [0xfffffe000b808350] ?
0xfffffe000b3fc6dc  f10300aa mov      x17, x0
0xfffffe000b3fc6e0  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc6e4  301ac1da autda    x16, x17
0xfffffe000b3fc6e8  088e46f8 ldr      x8, [x16, #0x68]!
0xfffffe000b3fc6ec  30c0e2f2 movk     x16, #0x1601, lsl #48
0xfffffe000b3fc6f0  10093fd7 blraa    x8, x16
0xfffffe000b3fc6f4  400200b4 cbz      x0, #0xfffffe000b3fc73c
0xfffffe000b3fc6f8  f90300aa mov      x25, x0
0xfffffe000b3fc6fc  100040f9 ldr      x16, [x0]; [0xfffffe000b808350] ?
0xfffffe000b3fc700  f10300aa mov      x17, x0
0xfffffe000b3fc704  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc708  301ac1da autda    x16, x17
0xfffffe000b3fc70c  080e4df8 ldr      x8, [x16, #0xd0]!
0xfffffe000b3fc710  01018052 mov      w1, #8
0xfffffe000b3fc714  5080f3f2 movk     x16, #0x9c02, lsl #48
0xfffffe000b3fc718  10093fd7 blraa    x8, x16
0xfffffe000b3fc71c  60010034 cbz      w0, #0xfffffe000b3fc748
0xfffffe000b3fc720  f30319aa mov      x19, x25
0xfffffe000b3fc724  bcffff17 b        #0xfffffe000b3fc614; -> 0xfffffe000b3fc614 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fc728  00008052 mov      w0, #0
0xfffffe000b3fc72c  a3b9fc97 bl       #0xfffffe000b32adb8; CALL 0xfffffe000b32adb8 sz=0x134 'pid %d, '
0xfffffe000b3fc730  c0faffb5 cbnz     x0, #0xfffffe000b3fc688
0xfffffe000b3fc734  3a008052 mov      w26, #1
0xfffffe000b3fc738  0e000014 b        #0xfffffe000b3fc770; -> 0xfffffe000b3fc770 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fc73c  1a008052 mov      w26, #0
0xfffffe000b3fc740  130080d2 mov      x19, #0
0xfffffe000b3fc744  0b000014 b        #0xfffffe000b3fc770; -> 0xfffffe000b3fc770 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fc748  1a008052 mov      w26, #0
0xfffffe000b3fc74c  130080d2 mov      x19, #0
0xfffffe000b3fc750  e80319aa mov      x8, x25
0xfffffe000b3fc754  28b4f9f2 movk     x8, #0xcda1, lsl #48
0xfffffe000b3fc758  300340f9 ldr      x16, [x25]
0xfffffe000b3fc75c  1019c1da autda    x16, x8
0xfffffe000b3fc760  088e42f8 ldr      x8, [x16, #0x28]!
0xfffffe000b3fc764  e00319aa mov      x0, x25
0xfffffe000b3fc768  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3fc76c  10093fd7 blraa    x8, x16
0xfffffe000b3fc770  bf831af8 stur     xzr, [x29, #-0x58]
0xfffffe000b3fc774  bf0200f9 str      xzr, [x21]
0xfffffe000b3fc778  a36301d1 sub      x3, x29, #0x58
0xfffffe000b3fc77c  e00314aa mov      x0, x20
0xfffffe000b3fc780  e10316aa mov      x1, x22
0xfffffe000b3fc784  e20313aa mov      x2, x19
0xfffffe000b3fc788  040080d2 mov      x4, #0
0xfffffe000b3fc78c  df80fc97 bl       #0xfffffe000b31cb08; CALL 0xfffffe000b31cb08 sz=0x1bc 
0xfffffe000b3fc790  f90300aa mov      x25, x0
0xfffffe000b3fc794  b6835af8 ldur     x22, [x29, #-0x58]
0xfffffe000b3fc798  a0040035 cbnz     w0, #0xfffffe000b3fc82c
0xfffffe000b3fc79c  960400b4 cbz      x22, #0xfffffe000b3fc82c
0xfffffe000b3fc7a0  d00240f9 ldr      x16, [x22]
0xfffffe000b3fc7a4  fb0316aa mov      x27, x22
0xfffffe000b3fc7a8  3bb4f9f2 movk     x27, #0xcda1, lsl #48
0xfffffe000b3fc7ac  f10316aa mov      x17, x22
0xfffffe000b3fc7b0  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc7b4  301ac1da autda    x16, x17
0xfffffe000b3fc7b8  088e43f8 ldr      x8, [x16, #0x38]!
0xfffffe000b3fc7bc  e00316aa mov      x0, x22
0xfffffe000b3fc7c0  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b3fc7c4  10093fd7 blraa    x8, x16
0xfffffe000b3fc7c8  682000d0 adrp     x8, #0xfffffe000b80a000; page 0xfffffe000b80a000
0xfffffe000b3fc7cc  08e12391 add      x8, x8, #0x8f8; 0xfffffe000b80a8f8 ?
0xfffffe000b3fc7d0  1f0008eb cmp      x0, x8
0xfffffe000b3fc7d4  40050054 b.eq     #0xfffffe000b3fc87c; -> 0xfffffe000b3fc87c FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fc7d8  000840f9 ldr      x0, [x0, #0x10]; [0xfffffe000b808360] ?
0xfffffe000b3fc7dc  a0ffffb5 cbnz     x0, #0xfffffe000b3fc7d0
0xfffffe000b3fc7e0  f9588052 mov      w25, #0x2c7
0xfffffe000b3fc7e4  1900bc72 movk     w25, #0xe000, lsl #16
0xfffffe000b3fc7e8  d00240f9 ldr      x16, [x22]
0xfffffe000b3fc7ec  701bc1da autda    x16, x27
0xfffffe000b3fc7f0  115e80d2 mov      x17, #0x2f0
0xfffffe000b3fc7f4  1002118b add      x16, x16, x17
0xfffffe000b3fc7f8  080240f9 ldr      x8, [x16]
0xfffffe000b3fc7fc  e00316aa mov      x0, x22
0xfffffe000b3fc800  01208052 mov      w1, #0x100
0xfffffe000b3fc804  b0d8ebf2 movk     x16, #0x5ec5, lsl #48
0xfffffe000b3fc808  10093fd7 blraa    x8, x16
0xfffffe000b3fc80c  e00316aa mov      x0, x22
0xfffffe000b3fc810  e10314aa mov      x1, x20
0xfffffe000b3fc814  02008052 mov      w2, #0
0xfffffe000b3fc818  a871fd97 bl       #0xfffffe000b358eb8; CALL 0xfffffe000b358eb8 sz=0x114 
0xfffffe000b3fc81c  d00240f9 ldr      x16, [x22]
0xfffffe000b3fc820  701bc1da autda    x16, x27
0xfffffe000b3fc824  088e42f8 ldr      x8, [x16, #0x28]!
0xfffffe000b3fc828  07000014 b        #0xfffffe000b3fc844; -> 0xfffffe000b3fc844 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fc82c  360100b4 cbz      x22, #0xfffffe000b3fc850
0xfffffe000b3fc830  d00240f9 ldr      x16, [x22]
0xfffffe000b3fc834  f10316aa mov      x17, x22
0xfffffe000b3fc838  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc83c  301ac1da autda    x16, x17
0xfffffe000b3fc840  088e42f8 ldr      x8, [x16, #0x28]!
0xfffffe000b3fc844  e00316aa mov      x0, x22
0xfffffe000b3fc848  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3fc84c  10093fd7 blraa    x8, x16
0xfffffe000b3fc850  bf831af8 stur     xzr, [x29, #-0x58]
0xfffffe000b3fc854  1a310034 cbz      w26, #0xfffffe000b3fce74
0xfffffe000b3fc858  700240f9 ldr      x16, [x19]
0xfffffe000b3fc85c  f10313aa mov      x17, x19
0xfffffe000b3fc860  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc864  301ac1da autda    x16, x17
0xfffffe000b3fc868  088e42f8 ldr      x8, [x16, #0x28]!
0xfffffe000b3fc86c  e00313aa mov      x0, x19
0xfffffe000b3fc870  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3fc874  10093fd7 blraa    x8, x16
0xfffffe000b3fc878  7f010014 b        #0xfffffe000b3fce74; -> 0xfffffe000b3fce74 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fc87c  e00318aa mov      x0, x24
0xfffffe000b3fc880  77d0e197 bl       #0xfffffe000ac70a5c; CALL 0xfffffe000ac70a5c sz=0x90 
0xfffffe000b3fc884  d86e00f9 str      x24, [x22, #0xd8]
0xfffffe000b3fc888  c856fef0 adrp     x8, #0xfffffe0007ed7000; page 0xfffffe0007ed7000
0xfffffe000b3fc88c  08a55139 ldrb     w8, [x8, #0x469]; [0xfffffe0007ed7469] ?
0xfffffe000b3fc890  08283837 tbnz     w8, #7, #0xfffffe000b3fcd90
0xfffffe000b3fc894  9a050034 cbz      w26, #0xfffffe000b3fc944
0xfffffe000b3fc898  682000d0 adrp     x8, #0xfffffe000b80a000; page 0xfffffe000b80a000
0xfffffe000b3fc89c  016144f9 ldr      x1, [x8, #0x8c0]; [0xfffffe000b80a8c0] ?
0xfffffe000b3fc8a0  700240f9 ldr      x16, [x19]
0xfffffe000b3fc8a4  f10313aa mov      x17, x19
0xfffffe000b3fc8a8  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc8ac  301ac1da autda    x16, x17
0xfffffe000b3fc8b0  112580d2 mov      x17, #0x128
0xfffffe000b3fc8b4  1002118b add      x16, x16, x17
0xfffffe000b3fc8b8  080240f9 ldr      x8, [x16]
0xfffffe000b3fc8bc  e00313aa mov      x0, x19
0xfffffe000b3fc8c0  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3fc8c4  10093fd7 blraa    x8, x16
0xfffffe000b3fc8c8  e00300b4 cbz      x0, #0xfffffe000b3fc944
0xfffffe000b3fc8cc  100040f9 ldr      x16, [x0]; [0xfffffe000b808350] ?
0xfffffe000b3fc8d0  f10300aa mov      x17, x0
0xfffffe000b3fc8d4  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc8d8  301ac1da autda    x16, x17
0xfffffe000b3fc8dc  080e42f8 ldr      x8, [x16, #0x20]!
0xfffffe000b3fc8e0  f80300aa mov      x24, x0
0xfffffe000b3fc8e4  50c9e5f2 movk     x16, #0x2e4a, lsl #48
0xfffffe000b3fc8e8  10093fd7 blraa    x8, x16
0xfffffe000b3fc8ec  e07640f9 ldr      x0, [x23, #0xe8]
0xfffffe000b3fc8f0  e10318aa mov      x1, x24
0xfffffe000b3fc8f4  020080d2 mov      x2, #0
0xfffffe000b3fc8f8  030080d2 mov      x3, #0
0xfffffe000b3fc8fc  a7e4ff97 bl       #0xfffffe000b3f5b98; CALL 0xfffffe000b3f5b98 sz=0x22c 
0xfffffe000b3fc900  80220037 tbnz     w0, #0, #0xfffffe000b3fcd50
0xfffffe000b3fc904  d00240f9 ldr      x16, [x22]
0xfffffe000b3fc908  701bc1da autda    x16, x27
0xfffffe000b3fc90c  113d80d2 mov      x17, #0x1e8
0xfffffe000b3fc910  1002118b add      x16, x16, x17
0xfffffe000b3fc914  080240f9 ldr      x8, [x16]
0xfffffe000b3fc918  e00316aa mov      x0, x22
0xfffffe000b3fc91c  010080d2 mov      x1, #0
0xfffffe000b3fc920  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3fc924  10093fd7 blraa    x8, x16
0xfffffe000b3fc928  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3fc92c  480000b4 cbz      x8, #0xfffffe000b3fc934
0xfffffe000b3fc930  080540f9 ldr      x8, [x8, #8]; [0xfffffe000b80a008] ?
0xfffffe000b3fc934  e02300a9 stp      x0, x8, [sp]
0xfffffe000b3fc938  60e6fd90 adrp     x0, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fc93c  00242991 add      x0, x0, #0xa49; 0xfffffe00070c8a49 ?
0xfffffe000b3fc940  5db8fc97 bl       #0xfffffe000b32aab4; CALL 0xfffffe000b32aab4 sz=0x118 
0xfffffe000b3fc944  e8824439 ldrb     w8, [x23, #0x120]
0xfffffe000b3fc948  480a0036 tbz      w8, #0, #0xfffffe000b3fca90
0xfffffe000b3fc94c  e07640f9 ldr      x0, [x23, #0xe8]
0xfffffe000b3fc950  a00100b4 cbz      x0, #0xfffffe000b3fc984
0xfffffe000b3fc954  682000d0 adrp     x8, #0xfffffe000b80a000; page 0xfffffe000b80a000
0xfffffe000b3fc958  016d44f9 ldr      x1, [x8, #0x8d8]; [0xfffffe000b80a8d8] ?
0xfffffe000b3fc95c  100040f9 ldr      x16, [x0]; [0xfffffe00070c8a49] ?
0xfffffe000b3fc960  f10300aa mov      x17, x0
0xfffffe000b3fc964  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc968  301ac1da autda    x16, x17
0xfffffe000b3fc96c  112580d2 mov      x17, #0x128
0xfffffe000b3fc970  1002118b add      x16, x16, x17
0xfffffe000b3fc974  080240f9 ldr      x8, [x16]
0xfffffe000b3fc978  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3fc97c  10093fd7 blraa    x8, x16
0xfffffe000b3fc980  801e00b5 cbnz     x0, #0xfffffe000b3fcd50
0xfffffe000b3fc984  682000d0 adrp     x8, #0xfffffe000b80a000; page 0xfffffe000b80a000
0xfffffe000b3fc988  015d44f9 ldr      x1, [x8, #0x8b8]; [0xfffffe000b80a8b8] ?
0xfffffe000b3fc98c  900240f9 ldr      x16, [x20]
0xfffffe000b3fc990  f10314aa mov      x17, x20
0xfffffe000b3fc994  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc998  301ac1da autda    x16, x17
0xfffffe000b3fc99c  112780d2 mov      x17, #0x138
0xfffffe000b3fc9a0  1002118b add      x16, x16, x17
0xfffffe000b3fc9a4  080240f9 ldr      x8, [x16]
0xfffffe000b3fc9a8  e00314aa mov      x0, x20
0xfffffe000b3fc9ac  d076f6f2 movk     x16, #0xb3b6, lsl #48
0xfffffe000b3fc9b0  10093fd7 blraa    x8, x16
0xfffffe000b3fc9b4  f70300aa mov      x23, x0
0xfffffe000b3fc9b8  1f0000f1 cmp      x0, #0
0xfffffe000b3fc9bc  e8039a1a csel     w8, wzr, w26, eq
0xfffffe000b3fc9c0  1f050071 cmp      w8, #1
0xfffffe000b3fc9c4  c10c0054 b.ne     #0xfffffe000b3fcb5c; -> 0xfffffe000b3fcb5c FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fc9c8  682000d0 adrp     x8, #0xfffffe000b80a000; page 0xfffffe000b80a000
0xfffffe000b3fc9cc  017144f9 ldr      x1, [x8, #0x8e0]; [0xfffffe000b80a8e0] ?
0xfffffe000b3fc9d0  700240f9 ldr      x16, [x19]
0xfffffe000b3fc9d4  f10313aa mov      x17, x19
0xfffffe000b3fc9d8  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fc9dc  301ac1da autda    x16, x17
0xfffffe000b3fc9e0  112580d2 mov      x17, #0x128
0xfffffe000b3fc9e4  1002118b add      x16, x16, x17
0xfffffe000b3fc9e8  080240f9 ldr      x8, [x16]
0xfffffe000b3fc9ec  e00313aa mov      x0, x19
0xfffffe000b3fc9f0  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3fc9f4  10093fd7 blraa    x8, x16
0xfffffe000b3fc9f8  400b00b4 cbz      x0, #0xfffffe000b3fcb60
0xfffffe000b3fc9fc  e8630191 add      x8, sp, #0x58
0xfffffe000b3fca00  ffa305a9 stp      xzr, x8, [sp, #0x58]
0xfffffe000b3fca04  89e0fdb0 adrp     x9, #0xfffffe000700d000; page 0xfffffe000700d000
0xfffffe000b3fca08  20f144fd ldr      d0, [x9, #0x9e0]; [0xfffffe000700d9e0] ?
0xfffffe000b3fca0c  e03700fd str      d0, [sp, #0x68]
0xfffffe000b3fca10  ffc30139 strb     wzr, [sp, #0x70]
0xfffffe000b3fca14  e9a30091 add      x9, sp, #0x28
0xfffffe000b3fca18  702000f0 adrp     x16, #0xfffffe000b80b000; page 0xfffffe000b80b000
0xfffffe000b3fca1c  10821391 add      x16, x16, #0x4e0; 0xfffffe000b80b4e0 ?
0xfffffe000b3fca20  f10309aa mov      x17, x9
0xfffffe000b3fca24  315cedf2 movk     x17, #0x6ae1, lsl #48
0xfffffe000b3fca28  300ac1da pacda    x16, x17
0xfffffe000b3fca2c  f01700f9 str      x16, [sp, #0x28]
0xfffffe000b3fca30  8ae0fdb0 adrp     x10, #0xfffffe000700d000; page 0xfffffe000700d000
0xfffffe000b3fca34  40f544fd ldr      d0, [x10, #0x9e8]; [0xfffffe000700d9e8] ?
0xfffffe000b3fca38  e01b00fd str      d0, [sp, #0x30]
0xfffffe000b3fca3c  2a410091 add      x10, x9, #0x10; 0xfffffe000700d010 ?
0xfffffe000b3fca40  10000090 adrp     x16, #0xfffffe000b3fc000; page 0xfffffe000b3fc000
0xfffffe000b3fca44  10d23b91 add      x16, x16, #0xef4; 0xfffffe000b3fcef4 FUNC 0xfffffe000b3fcef4
0xfffffe000b3fca48  5001c1da pacia    x16, x10
0xfffffe000b3fca4c  f01f00f9 str      x16, [sp, #0x38]
0xfffffe000b3fca50  29610091 add      x9, x9, #0x18; 0xfffffe000700d018 ?
0xfffffe000b3fca54  3058fe90 adrp     x16, #0xfffffe0007f00000; page 0xfffffe0007f00000
0xfffffe000b3fca58  10a23591 add      x16, x16, #0xd68; 0xfffffe0007f00d68 ?
0xfffffe000b3fca5c  f10309aa mov      x17, x9
0xfffffe000b3fca60  7117f8f2 movk     x17, #0xc0bb, lsl #48
0xfffffe000b3fca64  300ac1da pacda    x16, x17
0xfffffe000b3fca68  f02304a9 stp      x16, x8, [sp, #0x40]
0xfffffe000b3fca6c  f72b00f9 str      x23, [sp, #0x50]
0xfffffe000b3fca70  e1a30091 add      x1, sp, #0x28
0xfffffe000b3fca74  f108fb97 bl       #0xfffffe000b2bee38; CALL 0xfffffe000b2bee38 sz=0x8c 
0xfffffe000b3fca78  e83340f9 ldr      x8, [sp, #0x60]
0xfffffe000b3fca7c  18614039 ldrb     w24, [x8, #0x18]; [0xfffffe000b80a018] ?
0xfffffe000b3fca80  e0630191 add      x0, sp, #0x58
0xfffffe000b3fca84  01018052 mov      w1, #8
0xfffffe000b3fca88  2b65fc97 bl       #0xfffffe000b315f34; CALL 0xfffffe000b315f34 sz=0xdc 
0xfffffe000b3fca8c  a8000014 b        #0xfffffe000b3fcd2c; -> 0xfffffe000b3fcd2c FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fca90  e89640f9 ldr      x8, [x23, #0x128]
0xfffffe000b3fca94  680200b5 cbnz     x8, #0xfffffe000b3fcae0
0xfffffe000b3fca98  f00240f9 ldr      x16, [x23]
0xfffffe000b3fca9c  f10317aa mov      x17, x23
0xfffffe000b3fcaa0  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fcaa4  301ac1da autda    x16, x17
0xfffffe000b3fcaa8  113d80d2 mov      x17, #0x1e8
0xfffffe000b3fcaac  1002118b add      x16, x16, x17; 0xfffffe0007f00e53 ?
0xfffffe000b3fcab0  080240f9 ldr      x8, [x16]; [0xfffffe0007f00e53] ?
0xfffffe000b3fcab4  e00317aa mov      x0, x23
0xfffffe000b3fcab8  010080d2 mov      x1, #0
0xfffffe000b3fcabc  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3fcac0  10093fd7 blraa    x8, x16
0xfffffe000b3fcac4  e80a40f9 ldr      x8, [x23, #0x10]
0xfffffe000b3fcac8  480000b4 cbz      x8, #0xfffffe000b3fcad0
0xfffffe000b3fcacc  080540f9 ldr      x8, [x8, #8]; [0xfffffe000b80a008] ?
0xfffffe000b3fcad0  e02300a9 stp      x0, x8, [sp]
0xfffffe000b3fcad4  60e6fd90 adrp     x0, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fcad8  00f02991 add      x0, x0, #0xa7c; 0xfffffe00070c8a7c ?
0xfffffe000b3fcadc  f6b7fc97 bl       #0xfffffe000b32aab4; CALL 0xfffffe000b32aab4 sz=0x118 
0xfffffe000b3fcae0  782000d0 adrp     x24, #0xfffffe000b80a000; page 0xfffffe000b80a000
0xfffffe000b3fcae4  1a020034 cbz      w26, #0xfffffe000b3fcb24
0xfffffe000b3fcae8  016744f9 ldr      x1, [x24, #0x8c8]; [0xfffffe000b80a8c8] ?
0xfffffe000b3fcaec  700240f9 ldr      x16, [x19]
0xfffffe000b3fcaf0  f10313aa mov      x17, x19
0xfffffe000b3fcaf4  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fcaf8  301ac1da autda    x16, x17
0xfffffe000b3fcafc  112580d2 mov      x17, #0x128
0xfffffe000b3fcb00  1002118b add      x16, x16, x17; 0xfffffe0007f00f3e ?
0xfffffe000b3fcb04  080240f9 ldr      x8, [x16]; [0xfffffe0007f00f3e] ?
0xfffffe000b3fcb08  e00313aa mov      x0, x19
0xfffffe000b3fcb0c  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3fcb10  10093fd7 blraa    x8, x16
0xfffffe000b3fcb14  992500d0 adrp     x25, #0xfffffe000b8ae000; page 0xfffffe000b8ae000
0xfffffe000b3fcb18  28bf41f9 ldr      x8, [x25, #0x378]; [0xfffffe000b8ae378] ?
0xfffffe000b3fcb1c  1f0008eb cmp      x0, x8
0xfffffe000b3fcb20  e0050054 b.eq     #0xfffffe000b3fcbdc; -> 0xfffffe000b3fcbdc FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcb24  d00240f9 ldr      x16, [x22]
0xfffffe000b3fcb28  701bc1da autda    x16, x27
0xfffffe000b3fcb2c  113d80d2 mov      x17, #0x1e8
0xfffffe000b3fcb30  1002118b add      x16, x16, x17; 0xfffffe0007f01029 ?
0xfffffe000b3fcb34  080240f9 ldr      x8, [x16]; [0xfffffe0007f01029] ?
0xfffffe000b3fcb38  e00316aa mov      x0, x22
0xfffffe000b3fcb3c  010080d2 mov      x1, #0
0xfffffe000b3fcb40  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3fcb44  10093fd7 blraa    x8, x16
0xfffffe000b3fcb48  f50300aa mov      x21, x0
0xfffffe000b3fcb4c  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3fcb50  880200b4 cbz      x8, #0xfffffe000b3fcba0
0xfffffe000b3fcb54  170540f9 ldr      x23, [x8, #8]; [0xfffffe000b80a008] ?
0xfffffe000b3fcb58  13000014 b        #0xfffffe000b3fcba4; -> 0xfffffe000b3fcba4 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcb5c  f70100b4 cbz      x23, #0xfffffe000b3fcb98
0xfffffe000b3fcb60  f00240f9 ldr      x16, [x23]
0xfffffe000b3fcb64  f10317aa mov      x17, x23
0xfffffe000b3fcb68  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fcb6c  301ac1da autda    x16, x17
0xfffffe000b3fcb70  088e43f8 ldr      x8, [x16, #0x38]!; [0xfffffe0007f01061] ?
0xfffffe000b3fcb74  e00317aa mov      x0, x23
0xfffffe000b3fcb78  90fffff2 movk     x16, #0xfffc, lsl #48
0xfffffe000b3fcb7c  10093fd7 blraa    x8, x16
0xfffffe000b3fcb80  68200090 adrp     x8, #0xfffffe000b808000; page 0xfffffe000b808000
0xfffffe000b3fcb84  08011791 add      x8, x8, #0x5c0; 0xfffffe000b8085c0 ?
0xfffffe000b3fcb88  1f0008eb cmp      x0, x8
0xfffffe000b3fcb8c  a0080054 b.eq     #0xfffffe000b3fcca0; -> 0xfffffe000b3fcca0 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcb90  000840f9 ldr      x0, [x0, #0x10]; [0xfffffe00070c8a8c] ?
0xfffffe000b3fcb94  a0ffffb5 cbnz     x0, #0xfffffe000b3fcb88
0xfffffe000b3fcb98  180080d2 mov      x24, #0
0xfffffe000b3fcb9c  42000014 b        #0xfffffe000b3fcca4; -> 0xfffffe000b3fcca4 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcba0  170080d2 mov      x23, #0
0xfffffe000b3fcba4  006744f9 ldr      x0, [x24, #0x8c8]; [0xfffffe000b80a8c8] ?
0xfffffe000b3fcba8  100040f9 ldr      x16, [x0]; [0xfffffe00070c8a7c] ?
0xfffffe000b3fcbac  f10300aa mov      x17, x0
0xfffffe000b3fcbb0  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fcbb4  301ac1da autda    x16, x17
0xfffffe000b3fcbb8  088e4af8 ldr      x8, [x16, #0xa8]!; [0xfffffe0007f010d1] ?
0xfffffe000b3fcbbc  f030e5f2 movk     x16, #0x2987, lsl #48
0xfffffe000b3fcbc0  10093fd7 blraa    x8, x16
0xfffffe000b3fcbc4  f78300a9 stp      x23, x0, [sp, #8]
0xfffffe000b3fcbc8  f50300f9 str      x21, [sp]
0xfffffe000b3fcbcc  60e6fd90 adrp     x0, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fcbd0  00e42b91 add      x0, x0, #0xaf9; 0xfffffe00070c8af9 ?
0xfffffe000b3fcbd4  b8b7fc97 bl       #0xfffffe000b32aab4; CALL 0xfffffe000b32aab4 sz=0x118 
0xfffffe000b3fcbd8  7a000014 b        #0xfffffe000b3fcdc0; -> 0xfffffe000b3fcdc0 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcbdc  907ee297 bl       #0xfffffe000ac9c61c; CALL 0xfffffe000ac9c61c sz=0x98 
0xfffffe000b3fcbe0  000c40f9 ldr      x0, [x0, #0x18]; [0xfffffe00070c8b11] ?
0xfffffe000b3fcbe4  201800b4 cbz      x0, #0xfffffe000b3fcee8
0xfffffe000b3fcbe8  0d44f497 bl       #0xfffffe000b10dc1c; CALL 0xfffffe000b10dc1c sz=0xa0 
0xfffffe000b3fcbec  f80300aa mov      x24, x0
0xfffffe000b3fcbf0  e09640f9 ldr      x0, [x23, #0x128]
0xfffffe000b3fcbf4  a00100b4 cbz      x0, #0xfffffe000b3fcc28
0xfffffe000b3fcbf8  980100b4 cbz      x24, #0xfffffe000b3fcc28
0xfffffe000b3fcbfc  100040f9 ldr      x16, [x0]; [0xfffffe00070c8af9] ?
0xfffffe000b3fcc00  f10300aa mov      x17, x0
0xfffffe000b3fcc04  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fcc08  301ac1da autda    x16, x17
0xfffffe000b3fcc0c  088e4af8 ldr      x8, [x16, #0xa8]!; [0xfffffe0007f010d1] ?
0xfffffe000b3fcc10  f030e5f2 movk     x16, #0x2987, lsl #48
0xfffffe000b3fcc14  10093fd7 blraa    x8, x16
0xfffffe000b3fcc18  e10318aa mov      x1, x24
0xfffffe000b3fcc1c  02088052 mov      w2, #0x40
0xfffffe000b3fcc20  dc75de97 bl       #0xfffffe000ab9a390; CALL 0xfffffe000ab9a390 sz=0x1c0 
0xfffffe000b3fcc24  60090034 cbz      w0, #0xfffffe000b3fcd50
0xfffffe000b3fcc28  e07640f9 ldr      x0, [x23, #0xe8]
0xfffffe000b3fcc2c  e00100b4 cbz      x0, #0xfffffe000b3fcc68
0xfffffe000b3fcc30  682000d0 adrp     x8, #0xfffffe000b80a000; page 0xfffffe000b80a000
0xfffffe000b3fcc34  016944f9 ldr      x1, [x8, #0x8d0]; [0xfffffe000b80a8d0] ?
0xfffffe000b3fcc38  100040f9 ldr      x16, [x0]; [0xfffffe00070c8af9] ?
0xfffffe000b3fcc3c  f10300aa mov      x17, x0
0xfffffe000b3fcc40  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fcc44  301ac1da autda    x16, x17
0xfffffe000b3fcc48  112580d2 mov      x17, #0x128
0xfffffe000b3fcc4c  1002118b add      x16, x16, x17; 0xfffffe0007f01114 ?
0xfffffe000b3fcc50  080240f9 ldr      x8, [x16]; [0xfffffe0007f01114] ?
0xfffffe000b3fcc54  f006ebf2 movk     x16, #0x5837, lsl #48
0xfffffe000b3fcc58  10093fd7 blraa    x8, x16
0xfffffe000b3fcc5c  28bf41f9 ldr      x8, [x25, #0x378]; [0xfffffe000b8ae378] ?
0xfffffe000b3fcc60  1f0008eb cmp      x0, x8
0xfffffe000b3fcc64  60070054 b.eq     #0xfffffe000b3fcd50; -> 0xfffffe000b3fcd50 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcc68  d00240f9 ldr      x16, [x22]
0xfffffe000b3fcc6c  701bc1da autda    x16, x27
0xfffffe000b3fcc70  113d80d2 mov      x17, #0x1e8
0xfffffe000b3fcc74  1002118b add      x16, x16, x17; 0xfffffe0007f011ff ?
0xfffffe000b3fcc78  080240f9 ldr      x8, [x16]; [0xfffffe0007f011ff] ?
0xfffffe000b3fcc7c  e00316aa mov      x0, x22
0xfffffe000b3fcc80  010080d2 mov      x1, #0
0xfffffe000b3fcc84  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3fcc88  10093fd7 blraa    x8, x16
0xfffffe000b3fcc8c  f50300aa mov      x21, x0
0xfffffe000b3fcc90  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3fcc94  281000b4 cbz      x8, #0xfffffe000b3fce98
0xfffffe000b3fcc98  190540f9 ldr      x25, [x8, #8]; [0xfffffe000b80a008] ?
0xfffffe000b3fcc9c  80000014 b        #0xfffffe000b3fce9c; -> 0xfffffe000b3fce9c FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcca0  f80317aa mov      x24, x23
0xfffffe000b3fcca4  d00240f9 ldr      x16, [x22]
0xfffffe000b3fcca8  701bc1da autda    x16, x27
0xfffffe000b3fccac  113d80d2 mov      x17, #0x1e8
0xfffffe000b3fccb0  1002118b add      x16, x16, x17; 0xfffffe0007f012ea ?
0xfffffe000b3fccb4  080240f9 ldr      x8, [x16]; [0xfffffe0007f012ea] ?
0xfffffe000b3fccb8  e00316aa mov      x0, x22
0xfffffe000b3fccbc  010080d2 mov      x1, #0
0xfffffe000b3fccc0  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3fccc4  10093fd7 blraa    x8, x16
0xfffffe000b3fccc8  f90300aa mov      x25, x0
0xfffffe000b3fcccc  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3fccd0  680000b4 cbz      x8, #0xfffffe000b3fccdc
0xfffffe000b3fccd4  1c0540f9 ldr      x28, [x8, #8]; [0xfffffe000b80a008] ?
0xfffffe000b3fccd8  02000014 b        #0xfffffe000b3fcce0; -> 0xfffffe000b3fcce0 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fccdc  1c0080d2 mov      x28, #0
0xfffffe000b3fcce0  580100b4 cbz      x24, #0xfffffe000b3fcd08
0xfffffe000b3fcce4  100340f9 ldr      x16, [x24]; [0xfffffe000b80a000] ?
0xfffffe000b3fcce8  f10318aa mov      x17, x24
0xfffffe000b3fccec  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fccf0  301ac1da autda    x16, x17
0xfffffe000b3fccf4  088e4af8 ldr      x8, [x16, #0xa8]!; [0xfffffe0007f01392] ?
0xfffffe000b3fccf8  e00318aa mov      x0, x24
0xfffffe000b3fccfc  f030e5f2 movk     x16, #0x2987, lsl #48
0xfffffe000b3fcd00  10093fd7 blraa    x8, x16
0xfffffe000b3fcd04  03000014 b        #0xfffffe000b3fcd10; -> 0xfffffe000b3fcd10 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcd08  60e6fd90 adrp     x0, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fcd0c  00041291 add      x0, x0, #0x481; 0xfffffe00070c8481 STR "(null)"
0xfffffe000b3fcd10  fc8300a9 stp      x28, x0, [sp, #8]
0xfffffe000b3fcd14  f90300f9 str      x25, [sp]
0xfffffe000b3fcd18  60e6fd90 adrp     x0, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fcd1c  00142d91 add      x0, x0, #0xb45; 0xfffffe00070c8b45 ?
0xfffffe000b3fcd20  65b7fc97 bl       #0xfffffe000b32aab4; CALL 0xfffffe000b32aab4 sz=0x118 
0xfffffe000b3fcd24  f70400b4 cbz      x23, #0xfffffe000b3fcdc0
0xfffffe000b3fcd28  18008052 mov      w24, #0
0xfffffe000b3fcd2c  f00240f9 ldr      x16, [x23]
0xfffffe000b3fcd30  f10317aa mov      x17, x23
0xfffffe000b3fcd34  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fcd38  301ac1da autda    x16, x17
0xfffffe000b3fcd3c  088e42f8 ldr      x8, [x16, #0x28]!; [0xfffffe0007f01312] ?
0xfffffe000b3fcd40  e00317aa mov      x0, x23
0xfffffe000b3fcd44  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3fcd48  10093fd7 blraa    x8, x16
0xfffffe000b3fcd4c  b8030036 tbz      w24, #0, #0xfffffe000b3fcdc0
0xfffffe000b3fcd50  682000d0 adrp     x8, #0xfffffe000b80a000; page 0xfffffe000b80a000
0xfffffe000b3fcd54  012945f9 ldr      x1, [x8, #0xa50]; [0xfffffe000b80aa50] ?
0xfffffe000b3fcd58  d00240f9 ldr      x16, [x22]
0xfffffe000b3fcd5c  701bc1da autda    x16, x27
0xfffffe000b3fcd60  112780d2 mov      x17, #0x138
0xfffffe000b3fcd64  1002118b add      x16, x16, x17; 0xfffffe0007f013d5 ?
0xfffffe000b3fcd68  080240f9 ldr      x8, [x16]; [0xfffffe0007f013d5] ?
0xfffffe000b3fcd6c  e00316aa mov      x0, x22
0xfffffe000b3fcd70  d076f6f2 movk     x16, #0xb3b6, lsl #48
0xfffffe000b3fcd74  10093fd7 blraa    x8, x16
0xfffffe000b3fcd78  e10300aa mov      x1, x0
0xfffffe000b3fcd7c  e00313aa mov      x0, x19
0xfffffe000b3fcd80  020080d2 mov      x2, #0
0xfffffe000b3fcd84  030080d2 mov      x3, #0
0xfffffe000b3fcd88  84e3ff97 bl       #0xfffffe000b3f5b98; CALL 0xfffffe000b3f5b98 sz=0x22c 
0xfffffe000b3fcd8c  a0010036 tbz      w0, #0, #0xfffffe000b3fcdc0
0xfffffe000b3fcd90  3a010034 cbz      w26, #0xfffffe000b3fcdb4
0xfffffe000b3fcd94  700240f9 ldr      x16, [x19]
0xfffffe000b3fcd98  f10313aa mov      x17, x19
0xfffffe000b3fcd9c  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fcda0  301ac1da autda    x16, x17
0xfffffe000b3fcda4  088e42f8 ldr      x8, [x16, #0x28]!; [0xfffffe0007f013fd] ?
0xfffffe000b3fcda8  e00313aa mov      x0, x19
0xfffffe000b3fcdac  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3fcdb0  10093fd7 blraa    x8, x16
0xfffffe000b3fcdb4  19008052 mov      w25, #0
0xfffffe000b3fcdb8  b60200f9 str      x22, [x21]
0xfffffe000b3fcdbc  2e000014 b        #0xfffffe000b3fce74; -> 0xfffffe000b3fce74 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcdc0  d00240f9 ldr      x16, [x22]
0xfffffe000b3fcdc4  701bc1da autda    x16, x27
0xfffffe000b3fcdc8  113d80d2 mov      x17, #0x1e8
0xfffffe000b3fcdcc  1002118b add      x16, x16, x17; 0xfffffe0007f014c0 ?
0xfffffe000b3fcdd0  080240f9 ldr      x8, [x16]; [0xfffffe0007f014c0] ?
0xfffffe000b3fcdd4  e00316aa mov      x0, x22
0xfffffe000b3fcdd8  010080d2 mov      x1, #0
0xfffffe000b3fcddc  9093e1f2 movk     x16, #0xc9c, lsl #48
0xfffffe000b3fcde0  10093fd7 blraa    x8, x16
0xfffffe000b3fcde4  c80a40f9 ldr      x8, [x22, #0x10]
0xfffffe000b3fcde8  480000b4 cbz      x8, #0xfffffe000b3fcdf0
0xfffffe000b3fcdec  080540f9 ldr      x8, [x8, #8]; [0xfffffe000b80a008] ?
0xfffffe000b3fcdf0  f6588052 mov      w22, #0x2c7
0xfffffe000b3fcdf4  1600bc72 movk     w22, #0xe000, lsl #16
0xfffffe000b3fcdf8  e02300a9 stp      x0, x8, [sp]
0xfffffe000b3fcdfc  60e6fd90 adrp     x0, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fce00  00282e91 add      x0, x0, #0xb8a; 0xfffffe00070c8b8a ?
0xfffffe000b3fce04  2cb7fc97 bl       #0xfffffe000b32aab4; CALL 0xfffffe000b32aab4 sz=0x118 
0xfffffe000b3fce08  b5835af8 ldur     x21, [x29, #-0x58]
0xfffffe000b3fce0c  f10315aa mov      x17, x21
0xfffffe000b3fce10  b00240f9 ldr      x16, [x21]
0xfffffe000b3fce14  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fce18  301ac1da autda    x16, x17
0xfffffe000b3fce1c  08c20b91 add      x8, x16, #0x2f0; 0xfffffe0007f017b0 ?
0xfffffe000b3fce20  097a41f9 ldr      x9, [x16, #0x2f0]; [0xfffffe0007f017b0] ?
0xfffffe000b3fce24  e00315aa mov      x0, x21
0xfffffe000b3fce28  01208052 mov      w1, #0x100
0xfffffe000b3fce2c  f10308aa mov      x17, x8
0xfffffe000b3fce30  b1d8ebf2 movk     x17, #0x5ec5, lsl #48
0xfffffe000b3fce34  31093fd7 blraa    x9, x17
0xfffffe000b3fce38  e00315aa mov      x0, x21
0xfffffe000b3fce3c  e10314aa mov      x1, x20
0xfffffe000b3fce40  02008052 mov      w2, #0
0xfffffe000b3fce44  1d70fd97 bl       #0xfffffe000b358eb8; CALL 0xfffffe000b358eb8 sz=0x114 
0xfffffe000b3fce48  b00240f9 ldr      x16, [x21]
0xfffffe000b3fce4c  f10315aa mov      x17, x21
0xfffffe000b3fce50  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fce54  301ac1da autda    x16, x17
0xfffffe000b3fce58  088e42f8 ldr      x8, [x16, #0x28]!; [0xfffffe0007f014e8] ?
0xfffffe000b3fce5c  e00315aa mov      x0, x21
0xfffffe000b3fce60  f050e7f2 movk     x16, #0x3a87, lsl #48
0xfffffe000b3fce64  10093fd7 blraa    x8, x16
0xfffffe000b3fce68  bf831af8 stur     xzr, [x29, #-0x58]
0xfffffe000b3fce6c  d96e0011 add      w25, w22, #0x1b
0xfffffe000b3fce70  5acfff35 cbnz     w26, #0xfffffe000b3fc858
0xfffffe000b3fce74  e00319aa mov      x0, x25
0xfffffe000b3fce78  fd7b4da9 ldp      x29, x30, [sp, #0xd0]
0xfffffe000b3fce7c  f44f4ca9 ldp      x20, x19, [sp, #0xc0]
0xfffffe000b3fce80  f6574ba9 ldp      x22, x21, [sp, #0xb0]
0xfffffe000b3fce84  f85f4aa9 ldp      x24, x23, [sp, #0xa0]
0xfffffe000b3fce88  fa6749a9 ldp      x26, x25, [sp, #0x90]
0xfffffe000b3fce8c  fc6f48a9 ldp      x28, x27, [sp, #0x80]
0xfffffe000b3fce90  ff830391 add      sp, sp, #0xe0
0xfffffe000b3fce94  ff0f5fd6 retab    
0xfffffe000b3fce98  190080d2 mov      x25, #0
0xfffffe000b3fce9c  60e6fd90 adrp     x0, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fcea0  00041291 add      x0, x0, #0x481; 0xfffffe00070c8481 STR "(null)"
0xfffffe000b3fcea4  1f0300f1 cmp      x24, #0
0xfffffe000b3fcea8  1813809a csel     x24, x24, x0, ne
0xfffffe000b3fceac  e89640f9 ldr      x8, [x23, #0x128]
0xfffffe000b3fceb0  280100b4 cbz      x8, #0xfffffe000b3fced4
0xfffffe000b3fceb4  100140f9 ldr      x16, [x8]; [0xfffffe0007f017b0] ?
0xfffffe000b3fceb8  f10308aa mov      x17, x8
0xfffffe000b3fcebc  31b4f9f2 movk     x17, #0xcda1, lsl #48
0xfffffe000b3fcec0  301ac1da autda    x16, x17
0xfffffe000b3fcec4  098e4af8 ldr      x9, [x16, #0xa8]!; [0xfffffe0007f01568] ?
0xfffffe000b3fcec8  e00308aa mov      x0, x8
0xfffffe000b3fcecc  f030e5f2 movk     x16, #0x2987, lsl #48
0xfffffe000b3fced0  30093fd7 blraa    x9, x16
0xfffffe000b3fced4  f80301a9 stp      x24, x0, [sp, #0x10]
0xfffffe000b3fced8  f56700a9 stp      x21, x25, [sp]
0xfffffe000b3fcedc  60e6fd90 adrp     x0, #0xfffffe00070c8000; page 0xfffffe00070c8000
0xfffffe000b3fcee0  00cc2a91 add      x0, x0, #0xab3; 0xfffffe00070c8ab3 ?
0xfffffe000b3fcee4  3cffff17 b        #0xfffffe000b3fcbd4; -> 0xfffffe000b3fcbd4 FUNC 0xfffffe000b3fc5cc
0xfffffe000b3fcee8  6858fe90 adrp     x8, #0xfffffe0007f08000; page 0xfffffe0007f08000
0xfffffe000b3fceec  00d547f9 ldr      x0, [x8, #0xfa8]; [0xfffffe0007f08fa8] ?
0xfffffe000b3fcef0  3effff17 b        #0xfffffe000b3fcbe8; -> 0xfffffe000b3fcbe8 FUNC 0xfffffe000b3fc5cc

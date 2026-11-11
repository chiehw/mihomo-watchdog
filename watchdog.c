/* mihomo-watchdog: 拨号/TLS 失败则切下一个叶子。
 *
 * gcc -O2 -Wall -Wextra -s -o mihomo-watchdog watchdog.c
 *
 * env: MIHOMO_API MIHOMO_PROXY MIHOMO_SECRET_FILE MIHOMO_CONFIG
 *      MIHOMO_RELOAD_PATH MIHOMO_LOG_LEVEL BARK_KEY BARK_GROUP
 *      BARK_DEVICE BARK_TITLE BARK_BODY
 *      工作目录文件：bark-device / bark-title / bark-body
 *      模板变量：{device} {group} {old} {new}
 *
 * 日志来自 mihomo GET /logs WebSocket，不是 docker logs。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_NAME 192
#define MAX_GROUPS 64
#define MAX_MEMBERS 128
#define MAX_WATCHED 32
#define MAX_LINES 4096
#define MAX_EVENTS 1024
#define POOL_SIZE (256 * 1024)
#define BODY_MAX (8 * 1024 * 1024)
#define WS_BUF (64 * 1024)

static const char *DEFAULT_GROUP = "🚀 默认代理";
static const char *CURSOR_GROUP = "🤖 Cursor自动";
static const char *AUTO_SUFFIX = "自动";
static const char *HEALTH_URL = "https://cp.cloudflare.com/generate_204";
static const char *GROUP_TYPES[] = {"Selector", "URLTest", "Fallback", "LoadBalance", NULL};
static const char *WATCH_SKIP[] = {
    "🤖 AGY 美国自动",
    "♻️ 自动选择",
    "🌐 IPv6 自动",
    NULL,
};

typedef struct {
    const char *name;
    const char *type;
    const char *now;
    const char *all[MAX_MEMBERS];
    int nall;
} Group;

typedef struct {
    Group items[MAX_GROUPS];
    int n;
} Catalog;

typedef struct {
    char name[MAX_NAME];
    int nfail;
} Fail;

typedef struct {
    char name[MAX_NAME];
    time_t ts;
} Switch;

typedef struct {
    char api_host[128];
    int api_port;
    char proxy[256];
    char secret[256];
    char config_path[512];
    char reload_path[512];
    char log_level[16];
    char bark_key[128];
    char bark_group[64];
    char bark_device[64];
    char bark_title[192];
    char bark_body[256];
    int interval;
    int window;
    int fails;
    int cooldown;
    int once;
    int dry_run;
    int close_cursor;
    char only[MAX_WATCHED][MAX_NAME];
    int nonly;
} Cfg;

static char pool[POOL_SIZE];
static size_t pool_off;
static Fail fails[MAX_WATCHED];
static int nfails;
static Switch last_switch[MAX_WATCHED];
static int nlast;
static Cfg cfg;

typedef struct {
    time_t ts;
    char group[MAX_NAME];
} FailEvent;

static FailEvent events[MAX_EVENTS];
static int ev_start;
static int ev_count;
static int ws_fd = -1;
static unsigned char ws_buf[WS_BUF];
static size_t ws_len;

static const char *resolve_watch_group(const char *dial, Catalog *cat, char watched[][MAX_NAME], int nwatch);
static void add_fail(const char *name, int n);

static void die(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    exit(1);
}

static void pool_reset(void) { pool_off = 0; }

static const char *intern(const char *s) {
    size_t n = strlen(s) + 1;
    if (pool_off + n > POOL_SIZE)
        die("name pool full");
    memcpy(pool + pool_off, s, n);
    const char *p = pool + pool_off;
    pool_off += n;
    return p;
}

static int ends_with(const char *s, const char *suf) {
    size_t n = strlen(s), m = strlen(suf);
    return n >= m && memcmp(s + n - m, suf, m) == 0;
}

static int in_list(const char *s, const char **list) {
    for (int i = 0; list[i]; i++)
        if (strcmp(s, list[i]) == 0)
            return 1;
    return 0;
}

static int is_group_type(const char *t) {
    return t && in_list(t, GROUP_TYPES);
}

static void urlenc(const char *s, char *out, size_t cap) {
    static const char hex[] = "0123456789ABCDEF";
    size_t j = 0;
    for (; *s && j + 4 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            out[j++] = '%';
            out[j++] = hex[c >> 4];
            out[j++] = hex[c & 15];
        }
    }
    out[j] = 0;
}

static void json_esc(const char *s, char *out, size_t cap) {
    size_t j = 0;
    for (; *s && j + 8 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c == '\n') {
            out[j++] = '\\';
            out[j++] = 'n';
        } else if (c < 0x20) {
            j += (size_t)snprintf(out + j, cap - j, "\\u%04x", c);
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = 0;
}

static char *read_file(const char *path, size_t *out_n) {
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long n = ftell(fp);
    if (n < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    char *buf = malloc((size_t)n + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    if (fread(buf, 1, (size_t)n, fp) != (size_t)n) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    buf[n] = 0;
    fclose(fp);
    if (out_n)
        *out_n = (size_t)n;
    return buf;
}

static int write_file(const char *path, const char *text, size_t n) {
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return -1;
    if (fwrite(text, 1, n, fp) != n) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int copy_file(const char *src, const char *dst) {
    size_t n = 0;
    char *buf = read_file(src, &n);
    if (!buf)
        return -1;
    int rc = write_file(dst, buf, n);
    free(buf);
    return rc;
}

/* ---- HTTP (localhost mihomo API) ---- */

static int tcp_connect(const char *host, int port, int timeout_sec) {
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        rc = poll(&pfd, 1, timeout_sec * 1000);
        if (rc <= 0) {
            close(fd);
            fd = -1;
            continue;
        }
        int err = 0;
        socklen_t elen = sizeof err;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err) {
            close(fd);
            fd = -1;
            continue;
        }
        fcntl(fd, F_SETFL, flags);
        struct timeval tv = {.tv_sec = timeout_sec, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        break;
    }
    freeaddrinfo(res);
    return fd;
}

static int send_all(int fd, const char *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, buf + off, n - off, 0);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int recv_more(int fd, char **buf, size_t *len, size_t *cap) {
    if (*len + 4096 > *cap) {
        size_t ncap = *cap ? *cap * 2 : 8192;
        if (ncap > BODY_MAX)
            ncap = BODY_MAX;
        if (*len + 1 >= ncap)
            return -1;
        char *nb = realloc(*buf, ncap);
        if (!nb)
            return -1;
        *buf = nb;
        *cap = ncap;
    }
    ssize_t r = recv(fd, *buf + *len, *cap - *len - 1, 0);
    if (r < 0) {
        if (errno == EINTR)
            return 0;
        return -1;
    }
    if (r == 0)
        return 1;
    *len += (size_t)r;
    (*buf)[*len] = 0;
    return 0;
}

static int parse_hex(const char *s, size_t *out) {
    size_t v = 0;
    if (!isxdigit((unsigned char)*s))
        return -1;
    for (; isxdigit((unsigned char)*s); s++) {
        v <<= 4;
        v += (size_t)(isdigit((unsigned char)*s) ? *s - '0' : 10 + tolower((unsigned char)*s) - 'a');
    }
    *out = v;
    return 0;
}

static int decode_chunked(char *body, size_t n, size_t *out_n) {
    char *dst = body;
    char *p = body;
    char *end = body + n;
    while (p < end) {
        size_t sz = 0;
        if (parse_hex(p, &sz) != 0)
            return -1;
        char *nl = strstr(p, "\r\n");
        if (!nl)
            return -1;
        p = nl + 2;
        if (sz == 0)
            break;
        if (p + sz + 2 > end)
            return -1;
        memmove(dst, p, sz);
        dst += sz;
        p += sz;
        if (p[0] != '\r' || p[1] != '\n')
            return -1;
        p += 2;
    }
    *dst = 0;
    *out_n = (size_t)(dst - body);
    return 0;
}

static int http(const char *method, const char *path, const char *body, int timeout, char **out, long *status) {
    *out = NULL;
    if (status)
        *status = 0;
    int fd = tcp_connect(cfg.api_host, cfg.api_port, timeout);
    if (fd < 0)
        return -1;
    size_t blen = body ? strlen(body) : 0;
    char hdr[2048];
    int n = snprintf(hdr, sizeof hdr,
                     "%s %s HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Authorization: Bearer %s\r\n"
                     "Accept: application/json\r\n"
                     "Connection: close\r\n",
                     method, path, cfg.api_host, cfg.api_port, cfg.secret);
    if (body) {
        n += snprintf(hdr + n, sizeof hdr - (size_t)n,
                      "Content-Type: application/json\r\n"
                      "Content-Length: %zu\r\n",
                      blen);
    }
    n += snprintf(hdr + n, sizeof hdr - (size_t)n, "\r\n");
    if (n < 0 || (size_t)n >= sizeof hdr) {
        close(fd);
        return -1;
    }
    if (send_all(fd, hdr, (size_t)n) != 0 || (body && send_all(fd, body, blen) != 0)) {
        close(fd);
        return -1;
    }
    char *buf = NULL;
    size_t len = 0, cap = 0;
    int rc;
    while ((rc = recv_more(fd, &buf, &len, &cap)) == 0) {
    }
    close(fd);
    if (!buf)
        return -1;
    char *sep = strstr(buf, "\r\n\r\n");
    if (!sep) {
        free(buf);
        return -1;
    }
    long st = 0;
    sscanf(buf, "HTTP/%*s %ld", &st);
    if (status)
        *status = st;
    int chunked = 0;
    long clen = -1;
    char *h = buf;
    while (h < sep) {
        char *nl = strstr(h, "\r\n");
        if (!nl || nl > sep)
            break;
        if (!strncasecmp(h, "Transfer-Encoding:", 18) && strcasestr(h, "chunked"))
            chunked = 1;
        if (!strncasecmp(h, "Content-Length:", 15))
            clen = strtol(h + 15, NULL, 10);
        h = nl + 2;
    }
    char *payload = sep + 4;
    size_t plen = len - (size_t)(payload - buf);
    if (chunked) {
        size_t dn = 0;
        if (decode_chunked(payload, plen, &dn) != 0) {
            free(buf);
            return -1;
        }
        plen = dn;
    } else if (clen >= 0 && (size_t)clen < plen) {
        plen = (size_t)clen;
        payload[plen] = 0;
    }
    char *dup = malloc(plen + 1);
    if (!dup) {
        free(buf);
        return -1;
    }
    memcpy(dup, payload, plen);
    dup[plen] = 0;
    free(buf);
    *out = dup;
    return 0;
}

static int api(const char *method, const char *path, const char *body, char **out) {
    long st = 0;
    if (http(method, path, body, 20, out, &st) != 0)
        return -1;
    if (st < 200 || st >= 300) {
        fprintf(stderr, "%s %s -> %ld %.200s\n", method, path, st, *out ? *out : "");
        free(*out);
        *out = NULL;
        return -1;
    }
    return 0;
}

static int put_group(const char *group, const char *leaf) {
    char enc[1024], esc[512], path[1100], body[600];
    urlenc(group, enc, sizeof enc);
    json_esc(leaf, esc, sizeof esc);
    snprintf(path, sizeof path, "/proxies/%s", enc);
    snprintf(body, sizeof body, "{\"name\":\"%s\"}", esc);
    char *out = NULL;
    int rc = api("PUT", path, body, &out);
    free(out);
    return rc;
}

/* ---- JSON ---- */

typedef struct {
    const char *p;
    const char *end;
    int err;
} Json;

static void j_ws(Json *j) {
    while (j->p < j->end && isspace((unsigned char)*j->p))
        j->p++;
}

static int j_ch(Json *j, char c) {
    j_ws(j);
    if (j->p >= j->end || *j->p != c) {
        j->err = 1;
        return 0;
    }
    j->p++;
    return 1;
}

static int j_str(Json *j, char *out, size_t cap) {
    j_ws(j);
    if (j->p >= j->end || *j->p != '"') {
        j->err = 1;
        return 0;
    }
    j->p++;
    size_t n = 0;
    while (j->p < j->end && *j->p != '"') {
        unsigned char c = (unsigned char)*j->p++;
        if (c == '\\') {
            if (j->p >= j->end) {
                j->err = 1;
                return 0;
            }
            char e = *j->p++;
            switch (e) {
            case '"':
            case '\\':
            case '/':
                c = (unsigned char)e;
                break;
            case 'n':
                c = '\n';
                break;
            case 'r':
                c = '\r';
                break;
            case 't':
                c = '\t';
                break;
            case 'u': {
                unsigned v = 0;
                for (int i = 0; i < 4; i++) {
                    if (j->p >= j->end || !isxdigit((unsigned char)*j->p)) {
                        j->err = 1;
                        return 0;
                    }
                    char h = *j->p++;
                    v = (v << 4) + (unsigned)(isdigit((unsigned char)h) ? h - '0' : 10 + tolower((unsigned char)h) - 'a');
                }
                if (v < 0x80)
                    c = (unsigned char)v;
                else if (v < 0x800) {
                    if (n + 2 >= cap) {
                        j->err = 1;
                        return 0;
                    }
                    out[n++] = (char)(0xC0 | (v >> 6));
                    out[n++] = (char)(0x80 | (v & 0x3F));
                    continue;
                } else {
                    if (n + 3 >= cap) {
                        j->err = 1;
                        return 0;
                    }
                    out[n++] = (char)(0xE0 | (v >> 12));
                    out[n++] = (char)(0x80 | ((v >> 6) & 0x3F));
                    out[n++] = (char)(0x80 | (v & 0x3F));
                    continue;
                }
                break;
            }
            default:
                c = (unsigned char)e;
                break;
            }
        }
        if (n + 1 >= cap) {
            j->err = 1;
            return 0;
        }
        out[n++] = (char)c;
    }
    if (j->p >= j->end || *j->p != '"') {
        j->err = 1;
        return 0;
    }
    j->p++;
    if (out)
        out[n] = 0;
    return 1;
}

static int j_skip(Json *j);

static int j_skip(Json *j) {
    j_ws(j);
    if (j->p >= j->end) {
        j->err = 1;
        return 0;
    }
    char c = *j->p;
    if (c == '"') {
        size_t depth = 0;
        j->p++;
        while (j->p < j->end && *j->p != '"') {
            if (*j->p == '\\') {
                j->p++;
                if (j->p < j->end)
                    j->p++;
                continue;
            }
            j->p++;
            if (++depth > BODY_MAX)
                break;
        }
        if (j->p < j->end && *j->p == '"')
            j->p++;
        else
            j->err = 1;
        return !j->err;
    }
    if (c == '{') {
        j->p++;
        j_ws(j);
        if (j->p < j->end && *j->p == '}') {
            j->p++;
            return 1;
        }
        for (;;) {
            if (!j_skip(j) || !j_ch(j, ':') || !j_skip(j))
                return 0;
            j_ws(j);
            if (j->p < j->end && *j->p == ',') {
                j->p++;
                continue;
            }
            return j_ch(j, '}');
        }
    }
    if (c == '[') {
        j->p++;
        j_ws(j);
        if (j->p < j->end && *j->p == ']') {
            j->p++;
            return 1;
        }
        for (;;) {
            if (!j_skip(j))
                return 0;
            j_ws(j);
            if (j->p < j->end && *j->p == ',') {
                j->p++;
                continue;
            }
            return j_ch(j, ']');
        }
    }
    if (c == 't' || c == 'f' || c == 'n') {
        if (!strncmp(j->p, "true", 4))
            j->p += 4;
        else if (!strncmp(j->p, "false", 5))
            j->p += 5;
        else if (!strncmp(j->p, "null", 4))
            j->p += 4;
        else
            j->err = 1;
        return !j->err;
    }
    if (c == '-' || isdigit((unsigned char)c)) {
        if (c == '-')
            j->p++;
        while (j->p < j->end && (isdigit((unsigned char)*j->p) || *j->p == '.' || *j->p == 'e' || *j->p == 'E' || *j->p == '+' || *j->p == '-'))
            j->p++;
        return 1;
    }
    j->err = 1;
    return 0;
}

static int parse_all(Json *j, Group *g) {
    if (!j_ch(j, '['))
        return 0;
    j_ws(j);
    if (j->p < j->end && *j->p == ']') {
        j->p++;
        return 1;
    }
    char buf[MAX_NAME];
    for (;;) {
        if (!j_str(j, buf, sizeof buf))
            return 0;
        if (g->nall < MAX_MEMBERS)
            g->all[g->nall++] = intern(buf);
        j_ws(j);
        if (j->p < j->end && *j->p == ',') {
            j->p++;
            continue;
        }
        return j_ch(j, ']');
    }
}

static int parse_proxy_obj(Json *j, const char *key, Catalog *cat) {
    if (!j_ch(j, '{'))
        return 0;
    j_ws(j);
    Group g;
    memset(&g, 0, sizeof g);
    g.name = intern(key);
    g.type = intern("");
    g.now = intern("");
    if (j->p < j->end && *j->p == '}') {
        j->p++;
        return 1;
    }
    char k[MAX_NAME];
    for (;;) {
        if (!j_str(j, k, sizeof k) || !j_ch(j, ':'))
            return 0;
        if (!strcmp(k, "type")) {
            char v[64];
            if (!j_str(j, v, sizeof v))
                return 0;
            g.type = intern(v);
        } else if (!strcmp(k, "now")) {
            char v[MAX_NAME];
            if (!j_str(j, v, sizeof v))
                return 0;
            g.now = intern(v);
        } else if (!strcmp(k, "all")) {
            if (!parse_all(j, &g))
                return 0;
        } else if (!j_skip(j)) {
            return 0;
        }
        j_ws(j);
        if (j->p < j->end && *j->p == ',') {
            j->p++;
            continue;
        }
        if (!j_ch(j, '}'))
            return 0;
        break;
    }
    if (is_group_type(g.type) && cat->n < MAX_GROUPS)
        cat->items[cat->n++] = g;
    return 1;
}

static int parse_proxies(const char *json, Catalog *cat) {
    Json j = {.p = json, .end = json + strlen(json)};
    cat->n = 0;
    if (!j_ch(&j, '{'))
        return -1;
    char k[MAX_NAME];
    j_ws(&j);
    if (j.p < j.end && *j.p == '}')
        return 0;
    for (;;) {
        if (!j_str(&j, k, sizeof k) || !j_ch(&j, ':'))
            return -1;
        if (!strcmp(k, "proxies")) {
            if (!j_ch(&j, '{'))
                return -1;
            j_ws(&j);
            if (j.p < j.end && *j.p == '}') {
                j.p++;
            } else {
                char name[MAX_NAME];
                for (;;) {
                    if (!j_str(&j, name, sizeof name) || !j_ch(&j, ':'))
                        return -1;
                    if (!parse_proxy_obj(&j, name, cat))
                        return -1;
                    j_ws(&j);
                    if (j.p < j.end && *j.p == ',') {
                        j.p++;
                        continue;
                    }
                    if (!j_ch(&j, '}'))
                        return -1;
                    break;
                }
            }
        } else if (!j_skip(&j)) {
            return -1;
        }
        j_ws(&j);
        if (j.p < j.end && *j.p == ',') {
            j.p++;
            continue;
        }
        return j_ch(&j, '}') ? 0 : -1;
    }
}

static Group *find_group(Catalog *cat, const char *name) {
    for (int i = 0; i < cat->n; i++)
        if (strcmp(cat->items[i].name, name) == 0)
            return &cat->items[i];
    return NULL;
}

/* ---- classify / logs ---- */

static const char *classify(const char *err) {
    if (strcasestr(err, "ssl") || strcasestr(err, "syscall") || strcasestr(err, "handshake"))
        return "ssl";
    if (strcasestr(err, "deadline") || strcasestr(err, "i/o timeout"))
        return "timeout";
    if (strcasestr(err, "eof"))
        return "eof";
    if (strcasestr(err, "tls"))
        return "tls";
    if (strcasestr(err, "dns"))
        return "dns";
    if (strcasestr(err, "reset"))
        return "reset";
    if (strcasestr(err, "refused"))
        return "refused";
    return "other";
}

static int fail_type_ok(const char *t) {
    return !strcmp(t, "timeout") || !strcmp(t, "eof") || !strcmp(t, "tls") || !strcmp(t, "reset") || !strcmp(t, "ssl") || !strcmp(t, "dns");
}

static int parse_dial(const char *line, char *group, size_t gcap, char *err, size_t ecap) {
    const char *p = strstr(line, "[TCP]");
    if (!p)
        return 0;
    p = strstr(p, "dial ");
    if (!p)
        return 0;
    p += 5;
    const char *m = strstr(p, " (match ");
    if (!m)
        return 0;
    const char *e = strstr(m, " error: ");
    if (!e)
        return 0;
    size_t glen = (size_t)(m - p);
    if (glen >= gcap)
        glen = gcap - 1;
    memcpy(group, p, glen);
    group[glen] = 0;
    snprintf(err, ecap, "%s", e + 8);
    char *nl = strchr(err, '\n');
    if (nl)
        *nl = 0;
    char *cr = strchr(err, '\r');
    if (cr)
        *cr = 0;
    return 1;
}

static void add_fail(const char *name, int n) {
    for (int i = 0; i < nfails; i++) {
        if (!strcmp(fails[i].name, name)) {
            fails[i].nfail += n;
            return;
        }
    }
    if (nfails >= MAX_WATCHED)
        return;
    snprintf(fails[nfails].name, sizeof fails[0].name, "%s", name);
    fails[nfails].nfail = n;
    nfails++;
}

static int get_fail(const char *name) {
    for (int i = 0; i < nfails; i++)
        if (!strcmp(fails[i].name, name))
            return fails[i].nfail;
    return 0;
}

static time_t last_ts(const char *name) {
    for (int i = 0; i < nlast; i++)
        if (!strcmp(last_switch[i].name, name))
            return last_switch[i].ts;
    return 0;
}

static void set_last(const char *name, time_t ts) {
    for (int i = 0; i < nlast; i++) {
        if (!strcmp(last_switch[i].name, name)) {
            last_switch[i].ts = ts;
            return;
        }
    }
    if (nlast >= MAX_WATCHED)
        return;
    snprintf(last_switch[nlast].name, sizeof last_switch[0].name, "%s", name);
    last_switch[nlast].ts = ts;
    nlast++;
}

static void ev_push(const char *group) {
    int idx;
    if (ev_count == MAX_EVENTS) {
        ev_start = (ev_start + 1) % MAX_EVENTS;
        ev_count--;
    }
    idx = (ev_start + ev_count) % MAX_EVENTS;
    events[idx].ts = time(NULL);
    snprintf(events[idx].group, sizeof events[idx].group, "%s", group);
    ev_count++;
}

static void ev_expire(time_t cut) {
    while (ev_count > 0 && events[ev_start].ts < cut) {
        ev_start = (ev_start + 1) % MAX_EVENTS;
        ev_count--;
    }
}

static void rand_bytes(unsigned char *p, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, p, n);
        close(fd);
        if (r == (ssize_t)n)
            return;
    }
    for (size_t i = 0; i < n; i++)
        p[i] = (unsigned char)(rand() >> 8);
}

static void b64_16(const unsigned char in[16], char out[25]) {
    static const char *t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0;
    for (i = 0; i < 15; i += 3) {
        unsigned v = ((unsigned)in[i] << 16) | ((unsigned)in[i + 1] << 8) | in[i + 2];
        out[j++] = t[(v >> 18) & 63];
        out[j++] = t[(v >> 12) & 63];
        out[j++] = t[(v >> 6) & 63];
        out[j++] = t[v & 63];
    }
    out[j++] = t[(in[15] >> 2) & 63];
    out[j++] = t[(in[15] << 4) & 63];
    out[j++] = '=';
    out[j++] = '=';
    out[j] = 0;
}

static int ws_send(int fd, int opcode, const unsigned char *data, size_t n) {
    unsigned char hdr[14];
    unsigned char mask[4];
    size_t hlen = 2;
    hdr[0] = (unsigned char)(0x80 | (opcode & 0x0f));
    if (n < 126) {
        hdr[1] = (unsigned char)(0x80 | n);
    } else if (n < 65536) {
        hdr[1] = 0x80 | 126;
        hdr[2] = (unsigned char)((n >> 8) & 0xff);
        hdr[3] = (unsigned char)(n & 0xff);
        hlen = 4;
    } else {
        return -1;
    }
    rand_bytes(mask, 4);
    memcpy(hdr + hlen, mask, 4);
    hlen += 4;
    if (send_all(fd, (char *)hdr, hlen) != 0)
        return -1;
    if (!n)
        return 0;
    unsigned char *tmp = malloc(n);
    if (!tmp)
        return -1;
    for (size_t i = 0; i < n; i++)
        tmp[i] = (unsigned char)(data[i] ^ mask[i & 3]);
    int rc = send_all(fd, (char *)tmp, n);
    free(tmp);
    return rc;
}

static void ws_close(void) {
    if (ws_fd >= 0) {
        close(ws_fd);
        ws_fd = -1;
    }
    ws_len = 0;
}

static int extract_payload(const char *json, char *out, size_t cap) {
    Json j = {.p = json, .end = json + strlen(json)};
    j_ws(&j);
    if (j.p >= j.end || *j.p != '{') {
        snprintf(out, cap, "%s", json);
        return 1;
    }
    if (!j_ch(&j, '{'))
        return 0;
    char k[64];
    j_ws(&j);
    while (j.p < j.end && *j.p != '}') {
        if (!j_str(&j, k, sizeof k) || !j_ch(&j, ':'))
            return 0;
        if (!strcmp(k, "payload"))
            return j_str(&j, out, cap);
        if (!j_skip(&j))
            return 0;
        j_ws(&j);
        if (j.p < j.end && *j.p == ',')
            j.p++;
        j_ws(&j);
    }
    snprintf(out, cap, "%s", json);
    return 1;
}

static void ingest_log(const char *msg) {
    char payload[4096], group[MAX_NAME], err[256];
    if (!extract_payload(msg, payload, sizeof payload))
        snprintf(payload, sizeof payload, "%s", msg);
    if (parse_dial(payload, group, sizeof group, err, sizeof err) && fail_type_ok(classify(err)))
        ev_push(group);
}

static int ws_handle_frame(int opcode, const unsigned char *data, size_t n, int fin) {
    if (opcode == 0x8)
        return -1;
    if (opcode == 0x9)
        return ws_send(ws_fd, 0xA, data, n);
    if (opcode == 0xA)
        return 0;
    if (!fin)
        return 0;
    if (opcode == 0x1 || opcode == 0x2) {
        char *txt = malloc(n + 1);
        if (!txt)
            return 0;
        memcpy(txt, data, n);
        txt[n] = 0;
        ingest_log(txt);
        free(txt);
    }
    return 0;
}

static int ws_pump(void) {
    if (ws_fd < 0)
        return -1;
    for (;;) {
        ssize_t r = recv(ws_fd, ws_buf + ws_len, sizeof ws_buf - ws_len, 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                break;
            return -1;
        }
        if (r == 0)
            return -1;
        ws_len += (size_t)r;
        if (ws_len == sizeof ws_buf)
            return -1;
        if (ws_len < sizeof ws_buf)
            break;
    }
    while (ws_len >= 2) {
        unsigned char b0 = ws_buf[0], b1 = ws_buf[1];
        int fin = b0 & 0x80;
        int opcode = b0 & 0x0f;
        int masked = b1 & 0x80;
        uint64_t plen = b1 & 0x7f;
        size_t off = 2;
        if (plen == 126) {
            if (ws_len < 4)
                break;
            plen = ((uint64_t)ws_buf[2] << 8) | ws_buf[3];
            off = 4;
        } else if (plen == 127) {
            if (ws_len < 10)
                break;
            plen = 0;
            for (int i = 0; i < 8; i++)
                plen = (plen << 8) | ws_buf[2 + i];
            off = 10;
        }
        if (masked)
            off += 4;
        if (plen > WS_BUF / 2)
            return -1;
        if (ws_len < off + (size_t)plen)
            break;
        unsigned char *payload = ws_buf + off;
        if (masked) {
            unsigned char *mask = ws_buf + off - 4;
            for (uint64_t i = 0; i < plen; i++)
                payload[i] ^= mask[i & 3];
        }
        if (ws_handle_frame(opcode, payload, (size_t)plen, fin) < 0)
            return -1;
        size_t used = off + (size_t)plen;
        memmove(ws_buf, ws_buf + used, ws_len - used);
        ws_len -= used;
    }
    return 0;
}

static int ws_connect(void) {
    unsigned char keyraw[16];
    char keyb64[25], req[1024], hdr[2048];
    ws_close();
    int fd = tcp_connect(cfg.api_host, cfg.api_port, 8);
    if (fd < 0)
        return -1;
    rand_bytes(keyraw, 16);
    b64_16(keyraw, keyb64);
    snprintf(req, sizeof req,
             "GET /logs?level=%s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Authorization: Bearer %s\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n",
             cfg.log_level, cfg.api_host, cfg.api_port, cfg.secret, keyb64);
    if (send_all(fd, req, strlen(req)) != 0) {
        close(fd);
        return -1;
    }
    size_t n = 0;
    hdr[0] = 0;
    while (n + 1 < sizeof hdr && !strstr(hdr, "\r\n\r\n")) {
        ssize_t r = recv(fd, hdr + n, sizeof hdr - n - 1, 0);
        if (r <= 0) {
            close(fd);
            return -1;
        }
        n += (size_t)r;
        hdr[n] = 0;
    }
    if (strncmp(hdr, "HTTP/1.1 101", 12) != 0 && strncmp(hdr, "HTTP/1.0 101", 12) != 0) {
        close(fd);
        return -1;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    ws_fd = fd;
    ws_len = 0;
    printf("logs connected level=%s\n", cfg.log_level);
    fflush(stdout);
    return 0;
}

static void count_log_fails(Catalog *cat, char watched[][MAX_NAME], int nwatch) {
    time_t cut = time(NULL) - cfg.window;
    ev_expire(cut);
    nfails = 0;
    for (int i = 0; i < ev_count; i++) {
        FailEvent *e = &events[(ev_start + i) % MAX_EVENTS];
        const char *target = resolve_watch_group(e->group, cat, watched, nwatch);
        if (target)
            add_fail(target, 1);
    }
}

static int run_curl(char *const argv[], char *err, size_t errcap) {
    int pipefd[2];
    if (pipe(pipefd) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv("/usr/bin/curl", argv);
        _exit(127);
    }
    close(pipefd[1]);
    size_t n = 0;
    if (err && errcap) {
        err[0] = 0;
        while (n + 1 < errcap) {
            ssize_t r = read(pipefd[0], err + n, errcap - n - 1);
            if (r <= 0)
                break;
            n += (size_t)r;
        }
        err[n] = 0;
    } else {
        char drain[256];
        while (read(pipefd[0], drain, sizeof drain) > 0) {
        }
    }
    close(pipefd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    return -1;
}

static int probe_default_https(char *err, size_t errcap) {
    char *argv[] = {
        "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{errormsg}",
        "--max-time", "8", "-x", cfg.proxy, (char *)HEALTH_URL, NULL,
    };
    int rc = run_curl(argv, err, errcap);
    if (rc == 0)
        return 1;
    if (err && !err[0])
        snprintf(err, errcap, "curl-exit-%d", rc);
    return 0;
}

static void tmpl_expand(char *dst, size_t cap, const char *tmpl,
                        const char *device, const char *group,
                        const char *old, const char *nw) {
    size_t o = 0;
    for (const char *p = tmpl; *p && o + 1 < cap;) {
        if (*p == '{') {
            const char *end = strchr(p, '}');
            if (end) {
                size_t klen = (size_t)(end - (p + 1));
                const char *val = NULL;
                if (klen == 6 && !memcmp(p + 1, "device", 6))
                    val = device ? device : "";
                else if (klen == 5 && !memcmp(p + 1, "group", 5))
                    val = group ? group : "";
                else if (klen == 3 && !memcmp(p + 1, "old", 3))
                    val = old ? old : "";
                else if (klen == 3 && !memcmp(p + 1, "new", 3))
                    val = nw ? nw : "";
                if (val) {
                    size_t vl = strlen(val);
                    if (o + vl >= cap)
                        vl = cap - 1 - o;
                    memcpy(dst + o, val, vl);
                    o += vl;
                    p = end + 1;
                    continue;
                }
            }
        }
        dst[o++] = *p++;
    }
    dst[o] = 0;
}

static void notify_switch(const char *gname, const char *old, const char *nw) {
    if (!cfg.bark_key[0])
        return;
    char ek[256], et[256], eb[1024], eg[128], url[1600];
    char title[256];
    char body[512];
    const char *title_tmpl = cfg.bark_title[0] ? cfg.bark_title
        : (cfg.bark_device[0] ? "{device} | mihomo 切换" : "mihomo 切换");
    const char *body_tmpl = cfg.bark_body[0] ? cfg.bark_body : "{group}: {old} → {new}";
    tmpl_expand(title, sizeof title, title_tmpl, cfg.bark_device, gname, old, nw);
    tmpl_expand(body, sizeof body, body_tmpl, cfg.bark_device, gname, old, nw);
    urlenc(cfg.bark_key, ek, sizeof ek);
    urlenc(title, et, sizeof et);
    urlenc(body, eb, sizeof eb);
    urlenc(cfg.bark_group, eg, sizeof eg);
    snprintf(url, sizeof url, "https://api.day.app/%s/%s/%s?group=%s&ttl=600", ek, et, eb, eg);
    char *argv_proxy[] = {"curl", "-sS", "-o", "/dev/null", "--max-time", "8", "-x", cfg.proxy, url, NULL};
    if (run_curl(argv_proxy, NULL, 0) == 0) {
        printf("notify ok\n");
        fflush(stdout);
        return;
    }
    char *argv_direct[] = {"curl", "-sS", "-o", "/dev/null", "--max-time", "8", url, NULL};
    if (run_curl(argv_direct, NULL, 0) == 0) {
        printf("notify ok direct\n");
        fflush(stdout);
        return;
    }
    printf("notify fail\n");
    fflush(stdout);
}

/* ---- yaml demote ---- */

static char *strip_quotes(char *s) {
    size_t n = strlen(s);
    if (n >= 2 && ((s[0] == '\'' && s[n - 1] == '\'') || (s[0] == '"' && s[n - 1] == '"'))) {
        s[n - 1] = 0;
        memmove(s, s + 1, n - 1);
        if (s[0] == '\'') {
            char *d = s, *p = s;
            while (*p) {
                if (p[0] == '\'' && p[1] == '\'') {
                    *d++ = '\'';
                    p += 2;
                } else {
                    *d++ = *p++;
                }
            }
            *d = 0;
        }
    }
    return s;
}

static void go_escape(const char *s, char *out, size_t cap) {
    size_t j = 0;
    for (; *s && j + 3 < cap; s++) {
        if (strchr(".\\+*?()[]{}|^$", *s)) {
            out[j++] = '\\';
        }
        out[j++] = *s;
    }
    out[j] = 0;
}

static void yaml_quote(const char *s, char *out, size_t cap) {
    size_t j = 0;
    if (j + 1 < cap)
        out[j++] = '\'';
    for (; *s && j + 3 < cap; s++) {
        if (*s == '\'') {
            out[j++] = '\'';
            out[j++] = '\'';
        } else {
            out[j++] = *s;
        }
    }
    if (j + 1 < cap)
        out[j++] = '\'';
    out[j] = 0;
}

static int parse_filter_names(const char *filt, char names[][MAX_NAME], int maxn) {
    char buf[8192];
    snprintf(buf, sizeof buf, "%s", filt);
    char *s = buf;
    while (*s == ' ' || *s == '\t')
        s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n'))
        s[--n] = 0;
    strip_quotes(s);
    int cnt = 0;
    const char *start = s;
    for (const char *p = s;; p++) {
        if (*p && !(*p == '|' && (p == s || p[-1] != '\\')))
            continue;
        size_t len = (size_t)(p - start);
        char part[MAX_NAME];
        if (len >= sizeof part)
            len = sizeof part - 1;
        memcpy(part, start, len);
        part[len] = 0;
        char *t = part;
        while (*t == ' ')
            t++;
        char *e = t + strlen(t);
        while (e > t && e[-1] == ' ')
            *--e = 0;
        if (*t && cnt < maxn) {
            char un[MAX_NAME];
            size_t j = 0;
            for (char *q = t; *q && j + 1 < sizeof un; q++) {
                if (*q == '\\' && q[1]) {
                    un[j++] = *++q;
                } else {
                    un[j++] = *q;
                }
            }
            un[j] = 0;
            snprintf(names[cnt++], MAX_NAME, "%s", un);
        }
        if (!*p)
            break;
        start = p + 1;
    }
    return cnt;
}

static const char *next_leaf(Group *g) {
    if (!g || g->nall <= 0)
        return NULL;
    int start = -1;
    for (int i = 0; i < g->nall; i++)
        if (!strcmp(g->all[i], g->now ? g->now : ""))
            start = i;
    for (int i = 1; i <= g->nall; i++) {
        const char *cand = g->all[(start + i) % g->nall];
        if (strcmp(cand, g->now ? g->now : "") != 0)
            return cand;
    }
    return NULL;
}

static int watched_has(char watched[][MAX_NAME], int n, const char *name) {
    for (int i = 0; i < n; i++)
        if (!strcmp(watched[i], name))
            return 1;
    return 0;
}

static const char *resolve_watch_group(const char *dial, Catalog *cat, char watched[][MAX_NAME], int nwatch) {
    const char *name = dial;
    const char *seen[16];
    int nseen = 0;
    while (name && name[0] && !watched_has(watched, nwatch, name)) {
        for (int i = 0; i < nseen; i++)
            if (!strcmp(seen[i], name))
                return NULL;
        if (nseen < 16)
            seen[nseen++] = name;
        Group *g = find_group(cat, name);
        if (!g || !is_group_type(g->type))
            return NULL;
        name = g->now ? g->now : "";
    }
    if (!name || !watched_has(watched, nwatch, name))
        return NULL;
    const char *nested[16];
    int nn = 0;
    for (;;) {
        for (int i = 0; i < nn; i++)
            if (!strcmp(nested[i], name))
                return name;
        if (nn < 16)
            nested[nn++] = name;
        Group *g = find_group(cat, name);
        const char *child = (g && g->now) ? g->now : "";
        if (watched_has(watched, nwatch, child)) {
            name = child;
            continue;
        }
        break;
    }
    return name;
}

static int auto_groups(Catalog *cat, char watched[][MAX_NAME]) {
    int n = 0;
    for (int i = 0; i < cat->n && n < MAX_WATCHED; i++) {
        Group *g = &cat->items[i];
        if (!ends_with(g->name, AUTO_SUFFIX))
            continue;
        if (in_list(g->name, WATCH_SKIP))
            continue;
        if (!is_group_type(g->type))
            continue;
        snprintf(watched[n++], MAX_NAME, "%s", g->name);
    }
    if (find_group(cat, DEFAULT_GROUP) && !watched_has(watched, n, DEFAULT_GROUP) && n < MAX_WATCHED)
        snprintf(watched[n++], MAX_NAME, "%s", DEFAULT_GROUP);
    return n;
}

static int load_groups(Catalog *cat) {
    char *body = NULL;
    if (api("GET", "/proxies", NULL, &body) != 0)
        return -1;
    int rc = parse_proxies(body, cat);
    free(body);
    return rc;
}

static int split_lines(char *text, char **lines, int maxn) {
    int n = 0;
    char *p = text;
    while (*p && n < maxn) {
        lines[n++] = p;
        char *nl = strchr(p, '\n');
        if (!nl)
            break;
        *nl = 0;
        p = nl + 1;
    }
    return n;
}

static int starts(const char *s, const char *pfx) {
    return strncmp(s, pfx, strlen(pfx)) == 0;
}

static int demote_group_leaf(const char *gname, const char *leaf, char *bak_path, size_t bak_cap) {
    size_t n = 0;
    char *orig = read_file(cfg.config_path, &n);
    if (!orig)
        return -1;
    char *pg = strstr(orig, "proxy-groups:");
    char *rules = strstr(orig, "\nrules:");
    if (!pg || !rules || rules < pg) {
        free(orig);
        return -1;
    }
    size_t head_n = (size_t)(pg - orig);
    size_t mid_n = (size_t)(rules - pg);
    char *mid = malloc(mid_n + 1);
    if (!mid) {
        free(orig);
        return -1;
    }
    memcpy(mid, pg, mid_n);
    mid[mid_n] = 0;
    char *lines[MAX_LINES];
    int nlines = split_lines(mid, lines, MAX_LINES);
    int bstart = -1, bend = -1;
    char bname[MAX_NAME];
    for (int i = 0; i < nlines; i++) {
        if (starts(lines[i], "  - name:")) {
            if (bstart >= 0 && strcmp(bname, gname) == 0) {
                bend = i;
                break;
            }
            const char *v = strchr(lines[i], ':');
            snprintf(bname, sizeof bname, "%s", v ? v + 1 : "");
            char *t = bname;
            while (*t == ' ')
                t++;
            memmove(bname, t, strlen(t) + 1);
            strip_quotes(bname);
            bstart = i;
        }
    }
    if (bstart >= 0 && bend < 0 && strcmp(bname, gname) == 0)
        bend = nlines;
    if (bstart < 0 || bend <= bstart) {
        free(mid);
        free(orig);
        return -1;
    }
    int filter_i = -1, proxies_i = -1;
    for (int i = bstart; i < bend; i++) {
        if (starts(lines[i], "    filter:"))
            filter_i = i;
        if (starts(lines[i], "    proxies:"))
            proxies_i = i;
    }
    char filter_line[8192];
    char proxy_extra[MAX_MEMBERS][MAX_NAME + 16];
    int nproxy_extra = 0;
    int skip_from = -1, skip_to = -1;
    int replace_i = -1;
    const char *replace_s = NULL;
    if (filter_i >= 0) {
        const char *fv = strchr(lines[filter_i], ':');
        fv = fv ? fv + 1 : "";
        char names[MAX_MEMBERS][MAX_NAME];
        int nn = parse_filter_names(fv, names, MAX_MEMBERS);
        int hit = 0, nk = 0;
        char kept[MAX_MEMBERS][MAX_NAME];
        for (int i = 0; i < nn; i++) {
            if (!strcmp(names[i], leaf)) {
                hit = 1;
                continue;
            }
            memcpy(kept[nk], names[i], MAX_NAME);
            nk++;
        }
        if (!hit || nk < 1) {
            free(mid);
            free(orig);
            return -1;
        }
        char joined[8000] = {0};
        for (int i = 0; i < nk; i++) {
            char esc[MAX_NAME * 2];
            go_escape(kept[i], esc, sizeof esc);
            if (i)
                strncat(joined, "|", sizeof joined - strlen(joined) - 1);
            strncat(joined, esc, sizeof joined - strlen(joined) - 1);
        }
        char quoted[8008];
        yaml_quote(joined, quoted, sizeof quoted);
        snprintf(filter_line, sizeof filter_line, "    filter: %s", quoted);
        replace_i = filter_i;
        replace_s = filter_line;
    } else if (proxies_i >= 0) {
        char names[MAX_MEMBERS][MAX_NAME];
        int nn = 0, pend = proxies_i + 1;
        while (pend < bend && starts(lines[pend], "      - ")) {
            char item[MAX_NAME];
            snprintf(item, sizeof item, "%s", lines[pend] + 8);
            char *t = item;
            while (*t == ' ')
                t++;
            char *e = t + strlen(t);
            while (e > t && (e[-1] == ' ' || e[-1] == '\r'))
                *--e = 0;
            strip_quotes(t);
            if (nn < MAX_MEMBERS) {
                memset(names[nn], 0, MAX_NAME);
                strncpy(names[nn], t, MAX_NAME - 1);
                nn++;
            }
            pend++;
        }
        int hit = 0, nk = 0;
        char kept[MAX_MEMBERS][MAX_NAME];
        for (int i = 0; i < nn; i++) {
            if (!strcmp(names[i], leaf)) {
                hit = 1;
                continue;
            }
            memcpy(kept[nk], names[i], MAX_NAME);
            nk++;
        }
        if (!hit || nk < 1) {
            free(mid);
            free(orig);
            return -1;
        }
        skip_from = proxies_i + 1;
        skip_to = pend;
        nproxy_extra = nk;
        for (int k = 0; k < nk; k++) {
            char q[MAX_NAME + 8];
            yaml_quote(kept[k], q, sizeof q);
            snprintf(proxy_extra[k], sizeof proxy_extra[0], "      - %s", q);
        }
    } else {
        free(mid);
        free(orig);
        return -1;
    }
    size_t outcap = n + 8192;
    char *out = malloc(outcap);
    if (!out) {
        free(mid);
        free(orig);
        return -1;
    }
    memcpy(out, orig, head_n);
    size_t o = head_n;
    for (int i = 0; i < nlines; i++) {
        const char *s = lines[i];
        if (i == replace_i)
            s = replace_s;
        if (skip_from >= 0 && i >= skip_from && i < skip_to) {
            if (i == skip_from) {
                for (int k = 0; k < nproxy_extra; k++) {
                    size_t ln = strlen(proxy_extra[k]);
                    if (o + ln + 2 > outcap)
                        break;
                    memcpy(out + o, proxy_extra[k], ln);
                    o += ln;
                    out[o++] = '\n';
                }
            }
            continue;
        }
        size_t ln = strlen(s);
        if (o + ln + 2 > outcap)
            break;
        memcpy(out + o, s, ln);
        o += ln;
        out[o++] = '\n';
    }
    size_t tail_n = strlen(rules);
    if (o + tail_n + 1 > outcap) {
        free(out);
        free(mid);
        free(orig);
        return -1;
    }
    memcpy(out + o, rules, tail_n + 1);
    o += tail_n;
    char stamp[32];
    time_t now = time(NULL);
    strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", localtime(&now));
    snprintf(bak_path, bak_cap, "%s.bak.%s", cfg.config_path, stamp);
    if (copy_file(cfg.config_path, bak_path) != 0) {
        free(out);
        free(mid);
        free(orig);
        return -1;
    }
    if (write_file(cfg.config_path, out, o) != 0) {
        free(out);
        free(mid);
        free(orig);
        return -1;
    }
    char esc[1024], body[1200];
    json_esc(cfg.reload_path, esc, sizeof esc);
    snprintf(body, sizeof body, "{\"path\":\"%s\"}", esc);
    char *resp = NULL;
    api("PUT", "/configs?force=true", body, &resp);
    free(resp);
    sleep(1);
    free(out);
    free(mid);
    free(orig);
    return 0;
}

static int close_cursor(void) {
    char *body = NULL;
    if (api("GET", "/connections", NULL, &body) != 0)
        return 0;
    Json j = {.p = body, .end = body + strlen(body)};
    int closed = 0;
    if (!j_ch(&j, '{')) {
        free(body);
        return 0;
    }
    char k[MAX_NAME];
    j_ws(&j);
    for (;;) {
        if (j.p >= j.end)
            break;
        if (*j.p == '}')
            break;
        if (!j_str(&j, k, sizeof k) || !j_ch(&j, ':'))
            break;
        if (!strcmp(k, "connections")) {
            if (!j_ch(&j, '['))
                break;
            j_ws(&j);
            if (j.p < j.end && *j.p == ']') {
                j.p++;
            } else {
                for (;;) {
                    char id[128] = {0}, host[256] = {0}, sniff[256] = {0};
                    if (!j_ch(&j, '{'))
                        break;
                    j_ws(&j);
                    if (j.p < j.end && *j.p != '}') {
                        for (;;) {
                            char fk[64];
                            if (!j_str(&j, fk, sizeof fk) || !j_ch(&j, ':'))
                                break;
                            if (!strcmp(fk, "id")) {
                                j_str(&j, id, sizeof id);
                            } else if (!strcmp(fk, "metadata")) {
                                if (!j_ch(&j, '{'))
                                    break;
                                j_ws(&j);
                                if (j.p < j.end && *j.p != '}') {
                                    for (;;) {
                                        char mk[64];
                                        if (!j_str(&j, mk, sizeof mk) || !j_ch(&j, ':'))
                                            break;
                                        if (!strcmp(mk, "host"))
                                            j_str(&j, host, sizeof host);
                                        else if (!strcmp(mk, "sniffHost"))
                                            j_str(&j, sniff, sizeof sniff);
                                        else
                                            j_skip(&j);
                                        j_ws(&j);
                                        if (j.p < j.end && *j.p == ',') {
                                            j.p++;
                                            continue;
                                        }
                                        j_ch(&j, '}');
                                        break;
                                    }
                                } else {
                                    j.p++;
                                }
                            } else {
                                j_skip(&j);
                            }
                            j_ws(&j);
                            if (j.p < j.end && *j.p == ',') {
                                j.p++;
                                continue;
                            }
                            j_ch(&j, '}');
                            break;
                        }
                    } else {
                        j.p++;
                    }
                    if (id[0] && (strstr(host, "cursor") || strstr(sniff, "cursor"))) {
                        char enc[256], path[300];
                        urlenc(id, enc, sizeof enc);
                        snprintf(path, sizeof path, "/connections/%s", enc);
                        char *r = NULL;
                        if (api("DELETE", path, NULL, &r) == 0)
                            closed++;
                        free(r);
                    }
                    j_ws(&j);
                    if (j.p < j.end && *j.p == ',') {
                        j.p++;
                        continue;
                    }
                    j_ch(&j, ']');
                    break;
                }
            }
        } else {
            j_skip(&j);
        }
        j_ws(&j);
        if (j.p < j.end && *j.p == ',') {
            j.p++;
            continue;
        }
        break;
    }
    free(body);
    return closed;
}

/* ---- watchdog ---- */

static int load_catalog(Catalog *cat, char watched[][MAX_NAME], int *nwatch) {
    if (load_groups(cat) != 0)
        return -1;
    if (cfg.nonly) {
        *nwatch = 0;
        for (int i = 0; i < cfg.nonly && *nwatch < MAX_WATCHED; i++)
            snprintf(watched[(*nwatch)++], MAX_NAME, "%s", cfg.only[i]);
    } else {
        *nwatch = auto_groups(cat, watched);
    }
    return 0;
}

static void tick(void) {
    pool_reset();
    Catalog cat;
    char watched[MAX_WATCHED][MAX_NAME];
    int nwatch = 0;
    if (load_catalog(&cat, watched, &nwatch) != 0) {
        printf("watchdog load groups failed\n");
        fflush(stdout);
        return;
    }
    count_log_fails(&cat, watched, nwatch);
    char perr[256];
    if (!probe_default_https(perr, sizeof perr)) {
        printf("probe-fail %s %s\n", DEFAULT_GROUP, perr);
        fflush(stdout);
        add_fail(DEFAULT_GROUP, cfg.fails);
    }
    time_t now_ts = time(NULL);
    for (int i = 0; i < nwatch; i++) {
        const char *gname = watched[i];
        int nfail = get_fail(gname);
        if (nfail < cfg.fails)
            continue;
        if (now_ts - last_ts(gname) < cfg.cooldown) {
            printf("cooldown %s fails=%d\n", gname, nfail);
            fflush(stdout);
            continue;
        }
        Group *g = find_group(&cat, gname);
        char now[MAX_NAME], nxt[MAX_NAME], actual[MAX_NAME], switched[MAX_NAME];
        snprintf(now, sizeof now, "%s", (g && g->now) ? g->now : "");
        const char *nxtp = next_leaf(g);
        if (!nxtp || !strcmp(nxtp, now)) {
            printf("no-next %s now=%s fails=%d\n", gname, now, nfail);
            fflush(stdout);
            continue;
        }
        snprintf(nxt, sizeof nxt, "%s", nxtp);
        printf("switch %s fails=%d %s -> %s\n", gname, nfail, now, nxt);
        fflush(stdout);
        if (cfg.dry_run)
            continue;
        if (put_group(gname, nxt) != 0) {
            printf("put-fail %s\n", gname);
            fflush(stdout);
            set_last(gname, now_ts);
            continue;
        }
        usleep(300000);
        Catalog after;
        if (load_groups(&after) != 0) {
            set_last(gname, now_ts);
            continue;
        }
        Group *ag = find_group(&after, gname);
        snprintf(actual, sizeof actual, "%s", (ag && ag->now) ? ag->now : "");
        switched[0] = 0;
        if (!strcmp(actual, nxt)) {
            snprintf(switched, sizeof switched, "%s", actual);
        } else {
            printf("put-bounce %s want=%s now=%s\n", gname, nxt, actual);
            fflush(stdout);
            char bak[600];
            const char *drop = actual[0] ? actual : now;
            if (demote_group_leaf(gname, drop, bak, sizeof bak) == 0) {
                Catalog dem;
                load_groups(&dem);
                Group *dg = find_group(&dem, gname);
                const char *after_now = (dg && dg->now) ? dg->now : "";
                printf("demote %s drop=%s now=%s backup=%s\n", gname, drop, after_now, bak);
                fflush(stdout);
                if (after_now[0] && strcmp(after_now, now) != 0)
                    snprintf(switched, sizeof switched, "%s", after_now);
            } else {
                printf("demote-fail %s\n", gname);
                fflush(stdout);
            }
        }
        set_last(gname, now_ts);
        if (switched[0]) {
            notify_switch(gname, now, switched);
            if (!strcmp(gname, CURSOR_GROUP) && cfg.close_cursor) {
                printf("closed %d cursor connections\n", close_cursor());
                fflush(stdout);
            }
        }
    }
}

static void env_or(char *dst, size_t cap, const char *key, const char *def) {
    const char *v = getenv(key);
    snprintf(dst, cap, "%s", (v && v[0]) ? v : def);
}

static void parse_api(const char *api) {
    const char *p = api;
    if (!strncmp(p, "http://", 7))
        p += 7;
    else
        die("MIHOMO_API 只支持 http://");
    snprintf(cfg.api_host, sizeof cfg.api_host, "%s", p);
    char *slash = strchr(cfg.api_host, '/');
    if (slash)
        *slash = 0;
    cfg.api_port = 80;
    char *colon = strrchr(cfg.api_host, ':');
    if (colon) {
        *colon = 0;
        cfg.api_port = atoi(colon + 1);
    }
}

static void load_optional_text(char *dst, size_t cap, const char *path) {
    if (dst[0])
        return;
    char *s = read_file(path, NULL);
    if (!s)
        return;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
        *--e = 0;
    char *p = s;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p)
        snprintf(dst, cap, "%s", p);
    free(s);
}

static void load_bark_text(void) {
    load_optional_text(cfg.bark_device, sizeof cfg.bark_device, "bark-device");
    load_optional_text(cfg.bark_title, sizeof cfg.bark_title, "bark-title");
    load_optional_text(cfg.bark_body, sizeof cfg.bark_body, "bark-body");
}

static void load_secret(void) {
    char *s = read_file(cfg.secret, NULL);
    if (!s)
        die("读不了 MIHOMO_SECRET_FILE");
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' '))
        *--e = 0;
    if (strlen(s) >= sizeof cfg.secret)
        die("secret 太长");
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s", s);
    snprintf(cfg.secret, sizeof cfg.secret, "%s", tmp);
    free(s);
}

static void usage(void) {
    fprintf(stderr,
            "mihomo-watchdog [--interval N] [--window N] [--fails N] [--cooldown N]\n"
            "                [--group NAME]... [--once] [--dry-run] [--no-close-cursor]\n");
}

int main(int argc, char **argv) {
    memset(&cfg, 0, sizeof cfg);
    cfg.interval = 8;
    cfg.window = 10;
    cfg.fails = 3;
    cfg.cooldown = 20;
    cfg.close_cursor = 1;
    char apiurl[256];
    env_or(apiurl, sizeof apiurl, "MIHOMO_API", "http://127.0.0.1:19090");
    env_or(cfg.proxy, sizeof cfg.proxy, "MIHOMO_PROXY", "http://127.0.0.1:17890");
    env_or(cfg.secret, sizeof cfg.secret, "MIHOMO_SECRET_FILE", "/home/chieh/work/prod/mihomo/data/api-secret.txt");
    env_or(cfg.config_path, sizeof cfg.config_path, "MIHOMO_CONFIG", "/home/chieh/work/prod/mihomo/data/config.yaml");
    env_or(cfg.reload_path, sizeof cfg.reload_path, "MIHOMO_RELOAD_PATH", "/root/.config/mihomo/config.yaml");
    env_or(cfg.log_level, sizeof cfg.log_level, "MIHOMO_LOG_LEVEL", "warning");
    env_or(cfg.bark_key, sizeof cfg.bark_key, "BARK_KEY", "");
    env_or(cfg.bark_group, sizeof cfg.bark_group, "BARK_GROUP", "mihomo");
    env_or(cfg.bark_device, sizeof cfg.bark_device, "BARK_DEVICE", "");
    env_or(cfg.bark_title, sizeof cfg.bark_title, "BARK_TITLE", "");
    env_or(cfg.bark_body, sizeof cfg.bark_body, "BARK_BODY", "");
    parse_api(apiurl);
    load_secret();
    load_bark_text();
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--interval") && i + 1 < argc)
            cfg.interval = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--window") && i + 1 < argc)
            cfg.window = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--fails") && i + 1 < argc)
            cfg.fails = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--cooldown") && i + 1 < argc)
            cfg.cooldown = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--group") && i + 1 < argc) {
            if (cfg.nonly < MAX_WATCHED)
                snprintf(cfg.only[cfg.nonly++], MAX_NAME, "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--once"))
            cfg.once = 1;
        else if (!strcmp(argv[i], "--dry-run"))
            cfg.dry_run = 1;
        else if (!strcmp(argv[i], "--no-close-cursor"))
            cfg.close_cursor = 0;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage();
            return 0;
        } else {
            usage();
            return 2;
        }
    }
    if (cfg.interval < 1)
        cfg.interval = 1;
    for (char *p = cfg.log_level; *p; p++) {
        if (!isalnum((unsigned char)*p))
            die("MIHOMO_LOG_LEVEL 只能是字母数字");
    }
    Catalog cat;
    char watched[MAX_WATCHED][MAX_NAME];
    int nwatch = 0;
    if (load_catalog(&cat, watched, &nwatch) != 0)
        die("GET /proxies 失败");
    printf("watchdog interval=%ds window=%ds fails=%d cooldown=%ds groups=%d logs=ws\n",
           cfg.interval, cfg.window, cfg.fails, cfg.cooldown, nwatch);
    for (int i = 0; i < nwatch; i++)
        printf("  watch %s\n", watched[i]);
    fflush(stdout);
    if (ws_connect() != 0)
        printf("logs connect fail, retry\n");
    fflush(stdout);
    if (cfg.once) {
        if (ws_fd >= 0) {
            struct pollfd pfd = {.fd = ws_fd, .events = POLLIN};
            if (poll(&pfd, 1, 300) > 0 && (pfd.revents & POLLIN))
                ws_pump();
        }
        tick();
        ws_close();
        return 0;
    }
    for (;;) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (;;) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            int remain_ms = cfg.interval * 1000
                - (int)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
            if (remain_ms <= 0)
                break;
            if (ws_fd < 0) {
                if (ws_connect() != 0) {
                    printf("logs reconnect fail\n");
                    fflush(stdout);
                    usleep(200000);
                    continue;
                }
            }
            struct pollfd pfd = {.fd = ws_fd, .events = POLLIN};
            int pr = poll(&pfd, 1, remain_ms);
            if (pr < 0) {
                if (errno == EINTR)
                    continue;
                ws_close();
                continue;
            }
            if (pr == 0)
                break;
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                printf("logs disconnect\n");
                fflush(stdout);
                ws_close();
                continue;
            }
            if ((pfd.revents & POLLIN) && ws_pump() < 0) {
                printf("logs disconnect\n");
                fflush(stdout);
                ws_close();
            }
        }
        tick();
    }
}

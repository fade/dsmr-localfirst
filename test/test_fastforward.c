/* Unit test for the fastforward catch-all awareness in clause 2: the djb cdb
 * reader (cdb_find), the controlled-wildcard membership test
 * (fastforward_cdb_match), and the dot-qmail parser (fastforward_invocation).
 *
 * These are static internals, so the test compiles system_identity.c directly
 * (it is NOT also linked, to avoid duplicate symbols). The cdb fixtures are
 * built by an INDEPENDENT minimal cdbmake below — deliberately separate code
 * from the reader under test, so a shared bug cannot mask a fault. The on-host
 * integration test additionally cross-checks the reader against a cdb produced
 * by the real setforward(1). */
#include "../src/system_identity.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

/* --- independent cdb writer (standard two-pass cdbmake) --------------------- */

struct hentry { uint32_t h, p; };

struct cdbw {
    FILE *f;
    uint32_t pos;
    struct hentry *tbl[256];
    uint32_t cnt[256], cap[256];
};

static void wu32(FILE *f, uint32_t v)
{
    unsigned char b[4];
    b[0] = (unsigned char)(v & 0xff);
    b[1] = (unsigned char)((v >> 8) & 0xff);
    b[2] = (unsigned char)((v >> 16) & 0xff);
    b[3] = (unsigned char)((v >> 24) & 0xff);
    fwrite(b, 1, 4, f);
}

static void cdbw_begin(struct cdbw *w, const char *path)
{
    int i;
    char hdr[2048];
    memset(w, 0, sizeof(*w));
    w->f = fopen(path, "wb");
    if (w->f == NULL) { perror(path); exit(2); }
    memset(hdr, 0, sizeof(hdr));
    fwrite(hdr, 1, sizeof(hdr), w->f);   /* header placeholder */
    w->pos = 2048;
    for (i = 0; i < 256; ++i) { w->tbl[i] = NULL; w->cnt[i] = w->cap[i] = 0; }
}

static void cdbw_add(struct cdbw *w, const char *key, const char *data)
{
    uint32_t klen = (uint32_t)strlen(key);
    uint32_t dlen = (uint32_t)strlen(data);
    uint32_t h = cdb_hash((const unsigned char *)key, klen);
    int t = h & 255;

    wu32(w->f, klen);
    wu32(w->f, dlen);
    fwrite(key, 1, klen, w->f);
    fwrite(data, 1, dlen, w->f);

    if (w->cnt[t] == w->cap[t]) {
        w->cap[t] = w->cap[t] ? w->cap[t] * 2 : 4;
        w->tbl[t] = realloc(w->tbl[t], w->cap[t] * sizeof(struct hentry));
        if (w->tbl[t] == NULL) { perror("realloc"); exit(2); }
    }
    w->tbl[t][w->cnt[t]].h = h;
    w->tbl[t][w->cnt[t]].p = w->pos;
    w->cnt[t]++;
    w->pos += 8 + klen + dlen;
}

static void cdbw_finish(struct cdbw *w)
{
    uint32_t tpos[256], tlen[256];
    int i;
    uint32_t j;

    for (i = 0; i < 256; ++i) {
        struct hentry *slots;
        tlen[i] = w->cnt[i] * 2;
        tpos[i] = w->pos;
        if (tlen[i] == 0)
            continue;
        slots = calloc(tlen[i], sizeof(struct hentry));
        if (slots == NULL) { perror("calloc"); exit(2); }
        for (j = 0; j < w->cnt[i]; ++j) {
            uint32_t s = (w->tbl[i][j].h >> 8) % tlen[i];
            while (slots[s].p != 0)
                s = (s + 1) % tlen[i];
            slots[s] = w->tbl[i][j];
        }
        for (j = 0; j < tlen[i]; ++j) {
            wu32(w->f, slots[j].h);
            wu32(w->f, slots[j].p);
        }
        w->pos += tlen[i] * 8;
        free(slots);
        free(w->tbl[i]);
    }

    fseek(w->f, 0, SEEK_SET);
    for (i = 0; i < 256; ++i) {
        wu32(w->f, tpos[i]);
        wu32(w->f, tlen[i]);
    }
    fclose(w->f);
}

/* --- assertions ------------------------------------------------------------- */

static void ck(const char *desc, int got, int want)
{
    if (got == want) {
        printf("ok   %s (%d)\n", desc, got);
    } else {
        fprintf(stderr, "FAIL %s (got %d, want %d)\n", desc, got, want);
        ++failures;
    }
}

static void ck_str(const char *desc, const char *got, const char *want)
{
    if (strcmp(got, want) == 0) {
        printf("ok   %s (\"%s\")\n", desc, got);
    } else {
        fprintf(stderr, "FAIL %s (got \"%s\", want \"%s\")\n", desc, got, want);
        ++failures;
    }
}

static int ff_find(const char *cdb, const char *key)
{
    return cdb_find(cdb, (const unsigned char *)key, (uint32_t)strlen(key));
}

static void write_file(const char *path, const char *contents)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) { perror(path); exit(2); }
    fputs(contents, f);
    fclose(f);
}

int main(void)
{
    char dir[] = "/tmp/test_fastforward.XXXXXX";
    char cdb[512], cdb_glob[512], qfile[512];
    struct cdbw w;

    if (mkdtemp(dir) == NULL) { perror("mkdtemp"); return 2; }
    snprintf(cdb, sizeof(cdb), "%s/aliases.cdb", dir);
    snprintf(cdb_glob, sizeof(cdb_glob), "%s/global.cdb", dir);
    snprintf(qfile, sizeof(qfile), "%s/.qmail-default", dir);

    /* Fixture mirroring a real newaliases cdb plus host-specific and
     * domain-wildcard entries to exercise every branch of the key sequence. */
    cdbw_begin(&w, cdb);
    cdbw_add(&w, ":postmaster@", "&root@h");          /* :lp@      (any host) */
    cdbw_add(&w, ":abuse@",      "&root@h");
    cdbw_add(&w, ":root@",       "&walled@h");
    cdbw_add(&w, ":sales@example.com", "&team@h");    /* :lp@domain (host-specific) */
    cdbw_add(&w, ":@catchall.example", "&hole@h");    /* :@domain  (domain catch-all) */
    cdbw_finish(&w);

    /* --- cdb_find: exact membership against an independently-built cdb --- */
    ck("cdb_find present :postmaster@",  ff_find(cdb, ":postmaster@"), 1);
    ck("cdb_find present :sales@example.com", ff_find(cdb, ":sales@example.com"), 1);
    ck("cdb_find absent :bogus@",        ff_find(cdb, ":bogus@"), 0);
    ck("cdb_find absent empty-ish",      ff_find(cdb, ":zzz@nope"), 0);
    ck("cdb_find error on missing file", ff_find("/no/such/cdb/here", ":x@"), -1);

    /* --- fastforward_cdb_match: the controlled-wildcard sequence --- */
    ck("known role via :lp@",            fastforward_cdb_match(cdb, "postmaster", "deepsky.com"), 1);
    ck("known role case-folded",         fastforward_cdb_match(cdb, "PostMaster", "deepsky.com"), 1);
    ck("unknown localpart bounces",      fastforward_cdb_match(cdb, "nosuchuser", "deepsky.com"), 0);
    ck("host-specific :lp@domain hit",   fastforward_cdb_match(cdb, "sales", "example.com"), 1);
    ck("host-specific miss on other host", fastforward_cdb_match(cdb, "sales", "other.com"), 0);
    ck("domain catch-all :@domain hit",  fastforward_cdb_match(cdb, "whoever", "catchall.example"), 1);
    ck("domain catch-all miss elsewhere", fastforward_cdb_match(cdb, "whoever", "elsewhere.com"), 0);
    ck("unreadable cdb fails open (-1)", fastforward_cdb_match("/no/such/cdb", "x", "y"), -1);
    ck("NULL domain still matches :lp@", fastforward_cdb_match(cdb, "abuse", NULL), 1);

    /* A bare ":@" is NOT one of fastforward's three targets (user@host, @host,
     * user@), so even if it appears in a cdb it must never match — confirmed
     * against fastforward(1) itself. */
    cdbw_begin(&w, cdb_glob);
    cdbw_add(&w, ":@", "&hole@h");
    cdbw_finish(&w);
    ck("bare :@ is not a target (no match)", fastforward_cdb_match(cdb_glob, "anyone", "any.domain"), 0);

    /* --- fastforward_invocation: dot-qmail parsing --- */
    {
        char got[512];
        int pt;

        pt = -1;
        write_file(qfile, "| fastforward -d /etc/aliases.cdb\n");
        ck("parse -d invocation", fastforward_invocation(qfile, got, sizeof(got), &pt), 1);
        ck_str("  cdb extracted", got, "/etc/aliases.cdb");
        ck("  not pass-through", pt, 0);

        pt = -1;
        write_file(qfile, "| fastforward -p -d /etc/aliases.cdb\n");
        ck("parse -p pass-through", fastforward_invocation(qfile, got, sizeof(got), &pt), 1);
        ck("  pass-through set", pt, 1);

        pt = -1;
        write_file(qfile, "|fastforward /var/x.cdb\n");
        ck("parse no-space, no-flags", fastforward_invocation(qfile, got, sizeof(got), &pt), 1);
        ck_str("  cdb extracted", got, "/var/x.cdb");

        pt = -1;
        write_file(qfile, "| /usr/bin/fastforward -P /e/a.cdb\n");
        ck("parse full path + -P", fastforward_invocation(qfile, got, sizeof(got), &pt), 1);
        ck_str("  basename matched, cdb extracted", got, "/e/a.cdb");
        ck("  -P not pass-through", pt, 0);

        write_file(qfile, "# a comment\n\n| fastforward /after/comment.cdb\n");
        ck("skips comment and blank lines", fastforward_invocation(qfile, got, sizeof(got), NULL), 1);
        ck_str("  cdb after comment", got, "/after/comment.cdb");

        write_file(qfile, "| /home/vpopmail/bin/vdelivermail '' delete\n");
        ck("vdelivermail (quotes) declined", fastforward_invocation(qfile, got, sizeof(got), NULL), 0);

        write_file(qfile, "./Maildir/\n");
        ck("maildir delivery not a program", fastforward_invocation(qfile, got, sizeof(got), NULL), 0);

        write_file(qfile, "| forward someone@example.com\n");
        ck("forward is not fastforward", fastforward_invocation(qfile, got, sizeof(got), NULL), 0);

        write_file(qfile, "| condredirect foo bar\n");
        ck("condredirect is not fastforward", fastforward_invocation(qfile, got, sizeof(got), NULL), 0);
    }

    {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
        if (system(cmd) != 0) { /* best-effort cleanup */ }
    }

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all fastforward/cdb tests passed\n");
    return 0;
}

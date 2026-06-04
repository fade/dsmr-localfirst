/* Unit test for si_qmail_deliverable — must reproduce qmail-local's qmesearch
 * (.qmail-<ext> plus the .qmail-...default catch-all chain) exactly. Builds a
 * fixture home directory with a known set of dot-qmail files so the full
 * deliverability matrix is driven without a live qmail. */
#include "../src/system_identity.h"

#include <stdio.h>
#include <stdlib.h>

static int failures;
static char home[512];

static void touch(const char *name)
{
    char path[1024];
    FILE *f;
    snprintf(path, sizeof(path), "%s/%s", home, name);
    f = fopen(path, "w");
    if (f == NULL) { perror(path); exit(2); }
    fclose(f);
}

static void check(const char *desc, const char *ext, int want)
{
    int got = si_qmail_deliverable(home, ext);
    if (got == want) {
        printf("ok   %s (ext=\"%s\" -> %d)\n", desc, ext ? ext : "(null)", got);
    } else {
        fprintf(stderr, "FAIL %s (ext=\"%s\" -> %d, want %d)\n",
                desc, ext ? ext : "(null)", got, want);
        ++failures;
    }
}

int main(void)
{
    char tmpl[] = "/tmp/test_deliverable.XXXXXX";
    char *d = mkdtemp(tmpl);
    if (d == NULL) { perror("mkdtemp"); return 2; }
    snprintf(home, sizeof(home), "%s", d);

    /* Fixture home: a user with a specific extension file, a nested catch-all,
     * and a bare catch-all. Mirrors a real production .qmail layout. */
    touch(".qmail-twitch");        /* exact extension     */
    touch(".qmail-list-default");  /* nested -default     */
    /* deliberately NO .qmail-default at top level for the first pass */

    /* bare user: always deliverable regardless of files */
    check("bare user (NULL ext)", NULL, 1);
    check("bare user (empty ext)", "", 1);

    /* exact .qmail-<ext> */
    check("exact extension file present", "twitch", 1);
    check("exact extension, case-folded", "Twitch", 1);   /* safeext lowercases */

    /* nested -default catch-all: list-anything -> .qmail-list-default */
    check("nested -default catch-all matches", "list-weekly", 1);
    /* bare "list" has no '-', so the chain only reaches .qmail-default (absent
     * in this pass); .qmail-list-default requires a "list-<something>" ext. */
    check("bare prefix without its own file undeliverable", "list", 0);

    /* unknown extension with no catch-all -> NOT deliverable (qmail bounces) */
    check("unknown extension, no catch-all", "nosuchext", 0);
    check("unknown nested extension, no matching prefix", "other-thing", 0);

    /* dot in extension translates to ':' for the filename */
    touch(".qmail-a:b");
    check("dotted extension via :-translation", "a.b", 1);

    /* fail-open: a home the validator cannot search (here a nonexistent path,
     * which access() rejects for every uid including root) must be accepted,
     * deferring the deliver/bounce decision to qmail-local. This is the mode-700
     * private-home case the smtpd-user validator hits in production. */
    if (si_qmail_deliverable("/no/such/home/here", "sometag") == 1)
        printf("ok   fail-open when home unsearchable\n");
    else { fprintf(stderr, "FAIL fail-open when home unsearchable\n"); ++failures; }

    /* now add a top-level .qmail-default: everything becomes deliverable */
    touch(".qmail-default");
    check("top-level .qmail-default catches unknown", "anything-at-all", 1);
    check("top-level .qmail-default catches single", "zzz", 1);

    /* cleanup */
    {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", home);
        if (system(cmd) != 0) { /* best-effort */ }
    }

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all deliverable tests passed\n");
    return 0;
}

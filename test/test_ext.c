/* Unit test for si_qmail_ext — must reproduce qmail-local's extension→filename
 * translation exactly: lowercase, '.'->':', hyphens preserved. */
#include "../src/system_identity.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(const char *in, const char *want)
{
    char out[256];
    if (si_qmail_ext(in, out, sizeof(out)) != 0) {
        fprintf(stderr, "FAIL si_qmail_ext(\"%s\"): returned error\n", in);
        ++failures;
        return;
    }
    if (strcmp(out, want) != 0) {
        fprintf(stderr, "FAIL si_qmail_ext(\"%s\"): got \"%s\" want \"%s\"\n",
                in, out, want);
        ++failures;
        return;
    }
    printf("ok   si_qmail_ext(\"%s\") = \"%s\"\n", in, out);
}

int main(void)
{
    char out[4];

    check("root", "root");
    check("Root", "root");                 /* lowercased */
    check("POSTMASTER", "postmaster");
    check("mailer-daemon", "mailer-daemon"); /* hyphen preserved */
    check("mary.jones", "mary:jones");       /* dot -> colon */
    check("A.B-C.d", "a:b-c:d");             /* mixed */
    check("user+ext", "user+ext");           /* plus preserved */

    /* capacity: "abcd" needs 5 bytes, buffer holds 4 -> must fail cleanly */
    if (si_qmail_ext("abcd", out, sizeof(out)) == 0) {
        fprintf(stderr, "FAIL si_qmail_ext capacity check did not trip\n");
        ++failures;
    } else {
        printf("ok   si_qmail_ext capacity overflow rejected\n");
    }

    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("all ext tests passed\n");
    return 0;
}

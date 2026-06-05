/*
 * system-identity — CLI front end to the shared eligibility predicate.
 *
 * Usage: system-identity LOCALPART [DOMAIN]
 *   exit 0  and print LOCALPART on stdout  if L is a mail-eligible system
 *           identity (the re-injection local-part the dispatcher should use);
 *   exit 1  if L is not a system identity (resolution falls through to vpopmail);
 *   exit 2  on usage error.
 *
 * DOMAIN is optional and is consulted only when ~alias/.qmail-default is a
 * `| fastforward <cdb>` catch-all, where it is the recipient host the local-part
 * is validated against; omit it to probe with the host-wildcard keys only.
 *
 * The matched clause (passwd|alias) is printed on stderr for diagnostics.
 * This is the same predicate the dispatcher and RCPTCHECK validator use, so it
 * doubles as the canonical probe when debugging routing on a host.
 */
#include "system_identity.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    const char *domain;

    if (argc < 2 || argc > 3 || argv[1][0] == '\0') {
        fprintf(stderr, "usage: system-identity LOCALPART [DOMAIN]\n");
        return 2;
    }
    domain = (argc == 3) ? argv[2] : NULL;

    switch (system_identity(argv[1], domain)) {
    case SI_PASSWD:
        fprintf(stderr, "system-identity: %s -> passwd (/home account)\n", argv[1]);
        printf("%s\n", argv[1]);
        return 0;
    case SI_ALIAS:
        fprintf(stderr, "system-identity: %s -> alias (~alias/.qmail)\n", argv[1]);
        printf("%s\n", argv[1]);
        return 0;
    case SI_NONE:
    default:
        fprintf(stderr, "system-identity: %s -> vpopmail (no system identity)\n", argv[1]);
        return 1;
    }
}

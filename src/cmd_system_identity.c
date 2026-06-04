/*
 * system-identity — CLI front end to the shared eligibility predicate.
 *
 * Usage: system-identity LOCALPART
 *   exit 0  and print LOCALPART on stdout  if L is a mail-eligible system
 *           identity (the re-injection local-part the dispatcher should use);
 *   exit 1  if L is not a system identity (resolution falls through to vpopmail);
 *   exit 2  on usage error.
 *
 * The matched clause (passwd|alias) is printed on stderr for diagnostics.
 * This is the same predicate the dispatcher and RCPTCHECK validator use, so it
 * doubles as the canonical probe when debugging routing on a host.
 */
#include "system_identity.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1][0] == '\0') {
        fprintf(stderr, "usage: system-identity LOCALPART\n");
        return 2;
    }

    switch (system_identity(argv[1])) {
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

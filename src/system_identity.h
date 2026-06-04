/*
 * system_identity — the shared eligibility predicate for hybrid
 * system/vpopmail mail domains.
 *
 * A local-part L is a "mail-eligible system identity" iff EITHER
 *   (clause 1) getpwnam(L) resolves to an account whose home is under /home/,
 *   (clause 2) ~alias/.qmail-<translate(L)> exists.
 * Otherwise L is not a system identity and resolution falls through to vpopmail.
 *
 * This is the single source of truth used by BOTH the delivery dispatcher and
 * the SMTP-time RCPTCHECK validator so the two paths can never disagree.
 */
#ifndef SYSTEM_IDENTITY_H
#define SYSTEM_IDENTITY_H

#include <stddef.h>

typedef enum {
    SI_NONE  = 0,  /* not a system identity — fall through to vpopmail */
    SI_PASSWD,     /* clause 1: /home account                          */
    SI_ALIAS       /* clause 2: ~alias/.qmail-L                        */
} si_result;

/*
 * Translate a local-part into the extension form qmail-local uses for its
 * .qmail filenames: lowercase, and every '.' becomes ':'. Hyphens are kept.
 * Writes a NUL-terminated result into out (capacity n). Returns 0 on success,
 * -1 if the result would not fit.
 */
int si_qmail_ext(const char *localpart, char *out, size_t n);

/*
 * Evaluate the eligibility predicate for `localpart`.
 * Returns SI_PASSWD, SI_ALIAS, or SI_NONE.
 */
si_result system_identity(const char *localpart);

#endif /* SYSTEM_IDENTITY_H */

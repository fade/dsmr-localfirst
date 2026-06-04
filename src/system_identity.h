/*
 * system_identity — the shared eligibility predicate for hybrid
 * system/vpopmail mail domains.
 *
 * A local-part L is a "mail-eligible system identity" iff qmail itself would
 * deliver it locally (rather than bounce), restricted to /home accounts and the
 * alias user. The resolution faithfully follows qmail's own address handling:
 *
 *   (clause 1) qmail-getpw user resolution: the longest dash-delimited prefix of
 *              L that names a real /home account (uid != 0) is the controlling
 *              user, the remainder its qmail extension. A bare user is always
 *              deliverable; an extension is deliverable only when a matching
 *              .qmail-<ext> or .qmail-…default catch-all exists (qmail-local).
 *   (clause 2) the qmail-getpw alias fallback: an unresolved L is deliverable
 *              iff ~alias/.qmail-<translate(L)> or a -default catch-all exists.
 *
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
 * Would qmail-local deliver (not bounce) a recipient whose controlling user has
 * home `homedir` and RAW qmail extension `ext`? Reproduces qmail-local's
 * qmesearch: a non-empty extension is deliverable iff `.qmail-<safeext>` or one
 * of the `.qmail-…default` catch-alls (down to `.qmail-default`) exists as a
 * regular file; a bare extension (NULL/"") is always deliverable. Returns 1 if
 * deliverable, 0 otherwise. Exposed for unit testing against fixture homes.
 *
 * Fails open: if `homedir` cannot be searched (a mode-700 private home, since
 * the validator runs as the unprivileged smtpd user), returns 1 so a legitimate
 * tagged address is not rejected on a permission error — qmail-local, running as
 * the user, makes the real deliver/bounce decision.
 */
int si_qmail_deliverable(const char *homedir, const char *ext);

/*
 * Evaluate the eligibility predicate for `localpart`.
 * Returns SI_PASSWD, SI_ALIAS, or SI_NONE.
 */
si_result system_identity(const char *localpart);

#endif /* SYSTEM_IDENTITY_H */

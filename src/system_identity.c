#include "system_identity.h"

#include <ctype.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

/* Homes under this prefix denote real human/shell accounts. Service accounts
 * (bin, daemon, www-data, …) live elsewhere and are deliberately excluded, so
 * a virtual recipient that merely collides with a service login is NOT treated
 * as a system identity. The alias user's home (/var/lib/qmail/alias) is also
 * outside /home/, so it is reachable only via clause 2. */
#define HOME_PREFIX "/home/"

int si_qmail_ext(const char *localpart, char *out, size_t n)
{
    size_t i;
    size_t len = strlen(localpart);

    if (len + 1 > n)
        return -1;

    for (i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)localpart[i];
        if (c == '.')
            c = ':';
        else
            c = (unsigned char)tolower(c);
        out[i] = (char)c;
    }
    out[len] = '\0';
    return 0;
}

/* A local-part is only ever a single address component here. Reject anything
 * that could escape into a path, confuse downstream address splitting, or is
 * empty — defence in depth for clause 2's filename construction and clause 1's
 * getpwnam. '@' is rejected because a local-part containing it cannot name a
 * system account and would be mis-split by tools that parse on the first '@'. */
static int localpart_sane(const char *localpart)
{
    if (localpart == NULL || localpart[0] == '\0')
        return 0;
    if (strchr(localpart, '/') != NULL)
        return 0;
    if (strchr(localpart, '@') != NULL)
        return 0;
    if (strcmp(localpart, ".") == 0 || strcmp(localpart, "..") == 0)
        return 0;
    return 1;
}

static int home_under_home(const char *dir)
{
    return dir != NULL && strncmp(dir, HOME_PREFIX, sizeof(HOME_PREFIX) - 1) == 0;
}

/* clause 2: does ~alias/.qmail-<translate(localpart)> exist? */
static int alias_qmail_exists(const char *localpart)
{
    struct passwd *pw;
    char ext[256];
    char path[1024];
    int written;

    pw = getpwnam("alias");
    if (pw == NULL || pw->pw_dir == NULL)
        return 0;

    if (si_qmail_ext(localpart, ext, sizeof(ext)) != 0)
        return 0;

    written = snprintf(path, sizeof(path), "%s/.qmail-%s", pw->pw_dir, ext);
    if (written < 0 || (size_t)written >= sizeof(path))
        return 0;

    return access(path, F_OK) == 0;
}

si_result system_identity(const char *localpart)
{
    struct passwd *pw;
    char lower[256];
    size_t i, len;

    if (!localpart_sane(localpart))
        return SI_NONE;

    /* clause 1: real /home account. qmail-getpw lowercases the local-part
     * before getpwnam (qmail-getpw.c), so a mixed-case recipient like
     * "Fade" is delivered to account "fade"; lowercase here too or the
     * SMTP-time check and delivery-time routing would disagree. */
    len = strlen(localpart);
    if (len + 1 <= sizeof(lower)) {
        for (i = 0; i < len; ++i)
            lower[i] = (char)tolower((unsigned char)localpart[i]);
        lower[len] = '\0';
        pw = getpwnam(lower);
        if (pw != NULL && home_under_home(pw->pw_dir))
            return SI_PASSWD;
    }

    /* clause 2: alias-configured system identity */
    if (alias_qmail_exists(localpart))
        return SI_ALIAS;

    return SI_NONE;
}

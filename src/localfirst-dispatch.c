/*
 * localfirst-dispatch — delivery-time dispatcher for a hybrid system/vpopmail
 * domain. It replaces the vpopmail domain's catch-all
 *   .qmail-default:  | /home/vpopmail/bin/vdelivermail '' delete
 * with
 *   .qmail-default:  | /usr/libexec/dsmr-localfirst/localfirst-dispatch HOST
 *
 * For the recipient local-part (qmail's $DEFAULT, else $EXT), if it is a
 * mail-eligible system identity (SPEC §3) the message is re-injected to
 * <local-part>@HOST — a locals domain — via qmail's `forward`, so qmail-send
 * delivers it to the system account with correct ownership. Otherwise the
 * original vpopmail catch-all (vdelivermail '' delete) is exec'd unchanged.
 *
 * HOST is the locals host domain to re-inject to (e.g. hoth.example.org).
 * It is taken from argv[1]; if omitted, from control/me. It MUST differ from
 * the vpopmail virtual domain so re-injection does not loop back here (qmail's
 * Delivered-To loop guard is a backstop, not the primary defence).
 *
 * This program runs as the vpopmail user. It deliberately does NOT touch any
 * recipient's ~/Maildir: it cannot create a file owned by the target user.
 * Maildir creation (normal path: /etc/skel at account creation; fallback:
 * delivery-time) belongs to the delivery step that runs as the target user.
 */
#include "system_identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Production paths. Overridable at compile time (-D...) for hermetic tests;
 * never via the environment. */
#ifndef FORWARD
#define FORWARD     "/var/qmail/bin/forward"
#endif
#ifndef VDELIVERMAIL
#define VDELIVERMAIL "/home/vpopmail/bin/vdelivermail"
#endif
#ifndef CONTROL_ME
#define CONTROL_ME  "/var/qmail/control/me"
#endif

/* qmail soft-failure exit: the message is queued and retried later. Any exec
 * failure here is a host/config problem, not a permanent property of the mail,
 * so temporary failure is the correct disposition. */
#define EXIT_TEMP 111

static void exec_vpopmail(void)
{
    char *args[] = { (char *)VDELIVERMAIL, (char *)"", (char *)"delete", NULL };
    execv(VDELIVERMAIL, args);
    fprintf(stderr, "localfirst-dispatch: exec %s failed\n", VDELIVERMAIL);
    _exit(EXIT_TEMP);
}

/* Read control/me into buf (NUL-terminated, trailing newline stripped). */
static int read_control_me(char *buf, size_t n)
{
    FILE *f = fopen(CONTROL_ME, "r");
    size_t len;
    if (f == NULL)
        return -1;
    if (fgets(buf, (int)n, f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);
    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return len > 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *localpart;
    char host[256];
    char reinject[512];
    int written;

    /* Recipient local-part: qmail's $DEFAULT for a -default catch-all, with
     * $EXT as the fallback. */
    localpart = getenv("DEFAULT");
    if (localpart == NULL || localpart[0] == '\0')
        localpart = getenv("EXT");
    if (localpart == NULL || localpart[0] == '\0') {
        fprintf(stderr, "localfirst-dispatch: neither DEFAULT nor EXT set\n");
        _exit(EXIT_TEMP);
    }

    /* Re-injection host: argv[1] wins, else control/me. */
    if (argc >= 2 && argv[1][0] != '\0') {
        if (strlen(argv[1]) + 1 > sizeof(host)) {
            fprintf(stderr, "localfirst-dispatch: HOST too long\n");
            _exit(EXIT_TEMP);
        }
        strcpy(host, argv[1]);
    } else if (read_control_me(host, sizeof(host)) != 0) {
        fprintf(stderr, "localfirst-dispatch: no HOST arg and cannot read %s\n",
                CONTROL_ME);
        _exit(EXIT_TEMP);
    }

    if (system_identity(localpart, host) == SI_NONE)
        exec_vpopmail();   /* not a system identity — vpopmail path, unchanged */

    /* System identity: re-inject to <local-part>@HOST via forward. */
    written = snprintf(reinject, sizeof(reinject), "%s@%s", localpart, host);
    if (written < 0 || (size_t)written >= sizeof(reinject)) {
        fprintf(stderr, "localfirst-dispatch: re-injection address too long\n");
        _exit(EXIT_TEMP);
    }

    {
        char *args[] = { (char *)"forward", reinject, NULL };
        execv(FORWARD, args);
    }
    fprintf(stderr, "localfirst-dispatch: exec %s failed\n", FORWARD);
    _exit(EXIT_TEMP);

    return EXIT_TEMP;  /* not reached */
}

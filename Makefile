# dsmr-localfirst — system-first recipient routing for hybrid system/vpopmail domains.
#
# Three programs share one implementation of the eligibility predicate
# (system_identity.o) so the delivery and SMTP-validation paths can never
# disagree. The vpopmail recipient-existence lookup used by the validator is
# resolved at run time (it is optional: system-delivery-only hosts have no
# vpopmail), so the core links against nothing but libc.

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra
CPPFLAGS ?=
LDFLAGS ?=

# Install layout. qmail-invoked helpers live beside qmail's own binaries
# (PREFIX=/var/qmail, the stack convention); the admin diagnostic goes on the
# system admin PATH.
PREFIX   ?= /var/qmail
QMAILBIN ?= $(PREFIX)/bin
SBINDIR  ?= /usr/sbin
MANDIR   ?= /usr/share/man/man8
DESTDIR  ?=

PROGS = system-identity localfirst-dispatch localfirst-rcptcheck

OBJS_COMMON = src/system_identity.o

.PHONY: all clean test install
all: $(PROGS)

src/%.o: src/%.c src/system_identity.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

system-identity: src/cmd_system_identity.o $(OBJS_COMMON)
	$(CC) $(LDFLAGS) -o $@ $^

localfirst-dispatch: src/localfirst-dispatch.o $(OBJS_COMMON)
	$(CC) $(LDFLAGS) -o $@ $^

localfirst-rcptcheck: src/localfirst-rcptcheck.o $(OBJS_COMMON)
	$(CC) $(LDFLAGS) -o $@ $^

test: all
	./test/test_system_identity.sh
	./test/test_rcptcheck.sh
	./test/test_dispatch.sh

install: all
	install -D -m 0755 localfirst-rcptcheck $(DESTDIR)$(QMAILBIN)/localfirst-rcptcheck
	install -D -m 0755 localfirst-dispatch  $(DESTDIR)$(QMAILBIN)/localfirst-dispatch
	install -D -m 0755 system-identity      $(DESTDIR)$(SBINDIR)/system-identity
	install -D -m 0755 scripts/localfirst-backend-monitor $(DESTDIR)$(SBINDIR)/localfirst-backend-monitor
	install -D -m 0644 cron.d/dsmr-localfirst $(DESTDIR)/etc/cron.d/dsmr-localfirst
	install -D -m 0644 man/localfirst-rcptcheck.8 $(DESTDIR)$(MANDIR)/localfirst-rcptcheck.8
	install -D -m 0644 man/localfirst-dispatch.8  $(DESTDIR)$(MANDIR)/localfirst-dispatch.8
	install -D -m 0644 man/system-identity.8      $(DESTDIR)$(MANDIR)/system-identity.8
	install -D -m 0644 man/localfirst-backend-monitor.8 $(DESTDIR)$(MANDIR)/localfirst-backend-monitor.8

clean:
	rm -f $(PROGS) src/*.o test/test_ext

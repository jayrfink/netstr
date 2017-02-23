# CONFIGURE THESE AS NEEDED:
MANPREFIX=/usr/local/share/man/man1
BINDIR=/usr/local/bin

CC=gcc
JUNK=a.out
BINS=netstr
PCAP_PROGS=passive.c tcpdump.c arpsniff.c decode.c 
SCAN_PROGS=scan.c scan6.c udpscan.c
SRCS=utils.c ipv4_conn.c
LIBS="-lpcap"

all: objs 

NetBSD netbsd: 
	make objs DEFINES=-DNETBSD

OpenBSD openbsd: 
	make objs DEFINES=-DOPENBSD

FreeBSD freebsd:
	make objs DEFINES=-DFREEBSD

Darwin osx darwin:
	make objs DEFINES=-DDARWIN

Linux linux:
	make objs DEFINES=-DLINUX

netbsd-scan:
	make scanobjs DEFINES=-DNETBSD 

openbsd-scan:
	make scanobjs DEFINES=-DOPENBSD 

freebsd-scan:
	make scanobjs DEFINES=-DFREEBSD

osx-scan darwin-scan:
	make scanobjs DEFINES=-DDARWIN 

linux-scan:
	make scanobjs DEFINES=-DLINUX

objs: ${BINS}

scan: 
	make scanobjs 

scanobjs:
	$(CC)  -O2 $(DEFINES) -DSCAN netstr.c $(SCAN_PROGS) $(SRCS) -o netstr

netstr:
	$(CC)  -O3 $(DEFINES) $@.c $(SCAN_PROGS) $(PCAP_PROGS) $(SRCS) $(LIBS) -o $@

clean:
	rm -f ${JUNK} ${BINS} 

install: install-bin install-man

install-bin:
	for i in $(BINS) ; do \
		cp $$i $(BINDIR); \
	done

install-man:
	for i in $(BINS) ; do \
		cp $$i.1 $(MANPREFIXDIR)/$$i.1; \
	done

uninstall: uninstall-bin uninstall-man

uninstall-bin:
	for i in $(BINS) ; do \
		rm -f ${BINDIR}/$$i; \
	done

uninstall-man:
	for i in $(BINS) ; do \
		rm -f $(MANPREFIXDIR)/$$i.1; \
	done


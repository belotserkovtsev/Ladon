/**
 * Ladon unbound dynlib module (OPNsense / FreeBSD).
 *
 * Native (.so) module that coexists with the DNSBL python module in one chain
 * (module-config: "python dynlib iterator"). On every reply it emits the
 * observed domain, client and resolved A addresses to ladon's unix socket:
 *   <domain>\t<client>\t<ip1,ip2,...>\n
 * ladon's unbound mediator (internal/dnssrc) reads that socket. The module
 * never blocks or rewrites answers; it only observes.
 *
 * Why dynlib and not a 2nd python module: stock unbound runs only ONE python
 * module instance, so a second python (alongside OPNsense's DNSBL) never gets
 * operate(). dynlib is a separate module type and composes cleanly.
 *
 * BUILD (on a FreeBSD box with base clang; validated on OPNsense 26.1 /
 * unbound 1.24.2): fetch the MATCHING unbound source, ./configure with the same
 * ABI-affecting flags as the running unbound (see `unbound -V`), then:
 *   cp ladon-unbound.c unbound-<ver>/dynlibmod/examples/ladon.c
 *   cd unbound-<ver>/dynlibmod/examples
 *   cc -I../.. -shared -Wall -fpic -o ladon.so ladon.c
 * Do NOT include util/netevent.h (pulls dnscrypt->sodium.h); that is why the
 * client IP is a placeholder for now (real per-client attribution: TODO).
 *
 * UNBOUND CONFIG to load it (custom options):
 *   module-config: "python dynlib iterator"   # python = OPNsense DNSBL
 *   dynlib:
 *       dynlib-file: "/usr/local/lib/ladon/ladon.so"
 */
#include "../../config.h"
#include "../../util/module.h"
#include "../../util/data/msgreply.h"
#include "../../util/data/packed_rrset.h"
#include "../../util/data/dname.h"
#include "../../sldns/rrdef.h"
#include "../dynlibmod.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_WINDOWS_H
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

static const char* LADON_SOCK = "/var/run/ladon-dns.sock";
static int ladon_fd = -1;

static void ladon_connect(void) {
	struct sockaddr_un sa;
	int fd;
	if (ladon_fd >= 0) return;
	/* Non-blocking: a stuck ladon reader must never stall unbound's worker. */
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) return;
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, LADON_SOCK, sizeof(sa.sun_path) - 1);
	if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
		close(fd);
		return;
	}
	ladon_fd = fd;
}

static void ladon_emit(const char* line, size_t len) {
	ladon_connect();
	if (ladon_fd < 0) return;
	if (write(ladon_fd, line, len) < 0) {
		/* Backpressured (ladon slow/stuck): drop this observation rather than
		 * ever blocking unbound. Only a real socket error tears down the fd. */
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
		close(ladon_fd);
		ladon_fd = -1;
	}
}

/* Forward declare the reply callback. */
int reply_callback(struct query_info* qinfo,
	struct module_qstate* qstate, struct reply_info* rep, int rcode,
	struct edns_data* edns, struct edns_option** opt_list_out,
	struct comm_reply* repinfo, struct regional* region,
	struct timeval* start_time, int id, void* callback);

EXPORT int init(struct module_env* env, int id) {
	struct dynlibmod_env* de = (struct dynlibmod_env*) env->modinfo[id];
	log_info("ladon dynlib: init");
	de->inplace_cb_register_wrapped(&reply_callback, inplace_cb_reply, NULL, env, id);
	de->dyn_env = NULL;
	return 1;
}

EXPORT void deinit(struct module_env* env, int id) {
	struct dynlibmod_env* de = (struct dynlibmod_env*) env->modinfo[id];
	de->inplace_cb_delete_wrapped(env, inplace_cb_reply, id);
	if (ladon_fd >= 0) { close(ladon_fd); ladon_fd = -1; }
}

EXPORT void operate(struct module_qstate* qstate, enum module_ev event,
		int id, struct outbound_entry* entry) {
	(void)entry;
	if (event == module_event_new || event == module_event_pass) {
		qstate->ext_state[id] = module_wait_module;
	} else if (event == module_event_moddone) {
		qstate->ext_state[id] = module_finished;
	} else {
		qstate->ext_state[id] = module_error;
	}
}

EXPORT void inform_super(struct module_qstate* qstate, int id,
		struct module_qstate* super) {
	(void)qstate; (void)id; (void)super;
}

EXPORT void clear(struct module_qstate* qstate, int id) {
	(void)qstate; (void)id;
}

EXPORT size_t get_mem(struct module_env* env, int id) {
	(void)env; (void)id;
	return 0;
}

int reply_callback(struct query_info* qinfo,
	struct module_qstate* qstate, struct reply_info* rep, int rcode,
	struct edns_data* edns, struct edns_option** opt_list_out,
	struct comm_reply* repinfo, struct regional* region,
	struct timeval* start_time, int id, void* callback) {
	char dname[LDNS_MAX_DOMAINLEN + 1];
	char client[128];
	char ips[1024];
	char line[1400];
	size_t i, j, ipoff = 0;
	int ln;
	(void)qstate; (void)rcode; (void)edns; (void)opt_list_out;
	(void)repinfo; (void)region; (void)start_time; (void)id; (void)callback;

	if (!qinfo || !rep) return 0;

	dname_str(qinfo->qname, dname);

	/* repinfo->client_addr lives in struct comm_reply (util/netevent.h), which
	 * drags in dnscrypt/sodium build headers; not worth it just for the client
	 * IP. Use a fixed non-ignored peer — discovery only needs a stable marker.
	 * Real per-client attribution can be added later. */
	strncpy(client, "127.0.0.1", sizeof(client) - 1);
	client[sizeof(client) - 1] = 0;

	ips[0] = 0;
	for (i = 0; i < rep->an_numrrsets; i++) {
		struct ub_packed_rrset_key* k = rep->rrsets[i];
		struct packed_rrset_data* d;
		if (ntohs(k->rk.type) != LDNS_RR_TYPE_A) continue;
		d = (struct packed_rrset_data*)k->entry.data;
		for (j = 0; j < d->count; j++) {
			uint8_t* rd = d->rr_data[j];
			char ipbuf[16];
			int w;
			if (d->rr_len[j] < 6) continue; /* 2-byte rdlen + 4-byte A */
			snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
				rd[2], rd[3], rd[4], rd[5]);
			w = snprintf(ips + ipoff, sizeof(ips) - ipoff, "%s%s",
				ipoff ? "," : "", ipbuf);
			if (w > 0 && (size_t)w < sizeof(ips) - ipoff) ipoff += w;
		}
	}

	ln = snprintf(line, sizeof(line), "%s\t%s\t%s\n", dname, client, ips);
	if (ln > 0) ladon_emit(line, (size_t)ln);
	return 0;
}

/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 *
 * Scrapeable OpenMetrics metrics (compatible with Prometheus)
 *
 * https://tools.ietf.org/html/draft-richih-opsawg-openmetrics-00
 *
 * This plugin exports metrics via http listen socket on the vhost.
 *
 * Openmetrics supports a "metric" at the top of its report that describes the
 * source aka "target metadata".
 *
 * Since we want to enable collection from devices that are not externally
 * reachable, we must provide a reachable server that the clients can attach to
 * and have their stats aggregated and then read by Prometheus or whatever.
 * Openmetrics says that it wants to present the aggregated stats in a flat
 * summary with only the aggregator's "target metadata" and contributor targets
 * getting their data tagged with the source
 *
 * "The above discussion is in the context of individual exposers.  An
 *  exposition from a general purpose monitoring system may contain
 *  metrics from many individual targets, and thus may expose multiple
 *  target info Metrics.  The metrics may already have had target
 *  metadata added to them as labels as part of ingestion.  The metric
 *  names MUST NOT be varied based on target metadata.  For example it
 *  would be incorrect for all metrics to end up being prefixed with
 *  staging_ even if they all originated from targets in a staging
 *  environment)."
 */

#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

struct pss {
	struct lwsac *ac;	/* the translated metrics, one ac per line */
	struct lwsac *walk;	/* iterator for ac when writing */
	size_t tot;		/* content-length computation */
};

static void
prometheus_san(char *nm, size_t nl)
{
	size_t m;

	/* Prometheus has a very restricted token charset */

	for (m = 0; m < nl; m++)
		if ((nm[m] < 'A' || nm[m] > 'Z') &&
		    (nm[m] < 'a' || nm[m] > 'z') &&
		    (nm[m] < '0' || nm[m] > '9') &&
		    nm[m] != '_')
			nm[m] = '_';
}

static int
lws_metrics_om_format_agg(lws_metric_pub_t *pub, const char *nm, lws_usec_t now,
			  int gng, char *buf, size_t len)
{
	const char *_gng = gng ? "_nogo" : "_go";
	char *end = buf + len - 1, *obuf = buf;

	if (pub->flags & LWSMTFL_REPORT_ONLY_GO)
		_gng = "";

	if (!(pub->flags & LWSMTFL_REPORT_MEAN)) {
		/* only the sum is meaningful */
		if (pub->flags & LWSMTFL_REPORT_DUTY_WALLCLOCK_US) {
			buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf),
				"%s_count %u\n"
				"%s_us_sum %llu\n"
				"%s_created %lu.%06u\n",
				nm, (unsigned int)pub->u.agg.count[gng],
				nm, (unsigned long long)pub->u.agg.sum[gng],
				nm, (unsigned long)(pub->us_first / 1000000),
				    (unsigned int)(pub->us_first % 1000000));

			return lws_ptr_diff(buf, obuf);
		}

		/* it's a monotonic ordinal, like total tx */
		buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf),
				    "%s%s_count %u\n"
				    "%s%s_sum %llu\n",
				    nm, _gng,
				    (unsigned int)pub->u.agg.count[gng],
				    nm, _gng,
				    (unsigned long long)pub->u.agg.sum[gng]);

	} else
		buf += lws_snprintf(buf, lws_ptr_diff_size_t(end, buf),
				    "%s%s_count %u\n"
				    "%s%s_mean %llu\n",
				    nm, _gng,
				    (unsigned int)pub->u.agg.count[gng],
				    nm, _gng, (unsigned long long)
				    (pub->u.agg.count[gng] ?
						pub->u.agg.sum[gng] /
						pub->u.agg.count[gng] : 0));

	return lws_ptr_diff(buf, obuf);
}

static int
lws_metrics_om_ac_stash(struct pss *pss, char *buf, size_t len)
{
	char *q;

	buf[0] = (char)((len >> 8) & 0xff);
	buf[1] = (char)(len & 0xff);

	q = lwsac_use(&pss->ac, LWS_PRE + len + 2, LWS_PRE + len + 2);
	if (!q) {
		lwsac_free(&pss->ac);

		return -1;
	}
	memcpy(q + LWS_PRE, buf, len + 2);
	pss->tot += len;

	return 0;
}

/*
 * We have to do the ac listing at this level, because there can be too large
 * a number to metrics tags to iterate that can fit in a reasonable buffer.
 */

static int
lws_metrics_om_format(struct pss *pss, lws_metric_pub_t *pub, const char *nm)
{
	char buf[1200], *p = buf + 2, *end = buf + sizeof(buf) - 3, tmp[512];
	lws_usec_t t = lws_now_usecs();

	if (pub->flags & LWSMTFL_REPORT_HIST) {
		lws_metric_bucket_t *buck = pub->u.hist.head;

		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  "%s_count %llu\n",
				  nm, (unsigned long long)
				  pub->u.hist.total_count);

		while (buck) {
			lws_strncpy(tmp, lws_metric_bucket_name(buck),
				    sizeof(tmp));

			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "%s{%s} %llu\n", nm, tmp,
					  (unsigned long long)buck->count);

			lws_metrics_om_ac_stash(pss, buf,
						lws_ptr_diff_size_t(p, buf + 2));
			p = buf + 2;

			buck = buck->next;
		}

		goto happy;
	}

	if (!pub->u.agg.count[METRES_GO] && !pub->u.agg.count[METRES_NOGO])
		return 0;

	if (pub->u.agg.count[METRES_GO])
		p += lws_metrics_om_format_agg(pub, nm, t, METRES_GO, p,
					       lws_ptr_diff_size_t(end, p));

	if (!(pub->flags & LWSMTFL_REPORT_ONLY_GO) &&
	    pub->u.agg.count[METRES_NOGO])
		p += lws_metrics_om_format_agg(pub, nm, t, METRES_NOGO, p,
					       lws_ptr_diff_size_t(end, p));

	if (pub->flags & LWSMTFL_REPORT_MEAN)
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  "%s_min %llu\n"
				  "%s_max %llu\n",
				  nm, (unsigned long long)pub->u.agg.min,
				  nm, (unsigned long long)pub->u.agg.max);

happy:
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "\n");

	return lws_metrics_om_ac_stash(pss, buf,
				       lws_ptr_diff_size_t(p, buf + 2));
}

static int
append_om_metric(lws_metric_pub_t *pub, void *user)
{
	struct pss *pss = (struct pss *)user;
	char nm[64];
	size_t nl;

	/*
	 * Convert lws_metrics to prometheus metrics data, stashing into an
	 * lwsac without backfill.  Since it's not backfilling, use areas are in
	 * linear sequence simplifying walking them.  Limiting the lwsac alloc
	 * to less than a typical mtu means we can write one per write
	 * efficiently
	 */

	lws_strncpy(nm, pub->name, sizeof(nm));
	nl = strlen(nm);

	prometheus_san(nm, nl);

	return lws_metrics_om_format(pss, pub, nm);
}

#if defined(__linux__)
static int
grabfile(const char *fi, char *buf, size_t len)
{
	int n, fd = lws_open(fi, LWS_O_RDONLY);

	buf[0] = '\0';
	if (fd < 0)
		return -1;

	n = (int)read(fd, buf, len - 1);
	close(fd);
	if (n < 0) {
		buf[0] = '\0';
		return -1;
	}

	buf[n] = '\0';
	if (n > 0 && buf[n - 1] == '\n')
		buf[--n] = '\0';

	return n;
}
#endif

int
ome_prepare(struct lws_context *ctx, struct pss *pss)
{
	char buf[1224], *start = buf + LWS_PRE, *p = start,
	     *end = buf + sizeof(buf) - 1;
	char hn[64];

	pss->tot = 0;

	/*
	 * Target metadata
	 */

	hn[0] = '\0';
	gethostname(hn, sizeof(hn) - 1);
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "# TYPE target info\n"
			  "# HELP target Target metadata\n"
			  "target_info{hostname=\"%s\"", hn);

#if defined(__linux__)
	if (grabfile("/proc/self/cmdline", hn, sizeof(hn)))
		p += lws_snprintf((char *)p, lws_ptr_diff_size_t(end, p),
				  ",cmdline=\"%s\"", hn);
#endif

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "} 1\n\n");

	if (lws_metrics_om_ac_stash(pss, (char *)buf + LWS_PRE - 2,
				    lws_ptr_diff_size_t(p, buf + LWS_PRE)))
		return 1;

	/* lws version */

	p = start;
	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "# TYPE lws_info info\n"
			  "# HELP lws_info Version of lws producing this\n"
			  "lws_info{version=\"%s\"}\n", LWS_BUILD_HASH);
	if (lws_metrics_om_ac_stash(pss, (char *)buf + LWS_PRE - 2,
				    lws_ptr_diff_size_t(p, buf + LWS_PRE)))
		return 1;

	/* system scalars */

#if defined(__linux__)
	if (grabfile("/proc/loadavg", hn, sizeof(hn))) {
		char *sp = strchr(hn, ' ');
		if (sp) {
			p = start;
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "load_1m=\"%.*s\"\n",
					  lws_ptr_diff(sp, hn), hn);
			if (lws_metrics_om_ac_stash(pss,
						    (char *)buf + LWS_PRE - 2,
						    lws_ptr_diff_size_t(p,
								buf + LWS_PRE)))
				return 1;
		}
	}
#endif

	if (lws_metrics_foreach(ctx, pss, append_om_metric))
		return 1;

	pss->walk = pss->ac;

	return 0;
}

static int
callback_lws_openmetrics_export(struct lws *wsi,
				enum lws_callback_reasons reason,
				void *user, void *in, size_t len)
{
	unsigned char buf[1224], *start = buf + LWS_PRE, *p = start,
		      *end = buf + sizeof(buf) - 1, *ip;
	struct lws_context *ctx = lws_get_context(wsi);
	struct pss *pss = (struct pss *)user;
	unsigned int m, wm;

	switch (reason) {

	case LWS_CALLBACK_HTTP:
		/*
		 * Let's pregenerate the output into an lwsac all at once and
		 * then spool it back to the peer afterwards
		 *
		 * - there's not going to be that much of it (a few kB)
		 * - we then know the content-length for the headers
		 * - it's stretchy to arbitrary numbers of metrics
		 * - lwsac block list provides the per-metric structure to
		 *   hold the data in a way we can walk to write it simply
		 */

		ome_prepare(ctx, pss);

		p = start;
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"text/plain", pss->tot,
						&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_callback_on_writable(wsi);

		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		lwsac_free(&pss->ac);
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->walk)
			return 0;

		do {
			ip = (uint8_t *)pss->walk +
				lwsac_sizeof(pss->walk == pss->ac) + LWS_PRE;
			m = (unsigned int)((ip[0] << 8) | ip[1]);

			/* coverity */
			if (m > lwsac_get_tail_pos(pss->walk) -
				lwsac_sizeof(pss->walk == pss->ac))
				return -1;

			if (lws_ptr_diff_size_t(end, p) < m)
				break;

			memcpy(p, ip + 2, m);
			p += m;

			pss->walk = lwsac_get_next(pss->walk);
		} while (pss->walk);

		if (!lws_ptr_diff_size_t(p, start)) {
			lwsl_err("%s: stuck\n", __func__);
			return -1;
		}

		wm = pss->walk ? LWS_WRITE_HTTP : LWS_WRITE_HTTP_FINAL;

		if (lws_write(wsi, start, lws_ptr_diff_size_t(p, start),
			      (enum lws_write_protocol)wm) < 0)
			return 1;

		if (!pss->walk) {
			 if (lws_http_transaction_completed(wsi))
				return -1;
		} else
			lws_callback_on_writable(wsi);

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"lws-openmetrics",
		callback_lws_openmetrics_export,
		sizeof(struct pss),
		1024,
	},
};

LWS_VISIBLE const lws_plugin_protocol_t lws_openmetrics_export = {
	.hdr = {
		"lws OpenMetrics export",
		"lws_protocol_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},

	.protocols = protocols,
	.count_protocols = LWS_ARRAY_SIZE(protocols),
};

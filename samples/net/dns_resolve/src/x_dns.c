/** @file
 * @brief DNS API
 *
 * An API for applications to do DNS query.
 */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if 1
#define SYS_LOG_DOMAIN "dns-fuzz"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <zephyr.h>
#include <linker/sections.h>
#include <errno.h>
#include <stdio.h>

#include <net/net_core.h>
#include <net/net_if.h>
#include <net/net_mgmt.h>

#include <zephyr/types.h>
#include <string.h>

#include "x_dns.h"

static struct x_dns_ctx *x_dns_new_ctx(struct x_dns *d);
static void x_dns_resolve(struct k_work *work);
static void x_dns_reject(struct k_work *work);
static void x_dns_default_callback(enum dns_resolve_status status,
		   struct dns_addrinfo *info,
		   void *user_data);

struct x_dns *x_dns_init(struct x_dns *d, x_dns_result_cb callback)
{
	d->callback = callback ? callback : x_dns_default_callback;
	d->timeout = DNS_TIMEOUT;
	return d;
}

struct x_dns_ctx *x_dns_ctx_init(struct x_dns_ctx *d, struct x_dns *dns,
				 const char *query, x_dns_callback resolve,
				 x_dns_callback reject)
{
	d->dns = dns;
	d->query = query;
	d->resolve = resolve;
	d->reject = reject;
#if !defined(CONFIG_NET_IPV4) && !defined(CONFIG_NET_IPV6)
#error "You need to enable IPv4 or IPv6 to use DNS!"
#elif defined(CONFIG_NET_IPV4)
	d->query_type = DNS_QUERY_TYPE_AAAA;
#else
	d->query_type = DNS_QUERY_TYPE_A;
#endif
	return d;
}

void x_dns_lookup(struct x_dns *d, const char *query, x_dns_callback resolve,
		  x_dns_callback reject)
{
	int ret;
	struct x_dns_ctx *ctx = x_dns_new_ctx(d);
	if (!ctx) {
		NET_ERR("FAIL: Cannot create dns reslove context");
		return;
	}

	x_dns_ctx_init(ctx, d, query, resolve, reject);

	NET_DBG("DNS query: %s", ctx->query);
	ret = dns_get_addr_info(ctx->query,
				ctx->query_type,
				&ctx->id,
				d->callback,
				(void *)ctx,
				d->timeout);
	if (ret < 0) {
		NET_ERR("FAIL: Cannot resolve address (%d)", ret);
		return;
	}

	NET_DBG("DNS id %u", ctx->id);
}

static struct x_dns_ctx *x_dns_new_ctx(struct x_dns *d) {
	return &d->ctx_pool[0];
}

static void x_dns_resolve(struct k_work *work) {
	struct x_dns_ctx *ctx = CONTAINER_OF(work, struct x_dns_ctx, work);
	if (!ctx) {
		NET_ERR("FAIL: No resolve for DNS query of: %s", ctx->query);
		return;
	}

	NET_DBG("resolve ctx: %s", ctx->query);
	ctx->resolve(ctx);
}

static void x_dns_reject(struct k_work *work) {
	struct x_dns_ctx *ctx = CONTAINER_OF(work, struct x_dns_ctx, work);
	if (!ctx) {
		NET_ERR("FAIL: No reject for DNS query of: %s", ctx->query);
		return;
	}

	NET_DBG("reject ctx: %s", ctx->query);
	ctx->reject(ctx);
}

static void x_dns_default_callback(enum dns_resolve_status status,
		   struct dns_addrinfo *info,
		   void *user_data)
{
	char hr_addr[NET_IPV6_ADDR_LEN];
	char *hr_family;
	void *addr = NULL;
	struct x_dns_ctx *d = (struct x_dns_ctx *)user_data;

	switch (status) {
	case DNS_EAI_CANCELED:
		NET_INFO("DNS query was canceled");
		goto x_dns_default_callback_reject;
	case DNS_EAI_FAIL:
		NET_INFO("DNS resolve failed");
		goto x_dns_default_callback_reject;
	case DNS_EAI_NODATA:
		NET_INFO("Cannot resolve address");
		goto x_dns_default_callback_reject;
	case DNS_EAI_ALLDONE:
		NET_INFO("DNS resolving finished");
		goto x_dns_default_callback_reject;
	case DNS_EAI_INPROGRESS:
		break;
	default:
		NET_INFO("DNS resolving error (%d)", status);
		goto x_dns_default_callback_reject;
	}

	if (!info) {
		goto x_dns_default_callback_reject;
	}

	if (info->ai_family == AF_INET) {
		hr_family = "IPv4";
		memcpy(&d->addr, &net_sin(&info->ai_addr)->sin_addr,
		       sizeof(d->addr));
	} else if (info->ai_family == AF_INET6) {
		hr_family = "IPv6";
		memcpy(&d->addr, &net_sin6(&info->ai_addr)->sin6_addr,
		       sizeof(d->addr));
	} else {
		NET_ERR("Invalid IP address family %d", info->ai_family);
		goto x_dns_default_callback_reject;
	}

	NET_INFO("%s %s address: %s", d->query, hr_family,
		 net_addr_ntop(info->ai_family, addr,
			       hr_addr, sizeof(hr_addr)));

	k_delayed_work_init(&d->work, x_dns_resolve);
	goto x_dns_default_callback_return;

x_dns_default_callback_reject:
	k_delayed_work_init(&d->work, x_dns_reject);

x_dns_default_callback_return:
	k_delayed_work_submit(&d->work, 0);
}

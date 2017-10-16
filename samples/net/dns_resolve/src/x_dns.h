/** @file
 * @brief DNS resolving library
 *
 * An API for applications to resolve a DNS name.
 */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _X_DNS_H
#define _X_DNS_H

#include <net/dns_resolve.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DNS_TIMEOUT
#define DNS_TIMEOUT K_SECONDS(2)
#endif

typedef void (*x_dns_result_cb)(enum dns_resolve_status status,
			 struct dns_addrinfo *info,
			 void *user_data);

struct x_dns;
struct x_dns_ctx;

typedef void (*x_dns_callback)(struct x_dns_ctx *);

struct x_dns_ctx
{
	u16_t id;
	struct k_delayed_work work;
	struct x_dns *dns;
	enum dns_query_type query_type;
	const char *query;
	struct sockaddr addr;
	x_dns_callback resolve;
	x_dns_callback reject;
};

struct x_dns
{
	x_dns_result_cb callback;
	s32_t timeout;
	void *data;
	struct x_dns_ctx ctx_pool[1];
};

struct x_dns *x_dns_init(struct x_dns *d, x_dns_result_cb callback);
struct x_dns_ctx *x_dns_ctx_init(struct x_dns_ctx *d, struct x_dns *dns,
				 const char *query, x_dns_callback resolve,
				 x_dns_callback reject);
void x_dns_lookup(struct x_dns *d, const char *query, x_dns_callback resolve,
		  x_dns_callback reject);

#ifdef __cplusplus
}
#endif

#endif /* _X_DNS_H */

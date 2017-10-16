/*
 * Copyright (c) 2017 Intel Corporation.
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

#include "x_dns.h"

static void query_success(struct x_dns_ctx *d);
static void query_failure(struct x_dns_ctx *d);

static void query_success(struct x_dns_ctx *d) {
	NET_INFO("In query_success: %s", d->query);
	x_dns_lookup(d->dns, d->query, query_success, query_failure);
}

static void query_failure(struct x_dns_ctx *d) {
	NET_INFO("In query_failure: %s", d->query);
	x_dns_lookup(d->dns, d->query, query_success, query_failure);
}

static void setup_ipv4(struct net_if *iface)
{
	char hr_addr[NET_IPV4_ADDR_LEN];
	struct in_addr addr;

	struct x_dns dns;

	if (net_addr_pton(AF_INET, CONFIG_NET_APP_MY_IPV4_ADDR, &addr)) {
		NET_ERR("Invalid address: %s", CONFIG_NET_APP_MY_IPV4_ADDR);
		return;
	}

	net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0);

	NET_INFO("IPv4 address: %s",
		 net_addr_ntop(AF_INET, &addr, hr_addr, NET_IPV4_ADDR_LEN));

	x_dns_init(&dns, NULL);
	x_dns_lookup(&dns, "www.zephyrproject.org", query_success,
		     query_failure);
}

void main(void)
{
	struct net_if *iface = net_if_get_default();

	NET_INFO("Starting DNS resolve fuzzing client");

	setup_ipv4(iface);
}

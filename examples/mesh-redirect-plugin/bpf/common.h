/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/section.h>

#define TC_ACT_OK 0
#define TC_ACT_UNSPEC (-1)

/* Mark set by Envoy on forwarded traffic to prevent redirect loops */
#define ENVOY_MARK 0x539 /* 1337 */

/* Max entries in the mesh redirect map */
#define MAX_MESH_ENTRIES 1024

/* Map value for mesh_redirect_map */
struct mesh_config {
	__u16 inbound_port;  /* Envoy inbound listener port (default 15006) */
	__u16 outbound_port; /* Envoy outbound listener port (default 15001) */
};

/* BPF map: pod IP -> mesh config. Populated by the plugin's control plane. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);              /* IPv4 address in network byte order */
	__type(value, struct mesh_config);
	__uint(max_entries, MAX_MESH_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} mesh_redirect_map __section(".maps");

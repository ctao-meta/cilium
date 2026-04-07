// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <linux/byteorder.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include "common.h"

__section("freplace")
int before(struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip4;
	struct tcphdr *tcp;
	struct mesh_config *cfg;
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	__u32 src_ip, dst_ip;
	__u16 proxy_port;

	/* Skip packets marked by Envoy to prevent redirect loops */
	if (ctx->mark == ENVOY_MARK)
		return TC_ACT_UNSPEC;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_UNSPEC;

	/* Only handle IPv4 for now */
	if (eth->h_proto != MESH_HTONS(ETH_P_IP))
		return TC_ACT_UNSPEC;

	ip4 = (void *)(eth + 1);
	if ((void *)(ip4 + 1) > data_end)
		return TC_ACT_UNSPEC;

	/* Only redirect TCP traffic */
	if (ip4->protocol != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	tcp = (void *)(ip4 + 1);
	if ((void *)(tcp + 1) > data_end)
		return TC_ACT_UNSPEC;

	src_ip = ip4->saddr;
	dst_ip = ip4->daddr;

	/* Check if destination pod is mesh-enrolled (INBOUND) */
	cfg = map_lookup_elem(&mesh_redirect_map, &dst_ip);
	if (cfg) {
		proxy_port = cfg->inbound_port;
		goto do_redirect;
	}

	/* Check if source pod is mesh-enrolled (OUTBOUND) */
	cfg = map_lookup_elem(&mesh_redirect_map, &src_ip);
	if (cfg) {
		proxy_port = cfg->outbound_port;
		goto do_redirect;
	}

	/* Neither src nor dst is mesh-enrolled */
	return TC_ACT_UNSPEC;

do_redirect:
	/* Build the full 4-tuple from the packet */
	tuple.ipv4.saddr = src_ip;
	tuple.ipv4.daddr = dst_ip;
	tuple.ipv4.sport = tcp->source; /* already network byte order */
	tuple.ipv4.dport = tcp->dest;   /* already network byte order */

	/* Step 1: Look for an ESTABLISHED socket matching the original tuple.
	 * This handles non-SYN packets for connections already redirected.
	 */
	sk = sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
			   BPF_F_CURRENT_NETNS, 0);
	if (sk) {
		if (sk->state != BPF_TCP_LISTEN)
			goto assign;
		sk_release(sk);
	}

	/* Step 2: Look for Envoy's LISTEN socket on the proxy port.
	 * This handles new connections (SYN packets).
	 */
	tuple.ipv4.dport = MESH_HTONS(proxy_port);
	sk = sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
			   BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return TC_ACT_UNSPEC; /* Envoy not ready */

assign:
	if (sk_assign(ctx, sk, 0) != 0) {
		sk_release(sk);
		return TC_ACT_UNSPEC;
	}

	sk_release(sk);
	return TC_ACT_OK;
}

BPF_LICENSE("Dual BSD/GPL");

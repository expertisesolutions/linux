// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2020, 2021 SiPanda Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* PANDA Big Parser
 *
 * Implement flow dissector in PANDA. A protocol parse graph is created and
 * metadata is extracted at various nodes.
 */

#include <linux/module.h>
#include <linux/types.h>

/* Define protocol nodes that are used below */
#include <net/panda/parser.h>
#include <net/panda/parser_metadata.h>
#include <net/panda/proto_nodes_def.h>
/* Meta data functions for parser nodes. Use the canned templates
 * for common metadata
 */

struct mlx5_ct_tuple {
    u16 addr_type;
    __be16 n_proto;
    u8 ip_proto;
    struct {
        union {
            __be32 src_v4;
            struct in6_addr src_v6;
        };
        union {
            __be32 dst_v4;
            struct in6_addr dst_v6;
        };
    } ip;
    struct {
        __be16 src;
        __be16 dst;
    } port;

    u16 zone;
};

static void ether_metadata(const void *veth, void *iframe, struct panda_ctrl_data ctrl)
{
    struct mlx5_ct_tuple *frame = iframe;

    frame->n_proto = ((struct ethhdr *)veth)->h_proto;
}

static void ipv4_metadata(const void *viph, void *iframe, struct panda_ctrl_data ctrl)
{
    struct mlx5_ct_tuple *frame = iframe;
    const struct iphdr *iph = viph;

    frame->ip_proto = iph->protocol;

    frame->addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
    frame->ip.src_v4 = iph->saddr;
    frame->ip.dst_v4 = iph->daddr;
}


static void ipv6_metadata(const void *viph, void *iframe, struct panda_ctrl_data ctrl)
{
    struct mlx5_ct_tuple *frame = iframe;
    const struct iphdr *iph = viph;

    frame->ip_proto = iph->protocol;

    frame->addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;
    memcpy(&frame->ip.src_v6, &iph->saddr,
           sizeof(frame->ip));
}

static void ports_metadata(const void *vphdr, void *iframe,
         struct panda_ctrl_data ctrl)
{
    struct mlx5_ct_tuple *frame = iframe;

    frame->port.src = ((struct port_hdr *)vphdr)->sport;
    frame->port.dst = ((struct port_hdr *)vphdr)->dport;
}



/* Parse nodes. Parse nodes are composed of the common PANDA Parser protocol
 * nodes, metadata functions defined above, and protocol tables defined
 * below
 */

PANDA_MAKE_PARSE_NODE(ether_node, panda_parse_ether, ether_metadata,
		      NULL, ether_table);

PANDA_MAKE_PARSE_NODE(ipv4_node, panda_parse_ipv4, ipv4_metadata,
	   		  NULL,ipv4_table);
PANDA_MAKE_PARSE_NODE(ipv6_node, panda_parse_ipv6, ipv6_metadata,
	   		  NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_check_node, panda_parse_ipv6_check, ipv6_metadata,
              NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_eh_node, panda_parse_ipv6_eh, NULL,
              NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_frag_node, panda_parse_ipv6_frag_eh, NULL,
	   		  NULL, ipv6_table);
PANDA_MAKE_LEAF_PARSE_NODE(ports_node, panda_parse_ports, ports_metadata,
			  NULL);

/* Protocol tables */

PANDA_MAKE_PROTO_TABLE(ether_table,
	{ __cpu_to_be16(ETH_P_IP), &ipv4_node },
	{ __cpu_to_be16(ETH_P_IPV6), &ipv6_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_table,
	{ IPPROTO_TCP, &ports_node },
	{ IPPROTO_UDP, &ports_node },
);


PANDA_MAKE_PROTO_TABLE(ip_table,
	{ 4, &ipv4_node },
	{ 6, &ipv6_node },
);

PANDA_MAKE_PROTO_TABLE(ipv6_table,
    { IPPROTO_HOPOPTS, &ipv6_eh_node },
    { IPPROTO_ROUTING, &ipv6_eh_node },
    { IPPROTO_DSTOPTS, &ipv6_eh_node },
    { IPPROTO_FRAGMENT, &ipv6_frag_node },
    { IPPROTO_TCP, &ports_node },
    { IPPROTO_UDP, &ports_node },
);

/* Define parsers. Two of them: one for packets starting with an
 * Ethernet header, and one for packets starting with an IP header.
 */
PANDA_PARSER_EXT(panda_parser_big_ether, "PANDA big parser for Ethernet",
		 &ether_node);

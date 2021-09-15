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

#include <linux/module.h>
#include <linux/types.h>
#include <net/panda/parser.h>
#include <net/panda/parser_metadata.h>
#include <net/panda/proto_nodes_def.h>

/* PANDA Big Parser
 *
 * Implement flow dissector in PANDA. A protocol parse graph is created and
 * metadata is extracted at various nodes.
 */
struct flow_dissector_key_ppp {
	__be16 ppp_proto;
};

struct fl2_flow_key {
	struct flow_dissector_key_meta meta;
	struct flow_dissector_key_control control;
	struct flow_dissector_key_control enc_control;
	struct flow_dissector_key_basic basic;
	struct flow_dissector_key_eth_addrs eth;
	struct flow_dissector_key_vlan vlan;
	struct flow_dissector_key_vlan cvlan;
	union {
		struct flow_dissector_key_ipv4_addrs ipv4;
		struct flow_dissector_key_ipv6_addrs ipv6;
	};
	struct flow_dissector_key_ports tp;
	struct flow_dissector_key_icmp icmp;
	struct flow_dissector_key_arp arp;
	struct flow_dissector_key_keyid enc_key_id;
	union {
		struct flow_dissector_key_ipv4_addrs enc_ipv4;
		struct flow_dissector_key_ipv6_addrs enc_ipv6;
	};
	struct flow_dissector_key_ports enc_tp;
	struct flow_dissector_key_mpls mpls;
	struct flow_dissector_key_tcp tcp;
	struct flow_dissector_key_ip ip;
	struct flow_dissector_key_ip enc_ip;
	struct flow_dissector_key_enc_opts enc_opts;
	union {
		struct flow_dissector_key_ports tp;
		struct {
			struct flow_dissector_key_ports tp_min;
			struct flow_dissector_key_ports tp_max;
		};
	} tp_range;
	struct flow_dissector_key_ct ct;
	struct flow_dissector_key_hash hash;
	struct flow_dissector_key_ppp ppp;
} __aligned(BITS_PER_LONG / 8); /* Ensure that we can do comparisons as longs. */


/* Meta data structure for just one frame */
struct panda_parser_big_metadata_one {
	struct panda_metadata panda_data;
	struct fl2_flow_key frame;
};

/* Meta data functions for parser nodes. Use the canned templates
 * for common metadata
 */
static void ether_metadata(const void *veth, void *iframe, struct panda_ctrl_data ctrl)
{
	struct fl2_flow_key *frame = iframe;

	frame->basic.n_proto = ((struct ethhdr *)veth)->h_proto;
	memcpy(&frame->eth, &((struct ethhdr *)veth)->h_dest,
	       sizeof(frame->eth));
}

static void ipv4_metadata(const void *viph, void *iframe, struct panda_ctrl_data ctrl)
{
	struct fl2_flow_key *frame = iframe;
	const struct iphdr *iph = viph;
	
	frame->basic.ip_proto = iph->protocol;
	
	if (frame->vlan.vlan_id != 0 && frame->vlan.vlan_id != 1) {
		frame->enc_control.addr_type = FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS;
		memcpy(&frame->enc_ipv4.src, &iph->saddr,
		       sizeof(frame->ipv4));
	}
	frame->control.addr_type = FLOW_DISSECTOR_KEY_IPV4_ADDRS;
	memcpy(&frame->ipv4.src, &iph->saddr,
	       sizeof(frame->ipv4));
}

static void ipv6_metadata(const void *viph, void *iframe, struct panda_ctrl_data ctrl)
{
	struct fl2_flow_key *frame = iframe;
	const struct ipv6hdr *iph = viph;

	frame->basic.ip_proto = iph->nexthdr;

	frame->control.addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;
	memcpy(&frame->ipv6.src, &iph->saddr,
	       sizeof(frame->ipv6));

}

static void ppp_metadata(const void *vppph, void *iframe, struct panda_ctrl_data ctrl)
{
	struct fl2_flow_key *frame = iframe;
	//ppp protocol can have 8 or 16 bits
	frame->ppp.ppp_proto = __cpu_to_be16(
		ctrl.hdr_len == sizeof(struct pppoe_hdr_proto8) ? 
		((struct pppoe_hdr_proto8*)vppph)->protocol : 
		((struct pppoe_hdr_proto16*)vppph)->protocol
		);
		
}

static void ports_metadata(const void *vphdr, void *iframe,			
		 struct panda_ctrl_data ctrl)				
{									
	struct fl2_flow_key *frame = iframe;
	frame->tp.ports = ((struct port_hdr *)vphdr)->ports;
}

static void arp_rarp_metadata(const void *vearp, void *iframe, struct panda_ctrl_data ctrl)
{
	
	struct fl2_flow_key *frame = iframe;
	const struct earphdr *earp = vearp;

	frame->arp.op = ntohs(earp->arp.ar_op) & 0xff;

	/* Record Ethernet addresses */
	memcpy(frame->arp.sha, earp->ar_sha, ETH_ALEN);
	memcpy(frame->arp.tha, earp->ar_tha, ETH_ALEN);

	/* Record IP addresses */
	memcpy(&frame->arp.sip, &earp->ar_sip, sizeof(frame->arp.sip));
	memcpy(&frame->arp.tip, &earp->ar_tip, sizeof(frame->arp.tip));
}

static void icmp_metadata(const void *vicmp, void *iframe, struct panda_ctrl_data ctrl)
{
	struct fl2_flow_key *frame = iframe;
	const struct icmphdr *icmp = vicmp;

	frame->icmp.type = icmp->type;
	frame->icmp.code = icmp->code;
	if (icmp_has_id(icmp->type))
		frame->icmp.id = icmp->un.echo.id ? : 1;
	else
		frame->icmp.id = 0;
}

static void e8021Q_metadata(const void *vvlan, void *iframe,
		 struct panda_ctrl_data ctrl)
{
	struct fl2_flow_key *frame = iframe;
	const struct vlan_hdr *vlan = vvlan;

	frame->vlan.vlan_id = ntohs(vlan->h_vlan_TCI) &
				VLAN_VID_MASK;
	frame->vlan.vlan_priority = (ntohs(vlan->h_vlan_TCI) &
				VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
	frame->vlan.vlan_tpid = ETH_P_8021Q;
}

static void e8021AD_metadata(const void *vvlan, void *iframe,
		 struct panda_ctrl_data ctrl)
{
	struct fl2_flow_key *frame = iframe;
	const struct vlan_hdr *vlan = vvlan;

	frame->vlan.vlan_id = ntohs(vlan->h_vlan_TCI) &
				VLAN_VID_MASK;
	frame->vlan.vlan_priority = (ntohs(vlan->h_vlan_TCI) &
				VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
	frame->vlan.vlan_tpid = ETH_P_8021AD;
}

/* Parse nodes. Parse nodes are composed of the common PANDA Parser protocol
 * nodes, metadata functions defined above, and protocol tables defined
 * below
 */
PANDA_MAKE_PARSE_NODE(ether_node, panda_parse_ether, ether_metadata,
		      NULL, ether_table);
PANDA_MAKE_PARSE_NODE(ip_overlay_node, panda_parse_ip, NULL,
		      NULL, ip_table);
PANDA_MAKE_PARSE_NODE(ipv4_check_node, panda_parse_ipv4_check, ipv4_metadata,
		      NULL, ipv4_table);
PANDA_MAKE_PARSE_NODE(ipv4_node, panda_parse_ipv4, ipv4_metadata, NULL,
		      ipv4_table);
PANDA_MAKE_PARSE_NODE(ipv6_node, panda_parse_ipv6, ipv6_metadata, NULL,
		      ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_check_node, panda_parse_ipv6_check, ipv6_metadata,
		      NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_eh_node, panda_parse_ipv6_eh, NULL,
		      NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_frag_node, panda_parse_ipv6_frag_eh, NULL, NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ppp_node, panda_parse_ppp, NULL, NULL, ppp_table);
PANDA_MAKE_PARSE_NODE(pppoe_node, panda_parse_pppoe, ppp_metadata, NULL,
		      pppoe_table);

PANDA_MAKE_PARSE_NODE(e8021AD_node, panda_parse_vlan, e8021AD_metadata, NULL,
				ether_table);
PANDA_MAKE_PARSE_NODE(e8021Q_node, panda_parse_vlan, e8021Q_metadata, NULL,
		      	ether_table);
PANDA_MAKE_OVERLAY_PARSE_NODE(ipv4ip_node, panda_parse_ipv4ip, NULL, NULL,
			      &ipv4_node);
PANDA_MAKE_OVERLAY_PARSE_NODE(ipv6ip_node, panda_parse_ipv6ip, NULL, NULL,
			      &ipv6_node);

PANDA_MAKE_LEAF_PARSE_NODE(ports_node, panda_parse_ports, ports_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(icmpv4_node, panda_parse_icmpv4, icmp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(icmpv6_node, panda_parse_icmpv6, icmp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(arp_node, panda_parse_arp, arp_rarp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(rarp_node, panda_parse_rarp, arp_rarp_metadata,
			   NULL);

PANDA_MAKE_LEAF_PARSE_NODE(tcp_node, panda_parse_ports, ports_metadata,
			   NULL);

/* Protocol tables */
PANDA_MAKE_PROTO_TABLE(ether_table,
	{ __cpu_to_be16(ETH_P_IP), &ipv4_check_node },
	{ __cpu_to_be16(ETH_P_IPV6), &ipv6_check_node },
	{ __cpu_to_be16(ETH_P_8021AD), &e8021AD_node },
	{ __cpu_to_be16(ETH_P_8021Q), &e8021Q_node },
	{ __cpu_to_be16(ETH_P_ARP), &arp_node },
	{ __cpu_to_be16(ETH_P_RARP), &rarp_node },
	{ __cpu_to_be16(ETH_P_PPP_SES), &pppoe_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_table,
	{ IPPROTO_TCP, &tcp_node },
	{ IPPROTO_UDP, &ports_node },
	{ IPPROTO_SCTP, &ports_node },
	{ IPPROTO_DCCP, &ports_node },
	{ IPPROTO_ICMP, &icmpv4_node },
	{ IPPROTO_IPIP, &ipv4ip_node },
	{ IPPROTO_IPV6, &ipv6ip_node },
);

PANDA_MAKE_PROTO_TABLE(ipv6_table,
	{ IPPROTO_HOPOPTS, &ipv6_eh_node },
	{ IPPROTO_ROUTING, &ipv6_eh_node },
	{ IPPROTO_DSTOPTS, &ipv6_eh_node },
	{ IPPROTO_FRAGMENT, &ipv6_frag_node },
	{ IPPROTO_TCP, &tcp_node },
	{ IPPROTO_UDP, &ports_node },
	{ IPPROTO_SCTP, &ports_node },
	{ IPPROTO_DCCP, &ports_node },
	{ IPPROTO_ICMPV6, &icmpv6_node },
	{ IPPROTO_IPIP, &ipv4ip_node },
	{ IPPROTO_IPV6, &ipv6ip_node },
);

PANDA_MAKE_PROTO_TABLE(ip_table,
	{ 4, &ipv4_node },
	{ 6, &ipv6_node },
);

PANDA_MAKE_PROTO_TABLE(ppp_table,
	{ __cpu_to_be16(PPP_IP), &ipv4_check_node },
	{ __cpu_to_be16(PPP_IPV6), &ipv6_check_node },
);

PANDA_MAKE_PROTO_TABLE(pppoe_table,
	{ __cpu_to_be16(PPP_IP), &ipv4_check_node },
	{ __cpu_to_be16(PPP_IPV6), &ipv6_check_node },
);

/* Define parsers. Two of them: one for packets starting with an
 * Ethernet header, and one for packets starting with an IP header.
 */
PANDA_PARSER_EXT(panda_parser_big_ether, "PANDA big parser for Ethernet",
		 &ether_node);


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

/*
PANDA_METADATA_TEMP_ipv6(ipv6_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ip_overlay(ip_overlay_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ipv6_eh(ipv6_eh_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ipv6_frag(ipv6_frag_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_ports_off(ports_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_icmp(icmp_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_vlan_8021AD(e8021AD_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_vlan_8021Q(e8021Q_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_mpls(mpls_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_arp_rarp(arp_rarp_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_tipc(tipc_metadata, panda_metadata_all)

PANDA_METADATA_TEMP_tcp_option_mss(tcp_opt_mss_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_window_scaling(tcp_opt_window_scaling_metadata,
					      panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_timestamp(tcp_opt_timestamp_metadata,
					 panda_metadata_all)

PANDA_METADATA_TEMP_tcp_option_sack_1(tcp_opt_sack_metadata_1,
				      panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_sack_2(tcp_opt_sack_metadata_2,
				      panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_sack_3(tcp_opt_sack_metadata_3,
				      panda_metadata_all)
PANDA_METADATA_TEMP_tcp_option_sack_4(tcp_opt_sack_metadata_4,
				      panda_metadata_all)

PANDA_METADATA_TEMP_gre(gre_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_pptp(gre_pptp_metadata, panda_metadata_all)

PANDA_METADATA_TEMP_gre_checksum(gre_checksum_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_keyid(gre_keyid_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_seq(gre_seq_metadata, panda_metadata_all)

PANDA_METADATA_TEMP_gre_pptp_key(gre_pptp_key_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_pptp_seq(gre_pptp_seq_metadata, panda_metadata_all)
PANDA_METADATA_TEMP_gre_pptp_ack(gre_pptp_ack_metadata, panda_metadata_all)
*/
/* Parse nodes. Parse nodes are composed of the common PANDA Parser protocol
 * nodes, metadata functions defined above, and protocol tables defined
 * below
 */

PANDA_MAKE_PARSE_NODE(ether_node, panda_parse_ether, ether_metadata,
		      NULL, ether_table);
PANDA_MAKE_PARSE_NODE(ip_overlay_node, panda_parse_ip,/* ip_overlay_metadata*/NULL,
		      NULL, ip_table);
PANDA_MAKE_PARSE_NODE(ipv4_check_node, panda_parse_ipv4_check, ipv4_metadata,
		      NULL, ipv4_table);
PANDA_MAKE_PARSE_NODE(ipv4_node, panda_parse_ipv4, ipv4_metadata, NULL,
		      ipv4_table);
PANDA_MAKE_PARSE_NODE(ipv6_node, panda_parse_ipv6, ipv6_metadata, NULL,
		      ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_check_node, panda_parse_ipv6_check, ipv6_metadata,
		      NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_eh_node, panda_parse_ipv6_eh,/* ipv6_eh_metadata*/NULL,
		      NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ipv6_frag_node, panda_parse_ipv6_frag_eh,/*
								 ipv6_frag_metadata*/NULL, NULL, ipv6_table);
PANDA_MAKE_PARSE_NODE(ppp_node, panda_parse_ppp, NULL, NULL, ppp_table);
PANDA_MAKE_PARSE_NODE(pppoe_node, panda_parse_pppoe, ppp_metadata, NULL,
		      pppoe_table);
PANDA_MAKE_PARSE_NODE(gre_base_node, panda_parse_gre_base, NULL, NULL,
		      gre_base_table);

PANDA_MAKE_FLAG_FIELDS_PARSE_NODE(gre_v0_node, panda_parse_gre_v0,/*
								    gre_metadata*/NULL, NULL, gre_v0_table,
				  gre_v0_flag_fields_table);
PANDA_MAKE_FLAG_FIELDS_OVERLAY_PARSE_NODE(gre_v1_node, panda_parse_gre_v1,/*
									    gre_pptp_metadata*/NULL, NULL, &ppp_node,
					  gre_v1_flag_fields_table);

PANDA_MAKE_PARSE_NODE(e8021AD_node, panda_parse_vlan, e8021AD_metadata, NULL,
				ether_table);
PANDA_MAKE_PARSE_NODE(e8021Q_node, panda_parse_vlan, e8021Q_metadata, NULL,
		      	ether_table);
PANDA_MAKE_OVERLAY_PARSE_NODE(ipv4ip_node, panda_parse_ipv4ip, NULL, NULL,
			      &ipv4_node);
PANDA_MAKE_OVERLAY_PARSE_NODE(ipv6ip_node, panda_parse_ipv6ip, NULL, NULL,
			      &ipv6_node);

PANDA_MAKE_PARSE_NODE(batman_node, panda_parse_batman, NULL, NULL,
		      ether_table);

PANDA_MAKE_LEAF_PARSE_NODE(ports_node, panda_parse_ports, ports_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(icmpv4_node, panda_parse_icmpv4, icmp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(icmpv6_node, panda_parse_icmpv6, icmp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(mpls_node, panda_parse_mpls,/* mpls_metadata*/NULL,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(arp_node, panda_parse_arp, arp_rarp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(rarp_node, panda_parse_rarp, arp_rarp_metadata,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(tipc_node, panda_parse_tipc,/* tipc_metadata*/NULL,
			   NULL);
PANDA_MAKE_LEAF_PARSE_NODE(fcoe_node, panda_parse_fcoe, NULL, NULL);
PANDA_MAKE_LEAF_PARSE_NODE(igmp_node, panda_parse_igmp, NULL, NULL);

PANDA_MAKE_LEAF_TLVS_PARSE_NODE(tcp_node, panda_parse_tcp_tlvs,	ports_metadata,
				NULL, tcp_tlv_table);

PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_mss_node, panda_parse_tcp_option_mss,/*
									 tcp_opt_mss_metadata*/NULL, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_window_scaling_node,
			  panda_parse_tcp_option_window_scaling,/*
								  tcp_opt_window_scaling_metadata*/NULL, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_timestamp_node,
			  panda_parse_tcp_option_timestamp,/*
							     tcp_opt_timestamp_metadata*/NULL, NULL);

PANDA_MAKE_TLV_OVERLAY_PARSE_NODE(tcp_opt_sack_node, NULL, NULL,
				  tcp_sack_tlv_table, NULL, PANDA_OKAY, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_1, panda_parse_tcp_option_sack_1,
			  /*tcp_opt_sack_metadata_1*/NULL, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_2, panda_parse_tcp_option_sack_2,
			  /*tcp_opt_sack_metadata_2*/NULL, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_3, panda_parse_tcp_option_sack_3,
			  /*tcp_opt_sack_metadata_3*/NULL, NULL);
PANDA_MAKE_TLV_PARSE_NODE(tcp_opt_sack_4, panda_parse_tcp_option_sack_4,
			  /*tcp_opt_sack_metadata_4*/NULL, NULL);

PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_csum_node,/* gre_checksum_metadata*/NULL,
				 NULL);
PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_key_node,/* gre_keyid_metadata*/NULL, NULL);
PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_flag_seq_node,/* gre_seq_metadata*/NULL, NULL);

PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_pptp_flag_ack_node,/* gre_pptp_ack_metadata*/NULL,
				 NULL);
PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_pptp_flag_key_node,/* gre_pptp_key_metadata*/NULL,
				 NULL);
PANDA_MAKE_FLAG_FIELD_PARSE_NODE(gre_pptp_flag_seq_node,/* gre_pptp_seq_metadata*/NULL,
				 NULL);

/* Protocol tables */

PANDA_MAKE_PROTO_TABLE(ether_table,
	{ __cpu_to_be16(ETH_P_IP), &ipv4_check_node },
	{ __cpu_to_be16(ETH_P_IPV6), &ipv6_check_node },
	{ __cpu_to_be16(ETH_P_8021AD), &e8021AD_node },
	{ __cpu_to_be16(ETH_P_8021Q), &e8021Q_node },
	{ __cpu_to_be16(ETH_P_MPLS_UC), &mpls_node },
	{ __cpu_to_be16(ETH_P_MPLS_MC), &mpls_node },
	{ __cpu_to_be16(ETH_P_ARP), &arp_node },
	{ __cpu_to_be16(ETH_P_RARP), &rarp_node },
	{ __cpu_to_be16(ETH_P_TIPC), &tipc_node },
	{ __cpu_to_be16(ETH_P_BATMAN), &batman_node },
	{ __cpu_to_be16(ETH_P_FCOE), &fcoe_node },
	{ __cpu_to_be16(ETH_P_PPP_SES), &pppoe_node },
);

PANDA_MAKE_PROTO_TABLE(ipv4_table,
	{ IPPROTO_TCP, &tcp_node.parse_node },
	{ IPPROTO_UDP, &ports_node },
	{ IPPROTO_SCTP, &ports_node },
	{ IPPROTO_DCCP, &ports_node },
	{ IPPROTO_GRE, &gre_base_node },
	{ IPPROTO_ICMP, &icmpv4_node },
	{ IPPROTO_IGMP, &igmp_node },
	{ IPPROTO_MPLS, &mpls_node },
	{ IPPROTO_IPIP, &ipv4ip_node },
	{ IPPROTO_IPV6, &ipv6ip_node },
);

PANDA_MAKE_PROTO_TABLE(ipv6_table,
	{ IPPROTO_HOPOPTS, &ipv6_eh_node },
	{ IPPROTO_ROUTING, &ipv6_eh_node },
	{ IPPROTO_DSTOPTS, &ipv6_eh_node },
	{ IPPROTO_FRAGMENT, &ipv6_frag_node },
	{ IPPROTO_TCP, &tcp_node.parse_node },
	{ IPPROTO_UDP, &ports_node },
	{ IPPROTO_SCTP, &ports_node },
	{ IPPROTO_DCCP, &ports_node },
	{ IPPROTO_GRE, &gre_base_node },
	{ IPPROTO_ICMPV6, &icmpv6_node },
	{ IPPROTO_IGMP, &igmp_node },
	{ IPPROTO_MPLS, &mpls_node },
	{ IPPROTO_IPIP, &ipv4ip_node },
	{ IPPROTO_IPV6, &ipv6ip_node },
);

PANDA_MAKE_PROTO_TABLE(ip_table,
	{ 4, &ipv4_node },
	{ 6, &ipv6_node },
);

PANDA_MAKE_PROTO_TABLE(gre_base_table,
	{ 0, &gre_v0_node.parse_node },
	{ 1, &gre_v1_node.parse_node },
);

PANDA_MAKE_PROTO_TABLE(gre_v0_table,
	{ __cpu_to_be16(ETH_P_IP), &ipv4_check_node },
	{ __cpu_to_be16(ETH_P_IPV6), &ipv6_check_node },
	{ __cpu_to_be16(ETH_P_TEB), &ether_node },
);

PANDA_MAKE_PROTO_TABLE(ppp_table,
	{ __cpu_to_be16(PPP_IP), &ipv4_check_node },
	{ __cpu_to_be16(PPP_IPV6), &ipv6_check_node },
);

PANDA_MAKE_PROTO_TABLE(pppoe_table,
	{ __cpu_to_be16(PPP_IP), &ipv4_check_node },
	{ __cpu_to_be16(PPP_IPV6), &ipv6_check_node },
);

PANDA_MAKE_TLV_TABLE(tcp_tlv_table,
	{ TCPOPT_MSS, &tcp_opt_mss_node },
	{ TCPOPT_WINDOW, &tcp_opt_window_scaling_node },
	{ TCPOPT_TIMESTAMP, &tcp_opt_timestamp_node },
	{ TCPOPT_SACK, &tcp_opt_sack_node }
);

/* Keys are possible lengths of the TCP sack option */
PANDA_MAKE_TLV_TABLE(tcp_sack_tlv_table,
	{ 10, &tcp_opt_sack_1 },
	{ 18, &tcp_opt_sack_2 },
	{ 26, &tcp_opt_sack_3 },
	{ 34, &tcp_opt_sack_4 }
);

PANDA_MAKE_FLAG_FIELDS_TABLE(gre_v0_flag_fields_table,
	{ GRE_FLAGS_CSUM_IDX, &gre_flag_csum_node },
	{ GRE_FLAGS_KEY_IDX, &gre_flag_key_node },
	{ GRE_FLAGS_SEQ_IDX, &gre_flag_seq_node }
);

PANDA_MAKE_FLAG_FIELDS_TABLE(gre_v1_flag_fields_table,
	{ GRE_PPTP_FLAGS_CSUM_IDX, &PANDA_FLAG_NODE_NULL },
	{ GRE_PPTP_FLAGS_KEY_IDX, &gre_pptp_flag_key_node },
	{ GRE_PPTP_FLAGS_SEQ_IDX, &gre_pptp_flag_seq_node },
	{ GRE_PPTP_FLAGS_ACK_IDX, &gre_pptp_flag_ack_node }
);

/* Define parsers. Two of them: one for packets starting with an
 * Ethernet header, and one for packets starting with an IP header.
 */
PANDA_PARSER_EXT(panda_parser_big_ether, "PANDA big parser for Ethernet",
		 &ether_node);


#ifndef PANDA_LOOP_COUNT
#define PANDA_LOOP_COUNT 8
#endif

#define PANDA_MAX_ENCAPS (PANDA_LOOP_COUNT + 32)
enum {
CODE_ether_node,
CODE_ip_overlay_node,
CODE_ipv4_check_node,
CODE_ipv4_node,
CODE_ipv6_node,
CODE_ipv6_check_node,
CODE_ipv6_eh_node,
CODE_ipv6_frag_node,
CODE_ppp_node,
CODE_pppoe_node,
CODE_gre_base_node,
CODE_gre_v0_node,
CODE_e8021AD_node,
CODE_e8021Q_node,
CODE_ipv4ip_node,
CODE_ipv6ip_node,
CODE_batman_node,
CODE_ports_node,
CODE_icmpv4_node,
CODE_icmpv6_node,
CODE_mpls_node,
CODE_arp_node,
CODE_rarp_node,
CODE_tipc_node,
CODE_fcoe_node,
CODE_igmp_node,
CODE_tcp_node,
CODE_IGNORE
};

/* Parser control */
static long next = CODE_IGNORE;

static inline __attribute__((always_inline)) int check_pkt_len(const void *hdr,
		const struct panda_proto_node *pnode, size_t len, ssize_t *hlen)
{
	*hlen = pnode->min_len;

	/* Protocol node length checks */
	if (len < *hlen)
		return PANDA_STOP_LENGTH;

	if (pnode->ops.len) {
		*hlen = pnode->ops.len(hdr);
		if (len < *hlen)
			return PANDA_STOP_LENGTH;
		if (*hlen < pnode->min_len)
			return *hlen < 0 ? *hlen : PANDA_STOP_LENGTH;
	} else {
		*hlen = pnode->min_len;
	}

	return PANDA_OKAY;
}

static inline __attribute__((always_inline)) int panda_encap_layer(
		struct panda_metadata *metadata, unsigned int max_encaps,
		void **frame, unsigned int *frame_num)
{
	/* New encapsulation layer. Check against number of encap layers
	 * allowed and also if we need a new metadata frame.
	 */
	if (++metadata->encaps > max_encaps)
		return PANDA_STOP_ENCAP_DEPTH;

	if (metadata->max_frame_num > *frame_num) {
		*frame += metadata->frame_size;
		*frame_num = (*frame_num) + 1;
	}

	return PANDA_OKAY;
}

static inline __attribute__((always_inline)) int panda_parse_tlv(
		const struct panda_parse_tlvs_node *parse_node,
		const struct panda_parse_tlv_node *parse_tlv_node,
		const __u8 *cp, void *frame, struct panda_ctrl_data tlv_ctrl) {
	const struct panda_parse_tlv_node_ops *ops = &parse_tlv_node->tlv_ops;
	const struct panda_proto_tlv_node *proto_tlv_node =
					parse_tlv_node->proto_tlv_node;

	if (proto_tlv_node && (tlv_ctrl.hdr_len < proto_tlv_node->min_len)) {
		/* Treat check length error as an unrecognized TLV */
		if (parse_node->tlv_wildcard_node)
			return panda_parse_tlv(parse_node,
					parse_node->tlv_wildcard_node,
					cp, frame, tlv_ctrl);
		else
			return parse_node->unknown_tlv_type_ret;
	}

	if (ops->extract_metadata)
		ops->extract_metadata(cp, frame, tlv_ctrl);

	if (ops->handle_tlv)
		ops->handle_tlv(cp, frame, tlv_ctrl);

	return PANDA_OKAY;
}




static __always_inline int __ether_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ip_overlay_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ipv4_check_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ipv4_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ipv6_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ipv6_check_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ipv6_eh_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ipv6_frag_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ppp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __pppoe_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __gre_base_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __gre_v0_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __e8021AD_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __e8021Q_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ipv4ip_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ipv6ip_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __batman_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __ports_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __icmpv4_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __icmpv6_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __mpls_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __arp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __rarp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __tipc_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __fcoe_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __igmp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __tcp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);

static __always_inline int __ether_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ether_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case __cpu_to_be16(ETH_P_IP):
		next = CODE_ipv4_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_IPV6):
		next = CODE_ipv6_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_8021AD):
		next = CODE_e8021AD_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_8021Q):
		next = CODE_e8021Q_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_MPLS_UC):
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_MPLS_MC):
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_ARP):
		next = CODE_arp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_RARP):
		next = CODE_rarp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_TIPC):
		next = CODE_tipc_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_BATMAN):
		next = CODE_batman_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_FCOE):
		next = CODE_fcoe_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_PPP_SES):
		next = CODE_pppoe_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ip_overlay_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ip_overlay_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case 4:
		next = CODE_ipv4_node;
		return PANDA_STOP_OKAY;
	case 6:
		next = CODE_ipv6_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ipv4_check_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv4_check_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_TCP:
		next = CODE_tcp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_SCTP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DCCP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_GRE:
		next = CODE_gre_base_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ICMP:
		next = CODE_icmpv4_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IGMP:
		next = CODE_igmp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_MPLS:
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPIP:
		next = CODE_ipv4ip_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPV6:
		next = CODE_ipv6ip_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ipv4_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv4_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_TCP:
		next = CODE_tcp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_SCTP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DCCP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_GRE:
		next = CODE_gre_base_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ICMP:
		next = CODE_icmpv4_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IGMP:
		next = CODE_igmp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_MPLS:
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPIP:
		next = CODE_ipv4ip_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPV6:
		next = CODE_ipv6ip_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ipv6_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv6_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_HOPOPTS:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ROUTING:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DSTOPTS:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_FRAGMENT:
		next = CODE_ipv6_frag_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_TCP:
		next = CODE_tcp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_SCTP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DCCP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_GRE:
		next = CODE_gre_base_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ICMPV6:
		next = CODE_icmpv6_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IGMP:
		next = CODE_igmp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_MPLS:
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPIP:
		next = CODE_ipv4ip_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPV6:
		next = CODE_ipv6ip_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ipv6_check_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv6_check_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_HOPOPTS:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ROUTING:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DSTOPTS:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_FRAGMENT:
		next = CODE_ipv6_frag_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_TCP:
		next = CODE_tcp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_SCTP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DCCP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_GRE:
		next = CODE_gre_base_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ICMPV6:
		next = CODE_icmpv6_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IGMP:
		next = CODE_igmp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_MPLS:
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPIP:
		next = CODE_ipv4ip_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPV6:
		next = CODE_ipv6ip_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ipv6_eh_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv6_eh_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_HOPOPTS:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ROUTING:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DSTOPTS:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_FRAGMENT:
		next = CODE_ipv6_frag_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_TCP:
		next = CODE_tcp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_SCTP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DCCP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_GRE:
		next = CODE_gre_base_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ICMPV6:
		next = CODE_icmpv6_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IGMP:
		next = CODE_igmp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_MPLS:
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPIP:
		next = CODE_ipv4ip_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPV6:
		next = CODE_ipv6ip_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ipv6_frag_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv6_frag_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_HOPOPTS:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ROUTING:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DSTOPTS:
		next = CODE_ipv6_eh_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_FRAGMENT:
		next = CODE_ipv6_frag_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_TCP:
		next = CODE_tcp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_SCTP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_DCCP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_GRE:
		next = CODE_gre_base_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_ICMPV6:
		next = CODE_icmpv6_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IGMP:
		next = CODE_igmp_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_MPLS:
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPIP:
		next = CODE_ipv4ip_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_IPV6:
		next = CODE_ipv6ip_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ppp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ppp_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case __cpu_to_be16(PPP_IP):
		next = CODE_ipv4_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(PPP_IPV6):
		next = CODE_ipv6_check_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __pppoe_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&pppoe_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case __cpu_to_be16(PPP_IP):
		next = CODE_ipv4_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(PPP_IPV6):
		next = CODE_ipv6_check_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __gre_base_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&gre_base_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case 0:
		next = CODE_gre_v0_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static inline __attribute__((always_inline)) int
	__gre_v0_node_panda_parse_flag_fields(
		const struct panda_parse_node *parse_node,
		const void *hdr, void *frame, struct panda_ctrl_data ctrl)
{
	const struct panda_proto_flag_fields_node *proto_flag_fields_node;
	const struct panda_flag_field *flag_fields;
	const struct panda_flag_field *flag_field;
	__u32 flags, mask;
	const __u8 *cp;

	proto_flag_fields_node =
		(struct panda_proto_flag_fields_node *)parse_node->proto_node;
	cp = (__u8 const*)hdr +
			proto_flag_fields_node->ops.start_fields_offset(hdr);
	flag_fields = proto_flag_fields_node->flag_fields->fields;
	flags = proto_flag_fields_node->ops.get_flags(hdr);

	if (flags) {
		flag_field = &flag_fields[GRE_FLAGS_CSUM_IDX];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((flags & mask) == flag_field->flag) {
			ctrl.hdr_len = flag_field->size;
			if (gre_flag_csum_node.ops.extract_metadata)
				gre_flag_csum_node.ops.extract_metadata(
						cp, frame, ctrl);
			if(gre_flag_csum_node.ops.handle_flag_field)
				gre_flag_csum_node.ops.handle_flag_field(
						cp, frame, ctrl);
			cp += flag_field->size;
			ctrl.hdr_offset += flag_field->size;
		}
		flag_field = &flag_fields[GRE_FLAGS_KEY_IDX];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((flags & mask) == flag_field->flag) {
			ctrl.hdr_len = flag_field->size;
			if (gre_flag_key_node.ops.extract_metadata)
				gre_flag_key_node.ops.extract_metadata(
						cp, frame, ctrl);
			if(gre_flag_key_node.ops.handle_flag_field)
				gre_flag_key_node.ops.handle_flag_field(
						cp, frame, ctrl);
			cp += flag_field->size;
			ctrl.hdr_offset += flag_field->size;
		}
		flag_field = &flag_fields[GRE_FLAGS_SEQ_IDX];
		mask = flag_field->mask ? flag_field->mask : flag_field->flag;
		if ((flags & mask) == flag_field->flag) {
			ctrl.hdr_len = flag_field->size;
			if (gre_flag_seq_node.ops.extract_metadata)
				gre_flag_seq_node.ops.extract_metadata(
						cp, frame, ctrl);
			if(gre_flag_seq_node.ops.handle_flag_field)
				gre_flag_seq_node.ops.handle_flag_field(
						cp, frame, ctrl);
			cp += flag_field->size;
			ctrl.hdr_offset += flag_field->size;
		}
	}
	return PANDA_OKAY;
}
static __always_inline int __gre_v0_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&gre_v0_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);


	ret = __gre_v0_node_panda_parse_flag_fields(
					parse_node, *hdr, frame, ctrl);
	if (ret != PANDA_OKAY)
		return ret;

	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case __cpu_to_be16(ETH_P_IP):
		next = CODE_ipv4_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_IPV6):
		next = CODE_ipv6_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_TEB):
		next = CODE_ether_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __e8021AD_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&e8021AD_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case __cpu_to_be16(ETH_P_IP):
		next = CODE_ipv4_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_IPV6):
		next = CODE_ipv6_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_8021AD):
		next = CODE_e8021AD_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_8021Q):
		next = CODE_e8021Q_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_MPLS_UC):
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_MPLS_MC):
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_ARP):
		next = CODE_arp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_RARP):
		next = CODE_rarp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_TIPC):
		next = CODE_tipc_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_BATMAN):
		next = CODE_batman_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_FCOE):
		next = CODE_fcoe_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_PPP_SES):
		next = CODE_pppoe_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __e8021Q_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&e8021Q_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case __cpu_to_be16(ETH_P_IP):
		next = CODE_ipv4_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_IPV6):
		next = CODE_ipv6_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_8021AD):
		next = CODE_e8021AD_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_8021Q):
		next = CODE_e8021Q_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_MPLS_UC):
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_MPLS_MC):
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_ARP):
		next = CODE_arp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_RARP):
		next = CODE_rarp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_TIPC):
		next = CODE_tipc_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_BATMAN):
		next = CODE_batman_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_FCOE):
		next = CODE_fcoe_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_PPP_SES):
		next = CODE_pppoe_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ipv4ip_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv4ip_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __ipv6ip_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv6ip_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __batman_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&batman_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*hdr += hlen;
		*offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case __cpu_to_be16(ETH_P_IP):
		next = CODE_ipv4_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_IPV6):
		next = CODE_ipv6_check_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_8021AD):
		next = CODE_e8021AD_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_8021Q):
		next = CODE_e8021Q_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_MPLS_UC):
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_MPLS_MC):
		next = CODE_mpls_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_ARP):
		next = CODE_arp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_RARP):
		next = CODE_rarp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_TIPC):
		next = CODE_tipc_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_BATMAN):
		next = CODE_batman_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_FCOE):
		next = CODE_fcoe_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_PPP_SES):
		next = CODE_pppoe_node;
		return PANDA_STOP_OKAY;
	}
	/* Unknown protocol */
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static __always_inline int __ports_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ports_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __icmpv4_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&icmpv4_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __icmpv6_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&icmpv6_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __mpls_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&mpls_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __arp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&arp_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __rarp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&rarp_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __tipc_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&tipc_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __fcoe_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&fcoe_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static __always_inline int __igmp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&igmp_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}
static inline __attribute__((always_inline)) int __tcp_node_panda_parse_tlvs(
		const struct panda_parse_node *parse_node,
		const void *hdr, void *frame, struct panda_ctrl_data ctrl)
{
	const struct panda_proto_tlvs_node *proto_tlvs_node =
		(const struct panda_proto_tlvs_node*)parse_node->proto_node;
	const struct panda_parse_tlvs_node *parse_tlvs_node =
		(const struct panda_parse_tlvs_node*)&tcp_node;
	const struct panda_parse_tlv_node *parse_tlv_node;
	const struct panda_parse_tlv_node_ops *ops;
	const __u8 *cp = hdr;
	size_t offset, len;
	ssize_t tlv_len;
	int type;

	(void)ops;

	offset = proto_tlvs_node->ops.start_offset (hdr);
	/* Assume hdr_len marks end of TLVs */
	len = ctrl.hdr_len - offset;
	cp += offset;

	while (len > 0) {
		if (proto_tlvs_node->pad1_enable &&
		    *cp == proto_tlvs_node->pad1_val) {
			/* One byte padding, just advance */
			cp++;
			ctrl.hdr_offset++;
			len--;
			continue;
		}

		if (proto_tlvs_node->eol_enable &&
		    *cp == proto_tlvs_node->eol_val) {
			cp++;
			ctrl.hdr_offset++;
			len--;
			break;
		}

		if (len < proto_tlvs_node->min_len)
			return PANDA_STOP_TLV_LENGTH;

		if (proto_tlvs_node->ops.len) {
			tlv_len = proto_tlvs_node->ops.len(cp);
			if (!tlv_len || len < tlv_len)
				return PANDA_STOP_TLV_LENGTH;
			if (tlv_len < proto_tlvs_node->min_len)
				return tlv_len < 0 ? tlv_len :
							PANDA_STOP_TLV_LENGTH;
		} else {
			tlv_len = proto_tlvs_node->min_len;
		}

		type = proto_tlvs_node->ops.type (cp);
		switch (type) {
		case TCPOPT_MSS:
		{
			int ret;
			struct panda_ctrl_data tlv_ctrl = {
					tlv_len, ctrl.hdr_offset };
			parse_tlv_node = &tcp_opt_mss_node;
			ret = panda_parse_tlv(parse_tlvs_node, parse_tlv_node,
					      cp, frame, tlv_ctrl);
			if (ret != PANDA_OKAY)
				return ret;

			break;
		}
		case TCPOPT_WINDOW:
		{
			int ret;
			struct panda_ctrl_data tlv_ctrl = {
					tlv_len, ctrl.hdr_offset };
			parse_tlv_node = &tcp_opt_window_scaling_node;
			ret = panda_parse_tlv(parse_tlvs_node, parse_tlv_node,
					      cp, frame, tlv_ctrl);
			if (ret != PANDA_OKAY)
				return ret;

			break;
		}
		case TCPOPT_TIMESTAMP:
		{
			int ret;
			struct panda_ctrl_data tlv_ctrl = {
					tlv_len, ctrl.hdr_offset };
			parse_tlv_node = &tcp_opt_timestamp_node;
			ret = panda_parse_tlv(parse_tlvs_node, parse_tlv_node,
					      cp, frame, tlv_ctrl);
			if (ret != PANDA_OKAY)
				return ret;

			break;
		}
		case TCPOPT_SACK:
		{
			int ret;
			struct panda_ctrl_data tlv_ctrl = {
					tlv_len, ctrl.hdr_offset };
			parse_tlv_node = &tcp_opt_sack_node;
			ops = &parse_tlv_node->tlv_ops;
			ret = panda_parse_tlv(parse_tlvs_node, parse_tlv_node,
					      cp, frame, tlv_ctrl);
			if (ret != PANDA_OKAY)
				return ret;

			break;
			if (ops->overlay_type)
				type = ops->overlay_type(cp);
			else
				type = tlv_ctrl.hdr_len;

			switch (type) {
			case 10:
				parse_tlv_node = &tcp_opt_sack_1;
				ret = panda_parse_tlv(parse_tlvs_node,
						      parse_tlv_node, cp,
						      frame, tlv_ctrl);
				if (ret != PANDA_OKAY)
					return ret;
				break;
			case 18:
				parse_tlv_node = &tcp_opt_sack_2;
				ret = panda_parse_tlv(parse_tlvs_node,
						      parse_tlv_node, cp,
						      frame, tlv_ctrl);
				if (ret != PANDA_OKAY)
					return ret;
				break;
			case 26:
				parse_tlv_node = &tcp_opt_sack_3;
				ret = panda_parse_tlv(parse_tlvs_node,
						      parse_tlv_node, cp,
						      frame, tlv_ctrl);
				if (ret != PANDA_OKAY)
					return ret;
				break;
			case 34:
				parse_tlv_node = &tcp_opt_sack_4;
				ret = panda_parse_tlv(parse_tlvs_node,
						      parse_tlv_node, cp,
						      frame, tlv_ctrl);
				if (ret != PANDA_OKAY)
					return ret;
				break;
			default:
				break;
			 }

			break;
		}
		default:
		{
			struct panda_ctrl_data tlv_ctrl =
						{ tlv_len, ctrl.hdr_offset };

			if (parse_tlvs_node->tlv_wildcard_node)
				return panda_parse_tlv(parse_tlvs_node,
						       parse_tlvs_node->
							    tlv_wildcard_node,
						       cp, frame, tlv_ctrl);
			else if (parse_tlvs_node->unknown_tlv_type_ret != PANDA_OKAY)
				return parse_tlvs_node->unknown_tlv_type_ret;
		}
		}

		/* Move over current header */
		cp += tlv_len;
		ctrl.hdr_offset += tlv_len;
		len -= tlv_len;
	}
	return PANDA_OKAY;
}
static __always_inline int __tcp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&tcp_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);

	ret = __tcp_node_panda_parse_tlvs(parse_node, *hdr, frame, ctrl);
	if (ret != PANDA_OKAY)
		return ret;


	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;
}

static inline int panda_parser_big_ether_panda_parse_ether_node(
		const struct panda_parser *parser,
		const void *hdr, size_t len,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps)
{
	void *frame = metadata->frame_data;
	unsigned int frame_num = 0;
	int ret = PANDA_STOP_OKAY;
	int i;
	size_t offset;

	ret = __ether_node_panda_parse(parser, &hdr,
		len, &offset, metadata, flags, max_encaps, frame, frame_num);

	for (i = 0; i < PANDA_LOOP_COUNT; i++) {
		if (ret != PANDA_STOP_OKAY)
			break;
		switch (next) {
		case CODE_IGNORE:
			break;
		case CODE_ether_node:
			ret = __ether_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ip_overlay_node:
			ret = __ip_overlay_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ipv4_check_node:
			ret = __ipv4_check_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ipv4_node:
			ret = __ipv4_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ipv6_node:
			ret = __ipv6_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ipv6_check_node:
			ret = __ipv6_check_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ipv6_eh_node:
			ret = __ipv6_eh_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ipv6_frag_node:
			ret = __ipv6_frag_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ppp_node:
			ret = __ppp_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_pppoe_node:
			ret = __pppoe_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_gre_base_node:
			ret = __gre_base_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_gre_v0_node:
			ret = __gre_v0_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_e8021AD_node:
			ret = __e8021AD_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_e8021Q_node:
			ret = __e8021Q_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ipv4ip_node:
			ret = __ipv4ip_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ipv6ip_node:
			ret = __ipv6ip_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_batman_node:
			ret = __batman_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_ports_node:
			ret = __ports_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_icmpv4_node:
			ret = __icmpv4_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_icmpv6_node:
			ret = __icmpv6_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_mpls_node:
			ret = __mpls_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_arp_node:
			ret = __arp_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_rarp_node:
			ret = __rarp_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_tipc_node:
			ret = __tipc_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_fcoe_node:
			ret = __fcoe_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_igmp_node:
			ret = __igmp_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		case CODE_tcp_node:
			ret = __tcp_node_panda_parse(parser, &hdr, len, &offset,
						     metadata, flags,
						     max_encaps, frame,
						     frame_num);
			break;
		default:
			return PANDA_STOP_UNKNOWN_PROTO;
		}
	}

	return ret;
}

PANDA_PARSER_KMOD(
      panda_parser_big_ether,
      "",
      &ether_node,
      panda_parser_big_ether_panda_parse_ether_node
    );

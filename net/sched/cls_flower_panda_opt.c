
// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2020, 2021 by Mojatatu Networks.
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

#include "net/panda/parser.h"
#include "net/panda/parser_metadata.h"
#include "net/panda/proto_nodes_def.h"

#include "cls_flower_panda_noopt.c"

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
CODE_e8021AD_node,
CODE_e8021Q_node,
CODE_ipv4ip_node,
CODE_ipv6ip_node,
CODE_ports_node,
CODE_icmpv4_node,
CODE_icmpv6_node,
CODE_arp_node,
CODE_rarp_node,
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
static __always_inline int __arp_node_panda_parse(const struct panda_parser *parser,
		const void **hdr, size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static __always_inline int __rarp_node_panda_parse(const struct panda_parser *parser,
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
	case __cpu_to_be16(ETH_P_ARP):
		next = CODE_arp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_RARP):
		next = CODE_rarp_node;
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
	case IPPROTO_ICMP:
		next = CODE_icmpv4_node;
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
	case IPPROTO_ICMP:
		next = CODE_icmpv4_node;
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
	case IPPROTO_ICMPV6:
		next = CODE_icmpv6_node;
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
	case IPPROTO_ICMPV6:
		next = CODE_icmpv6_node;
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
	case IPPROTO_ICMPV6:
		next = CODE_icmpv6_node;
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
	case IPPROTO_ICMPV6:
		next = CODE_icmpv6_node;
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
	case __cpu_to_be16(ETH_P_ARP):
		next = CODE_arp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_RARP):
		next = CODE_rarp_node;
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
	case __cpu_to_be16(ETH_P_ARP):
		next = CODE_arp_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_RARP):
		next = CODE_rarp_node;
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

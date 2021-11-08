
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "panda/parser.h"
#include "panda/proto_nodes_def.h"
#include "simpleparser.c"

static inline __attribute__((always_inline)) int check_pkt_len(const void* hdr,
		const struct panda_proto_node *pnode, size_t len, ssize_t* hlen)
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
		struct panda_metadata *metadata, unsigned max_encaps,
		void **frame, unsigned *frame_num)
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
static inline __attribute__((always_inline)) int panda_parse_wildcard_tlv(
		const struct panda_parse_tlvs_node *parse_node,
		const struct panda_parse_tlv_node *wildcard_parse_tlv_node,
		const __u8 *cp, void *frame, struct panda_ctrl_data tlv_ctrl) {
	const struct panda_parse_tlv_node_ops *ops =
					&wildcard_parse_tlv_node->tlv_ops;
	const struct panda_proto_tlv_node *proto_tlv_node =
					wildcard_parse_tlv_node->proto_tlv_node;

	if (proto_tlv_node && (tlv_ctrl.hdr_len < proto_tlv_node->min_len))
		return parse_node->unknown_tlv_type_ret;

	if (ops->extract_metadata)
		ops->extract_metadata(cp, frame, tlv_ctrl);

	if (ops->handle_tlv)
		ops->handle_tlv(cp, frame, tlv_ctrl);

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
			return panda_parse_wildcard_tlv(parse_node,
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
static inline int __ether_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static inline int __ipv4_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static inline int __ipv6_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static inline int __ipv6_check_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static inline int __ipv6_eh_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static inline int __ipv6_frag_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static inline int __ports_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num);
static inline int __ether_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node*)&ether_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto (hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		hdr += hlen;
		offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case __cpu_to_be16(ETH_P_IP):
		return __ipv4_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case __cpu_to_be16(ETH_P_IPV6):
		return __ipv6_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	}
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static inline int __ipv4_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node*)&ipv4_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto (hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		hdr += hlen;
		offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_TCP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_UDP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	}
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static inline int __ipv6_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node*)&ipv6_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto (hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		hdr += hlen;
		offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_HOPOPTS:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_ROUTING:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_DSTOPTS:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_FRAGMENT:
		return __ipv6_frag_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_TCP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_UDP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	}
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static inline int __ipv6_check_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node*)&ipv6_check_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto (hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		hdr += hlen;
		offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_HOPOPTS:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_ROUTING:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_DSTOPTS:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_FRAGMENT:
		return __ipv6_frag_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_TCP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_UDP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	}
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static inline int __ipv6_eh_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node*)&ipv6_eh_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto (hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		hdr += hlen;
		offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_HOPOPTS:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_ROUTING:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_DSTOPTS:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_FRAGMENT:
		return __ipv6_frag_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_TCP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_UDP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	}
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static inline int __ipv6_frag_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node*)&ipv6_frag_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto (hdr);

	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		hdr += hlen;
		offset += hlen;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_HOPOPTS:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_ROUTING:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_DSTOPTS:
		return __ipv6_eh_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_FRAGMENT:
		return __ipv6_frag_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_TCP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	case IPPROTO_UDP:
		return __ports_node_panda_parse(
			parser, hdr, len, offset, metadata, flags, max_encaps,
			frame, frame_num);
	}
	return PANDA_STOP_UNKNOWN_PROTO;
	}
}
static inline int __ports_node_panda_parse(const struct panda_parser *parser,
		const void *hdr, size_t len, size_t offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node*)&ports_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;

	ret = check_pkt_len(hdr, parse_node->proto_node, len, &hlen);
	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = offset;

	if (parse_node->ops.extract_metadata)
		parse_node->ops.extract_metadata(hdr, frame, ctrl);



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}


	return PANDA_STOP_OKAY;
}
static inline int panda_parser_big_ether_panda_parse_ether_node(
		const struct panda_parser *parser,
		const void *hdr, size_t len,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps)
{
	void *frame = metadata->frame_data;
	unsigned frame_num = 0;

	return __ether_node_panda_parse(parser, hdr,
		len, 0, metadata, flags, max_encaps, frame, frame_num);
}
PANDA_PARSER_OPT_EXT(
      panda_parser_big_ether_opt,
      "",
      &ether_node,
      panda_parser_big_ether_panda_parse_ether_node
    );

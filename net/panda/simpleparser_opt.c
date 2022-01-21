// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2020, 2021 by Mojatatu Networks.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permittedq provided that the following conditions
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

#include "simpleparser.c"

#ifndef PANDA_LOOP_COUNT
#define PANDA_LOOP_COUNT 8
#endif

#define MIN_STATIC_HDR_SIZE 8
#define PANDA_MAX_ENCAPS (PANDA_LOOP_COUNT + 32)
enum {
CODE_ether_node,
CODE_ipv4_node,
CODE_ipv6_node,
CODE_ipv6_check_node,
CODE_ipv6_eh_node,
CODE_ipv6_frag_node,
CODE_ports_node,
CODE_IGNORE
};

/* Parser control */
static long next = CODE_IGNORE;

static inline __attribute__((always_inline)) int check_pkt_len(const u8 *hdr,
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




static __always_inline int __ether_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read);
__attribute__((unused)) static int
	__ether_node_panda_parse(const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned int frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	return __ether_node_panda_parse_impl(parser, hdr, len, offset, metadata,
					   flags, max_encaps, frame, frame_num, skb, usr_hdr_buf, usr_hdr_buf_len, last_read);
}
static __always_inline int __ipv4_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read);
__attribute__((unused)) static int
	__ipv4_node_panda_parse(const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned int frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	return __ipv4_node_panda_parse_impl(parser, hdr, len, offset, metadata,
					   flags, max_encaps, frame, frame_num, skb, usr_hdr_buf, usr_hdr_buf_len, last_read);
}
static __always_inline int __ipv6_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read);
__attribute__((unused)) static int
	__ipv6_node_panda_parse(const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned int frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	return __ipv6_node_panda_parse_impl(parser, hdr, len, offset, metadata,
					   flags, max_encaps, frame, frame_num, skb, usr_hdr_buf, usr_hdr_buf_len, last_read);
}
static __always_inline int __ipv6_check_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read);
__attribute__((unused)) static int
	__ipv6_check_node_panda_parse(const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned int frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	return __ipv6_check_node_panda_parse_impl(parser, hdr, len, offset, metadata,
					   flags, max_encaps, frame, frame_num, skb, usr_hdr_buf, usr_hdr_buf_len, last_read);
}
static __always_inline int __ipv6_eh_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read);
__attribute__((unused)) static int
	__ipv6_eh_node_panda_parse(const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned int frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	return __ipv6_eh_node_panda_parse_impl(parser, hdr, len, offset, metadata,
					   flags, max_encaps, frame, frame_num, skb, usr_hdr_buf, usr_hdr_buf_len, last_read);
}
static __always_inline int __ipv6_frag_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read);
__attribute__((unused)) static int
	__ipv6_frag_node_panda_parse(const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned int frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	return __ipv6_frag_node_panda_parse_impl(parser, hdr, len, offset, metadata,
					   flags, max_encaps, frame, frame_num, skb, usr_hdr_buf, usr_hdr_buf_len, last_read);
}
static __always_inline int __ports_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read);
__attribute__((unused)) static int
	__ports_node_panda_parse(const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata, unsigned int flags,
		unsigned int max_encaps, void *frame, unsigned int frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	return __ports_node_panda_parse_impl(parser, hdr, len, offset, metadata,
					   flags, max_encaps, frame, frame_num, skb, usr_hdr_buf, usr_hdr_buf_len, last_read);
}

static __always_inline int __ether_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ether_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;
	*hdr = eth_hdr(skb);

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);

	if (ret != PANDA_OKAY)
		return ret;

	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata){
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);
	}



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);
	pr_debug("ether_node type 0x%x",type);
	if (type < 0)
		return type;


	switch (type) {
	case __cpu_to_be16(ETH_P_IP):
		next = CODE_ipv4_node;
		return PANDA_STOP_OKAY;
	case __cpu_to_be16(ETH_P_IPV6):
		next = CODE_ipv6_node;
		return PANDA_STOP_OKAY;
	}

	/* Unknown protocol */

	return PANDA_STOP_UNKNOWN_PROTO;
	}

}
static __always_inline int __ipv4_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv4_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;
	void *scratch_buf, *mem;
	ssize_t scratch_buf_len;
	ssize_t pktbuf_len = skb->len;
	ssize_t min_hdr_len = proto_node->min_len;
	//this will not happend
	if (*offset > pktbuf_len)
		return PANDA_STOP_LENGTH;
	if (pktbuf_len - *offset < min_hdr_len)
		return PANDA_STOP_LENGTH;

	//check if it has been read enough to fit the protocol
	if (*last_read - *offset < min_hdr_len){
		if (*usr_hdr_buf_len < min_hdr_len){
			scratch_buf = kmalloc(min_hdr_len, GFP_KERNEL);
			if (scratch_buf == NULL) {
				pr_err("kmalloc failed");
				return PANDA_STOP_FAIL; 
			}
			scratch_buf_len = min_hdr_len;
			//use new temporary buffer for another protocols
			*usr_hdr_buf = scratch_buf;
			*usr_hdr_buf_len = scratch_buf_len;	
		} else {
			scratch_buf = *usr_hdr_buf;
			scratch_buf_len = *usr_hdr_buf_len;
		}
		//check if chunk exceeds skbuff length
		if(*offset + *usr_hdr_buf_len < pktbuf_len){
			*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
			*last_read = *offset + *usr_hdr_buf_len;
		} else{
			*hdr = skb_header_pointer(skb, *offset, pktbuf_len - *offset, scratch_buf);
			*last_read = pktbuf_len;
		}
		if (hdr == NULL) { // This should not happen
			pr_err("failure at read skbuff");
			return PANDA_STOP_FAIL;
		}
	}	
	hlen = min_hdr_len;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);

	if (ret != PANDA_OKAY)
		return ret;
	//check if protocol lenght changed
	if(hlen > min_hdr_len){
		//check if it has been read enough to fit the protocol
		if (*last_read - *offset < hlen){
			if (scratch_buf_len < hlen) {
				mem = krealloc(scratch_buf, hlen, GFP_KERNEL);
				if (mem == NULL) {
					pr_err("realloc failed");
					if (scratch_buf != *usr_hdr_buf)
						kfree(scratch_buf);
					return PANDA_STOP_FAIL;
				}
				scratch_buf = mem;
				scratch_buf_len = hlen;
				//use new temporary buffer for another protocols
				*usr_hdr_buf = scratch_buf;
				*usr_hdr_buf_len = scratch_buf_len;
			}
			//check if chunk exceeds skbuff length
			if (*offset + *usr_hdr_buf_len < pktbuf_len){
				*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
				*last_read = *offset + *usr_hdr_buf_len;
			} else{
				*hdr = skb_header_pointer(skb, *offset, pktbuf_len, scratch_buf);
				*last_read = *offset + min_hdr_len;
			}
			if (hdr == NULL) { // This should not happen
				if (scratch_buf != *usr_hdr_buf)
					kfree(scratch_buf);
				return PANDA_STOP_FAIL;
			}
		}
	}


	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata){
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);
	}



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);
	pr_debug("ipv4_node type 0x%x",type);
	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*offset += hlen;
		*hdr += *offset;
		len -= hlen;
	}

	switch (type) {
	case IPPROTO_TCP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	}

	/* Unknown protocol */

	return PANDA_STOP_UNKNOWN_PROTO;
	}

}
static __always_inline int __ipv6_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv6_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;
	void *scratch_buf, *mem;
	ssize_t scratch_buf_len;
	ssize_t pktbuf_len = skb->len;
	ssize_t min_hdr_len = proto_node->min_len;
	//this will not happend
	if (*offset > pktbuf_len)
		return PANDA_STOP_LENGTH;
	if (pktbuf_len - *offset < min_hdr_len)
		return PANDA_STOP_LENGTH;

	//check if it has been read enough to fit the protocol
	if (*last_read - *offset < min_hdr_len){
		if (*usr_hdr_buf_len < min_hdr_len){
			scratch_buf = kmalloc(min_hdr_len, GFP_KERNEL);
			if (scratch_buf == NULL) {
				pr_err("kmalloc failed");
				return PANDA_STOP_FAIL; 
			}
			scratch_buf_len = min_hdr_len;
			//use new temporary buffer for another protocols
			*usr_hdr_buf = scratch_buf;
			*usr_hdr_buf_len = scratch_buf_len;	
		} else {
			scratch_buf = *usr_hdr_buf;
			scratch_buf_len = *usr_hdr_buf_len;
		}
		//check if chunk exceeds skbuff length
		if(*offset + *usr_hdr_buf_len < pktbuf_len){
			*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
			*last_read = *offset + *usr_hdr_buf_len;
		} else{
			*hdr = skb_header_pointer(skb, *offset, pktbuf_len - *offset, scratch_buf);
			*last_read = pktbuf_len;
		}
		if (hdr == NULL) { // This should not happen
			pr_err("failure at read skbuff");
			return PANDA_STOP_FAIL;
		}
	}	
	hlen = min_hdr_len;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);

	if (ret != PANDA_OKAY)
		return ret;
	//check if protocol lenght changed
	if(hlen > min_hdr_len){
		//check if it has been read enough to fit the protocol
		if (*last_read - *offset < hlen){
			if (scratch_buf_len < hlen) {
				mem = krealloc(scratch_buf, hlen, GFP_KERNEL);
				if (mem == NULL) {
					pr_err("realloc failed");
					if (scratch_buf != *usr_hdr_buf)
						kfree(scratch_buf);
					return PANDA_STOP_FAIL;
				}
				scratch_buf = mem;
				scratch_buf_len = hlen;
				//use new temporary buffer for another protocols
				*usr_hdr_buf = scratch_buf;
				*usr_hdr_buf_len = scratch_buf_len;
			}
			//check if chunk exceeds skbuff length
			if (*offset + *usr_hdr_buf_len < pktbuf_len){
				*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
				*last_read = *offset + *usr_hdr_buf_len;
			} else{
				*hdr = skb_header_pointer(skb, *offset, pktbuf_len, scratch_buf);
				*last_read = *offset + min_hdr_len;
			}
			if (hdr == NULL) { // This should not happen
				if (scratch_buf != *usr_hdr_buf)
					kfree(scratch_buf);
				return PANDA_STOP_FAIL;
			}
		}
	}


	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata){
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);
	}



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);
	pr_debug("ipv6_node type 0x%x",type);
	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*offset += hlen;
		*hdr += *offset;
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
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	}

	/* Unknown protocol */

	return PANDA_STOP_UNKNOWN_PROTO;
	}

}
static __always_inline int __ipv6_check_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv6_check_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;
	void *scratch_buf, *mem;
	ssize_t scratch_buf_len;
	ssize_t pktbuf_len = skb->len;
	ssize_t min_hdr_len = proto_node->min_len;
	//this will not happend
	if (*offset > pktbuf_len)
		return PANDA_STOP_LENGTH;
	if (pktbuf_len - *offset < min_hdr_len)
		return PANDA_STOP_LENGTH;

	//check if it has been read enough to fit the protocol
	if (*last_read - *offset < min_hdr_len){
		if (*usr_hdr_buf_len < min_hdr_len){
			scratch_buf = kmalloc(min_hdr_len, GFP_KERNEL);
			if (scratch_buf == NULL) {
				pr_err("kmalloc failed");
				return PANDA_STOP_FAIL; 
			}
			scratch_buf_len = min_hdr_len;
			//use new temporary buffer for another protocols
			*usr_hdr_buf = scratch_buf;
			*usr_hdr_buf_len = scratch_buf_len;	
		} else {
			scratch_buf = *usr_hdr_buf;
			scratch_buf_len = *usr_hdr_buf_len;
		}
		//check if chunk exceeds skbuff length
		if(*offset + *usr_hdr_buf_len < pktbuf_len){
			*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
			*last_read = *offset + *usr_hdr_buf_len;
		} else{
			*hdr = skb_header_pointer(skb, *offset, pktbuf_len - *offset, scratch_buf);
			*last_read = pktbuf_len;
		}
		if (hdr == NULL) { // This should not happen
			pr_err("failure at read skbuff");
			return PANDA_STOP_FAIL;
		}
	}	
	hlen = min_hdr_len;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);

	if (ret != PANDA_OKAY)
		return ret;
	//check if protocol lenght changed
	if(hlen > min_hdr_len){
		//check if it has been read enough to fit the protocol
		if (*last_read - *offset < hlen){
			if (scratch_buf_len < hlen) {
				mem = krealloc(scratch_buf, hlen, GFP_KERNEL);
				if (mem == NULL) {
					pr_err("realloc failed");
					if (scratch_buf != *usr_hdr_buf)
						kfree(scratch_buf);
					return PANDA_STOP_FAIL;
				}
				scratch_buf = mem;
				scratch_buf_len = hlen;
				//use new temporary buffer for another protocols
				*usr_hdr_buf = scratch_buf;
				*usr_hdr_buf_len = scratch_buf_len;
			}
			//check if chunk exceeds skbuff length
			if (*offset + *usr_hdr_buf_len < pktbuf_len){
				*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
				*last_read = *offset + *usr_hdr_buf_len;
			} else{
				*hdr = skb_header_pointer(skb, *offset, pktbuf_len, scratch_buf);
				*last_read = *offset + min_hdr_len;
			}
			if (hdr == NULL) { // This should not happen
				if (scratch_buf != *usr_hdr_buf)
					kfree(scratch_buf);
				return PANDA_STOP_FAIL;
			}
		}
	}


	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata){
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);
	}



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);
	pr_debug("ipv6_check_node type 0x%x",type);
	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*offset += hlen;
		*hdr += *offset;
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
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	}

	/* Unknown protocol */

	return PANDA_STOP_UNKNOWN_PROTO;
	}

}
static __always_inline int __ipv6_eh_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv6_eh_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;
	void *scratch_buf, *mem;
	ssize_t scratch_buf_len;
	ssize_t pktbuf_len = skb->len;
	ssize_t min_hdr_len = proto_node->min_len;
	//this will not happend
	if (*offset > pktbuf_len)
		return PANDA_STOP_LENGTH;
	if (pktbuf_len - *offset < min_hdr_len)
		return PANDA_STOP_LENGTH;

	//check if it has been read enough to fit the protocol
	if (*last_read - *offset < min_hdr_len){
		if (*usr_hdr_buf_len < min_hdr_len){
			scratch_buf = kmalloc(min_hdr_len, GFP_KERNEL);
			if (scratch_buf == NULL) {
				pr_err("kmalloc failed");
				return PANDA_STOP_FAIL; 
			}
			scratch_buf_len = min_hdr_len;
			//use new temporary buffer for another protocols
			*usr_hdr_buf = scratch_buf;
			*usr_hdr_buf_len = scratch_buf_len;	
		} else {
			scratch_buf = *usr_hdr_buf;
			scratch_buf_len = *usr_hdr_buf_len;
		}
		//check if chunk exceeds skbuff length
		if(*offset + *usr_hdr_buf_len < pktbuf_len){
			*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
			*last_read = *offset + *usr_hdr_buf_len;
		} else{
			*hdr = skb_header_pointer(skb, *offset, pktbuf_len - *offset, scratch_buf);
			*last_read = pktbuf_len;
		}
		if (hdr == NULL) { // This should not happen
			pr_err("failure at read skbuff");
			return PANDA_STOP_FAIL;
		}
	}	
	hlen = min_hdr_len;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);

	if (ret != PANDA_OKAY)
		return ret;
	//check if protocol lenght changed
	if(hlen > min_hdr_len){
		//check if it has been read enough to fit the protocol
		if (*last_read - *offset < hlen){
			if (scratch_buf_len < hlen) {
				mem = krealloc(scratch_buf, hlen, GFP_KERNEL);
				if (mem == NULL) {
					pr_err("realloc failed");
					if (scratch_buf != *usr_hdr_buf)
						kfree(scratch_buf);
					return PANDA_STOP_FAIL;
				}
				scratch_buf = mem;
				scratch_buf_len = hlen;
				//use new temporary buffer for another protocols
				*usr_hdr_buf = scratch_buf;
				*usr_hdr_buf_len = scratch_buf_len;
			}
			//check if chunk exceeds skbuff length
			if (*offset + *usr_hdr_buf_len < pktbuf_len){
				*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
				*last_read = *offset + *usr_hdr_buf_len;
			} else{
				*hdr = skb_header_pointer(skb, *offset, pktbuf_len, scratch_buf);
				*last_read = *offset + min_hdr_len;
			}
			if (hdr == NULL) { // This should not happen
				if (scratch_buf != *usr_hdr_buf)
					kfree(scratch_buf);
				return PANDA_STOP_FAIL;
			}
		}
	}


	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata){
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);
	}



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);
	pr_debug("ipv6_eh_node type 0x%x",type);
	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*offset += hlen;
		*hdr += *offset;
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
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	}

	/* Unknown protocol */

	return PANDA_STOP_UNKNOWN_PROTO;
	}

}
static __always_inline int __ipv6_frag_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ipv6_frag_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;
	void *scratch_buf, *mem;
	ssize_t scratch_buf_len;
	ssize_t pktbuf_len = skb->len;
	ssize_t min_hdr_len = proto_node->min_len;
	//this will not happend
	if (*offset > pktbuf_len)
		return PANDA_STOP_LENGTH;
	if (pktbuf_len - *offset < min_hdr_len)
		return PANDA_STOP_LENGTH;

	//check if it has been read enough to fit the protocol
	if (*last_read - *offset < min_hdr_len){
		if (*usr_hdr_buf_len < min_hdr_len){
			scratch_buf = kmalloc(min_hdr_len, GFP_KERNEL);
			if (scratch_buf == NULL) {
				pr_err("kmalloc failed");
				return PANDA_STOP_FAIL; 
			}
			scratch_buf_len = min_hdr_len;
			//use new temporary buffer for another protocols
			*usr_hdr_buf = scratch_buf;
			*usr_hdr_buf_len = scratch_buf_len;	
		} else {
			scratch_buf = *usr_hdr_buf;
			scratch_buf_len = *usr_hdr_buf_len;
		}
		//check if chunk exceeds skbuff length
		if(*offset + *usr_hdr_buf_len < pktbuf_len){
			*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
			*last_read = *offset + *usr_hdr_buf_len;
		} else{
			*hdr = skb_header_pointer(skb, *offset, pktbuf_len - *offset, scratch_buf);
			*last_read = pktbuf_len;
		}
		if (hdr == NULL) { // This should not happen
			pr_err("failure at read skbuff");
			return PANDA_STOP_FAIL;
		}
	}	
	hlen = min_hdr_len;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);

	if (ret != PANDA_OKAY)
		return ret;
	//check if protocol lenght changed
	if(hlen > min_hdr_len){
		//check if it has been read enough to fit the protocol
		if (*last_read - *offset < hlen){
			if (scratch_buf_len < hlen) {
				mem = krealloc(scratch_buf, hlen, GFP_KERNEL);
				if (mem == NULL) {
					pr_err("realloc failed");
					if (scratch_buf != *usr_hdr_buf)
						kfree(scratch_buf);
					return PANDA_STOP_FAIL;
				}
				scratch_buf = mem;
				scratch_buf_len = hlen;
				//use new temporary buffer for another protocols
				*usr_hdr_buf = scratch_buf;
				*usr_hdr_buf_len = scratch_buf_len;
			}
			//check if chunk exceeds skbuff length
			if (*offset + *usr_hdr_buf_len < pktbuf_len){
				*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
				*last_read = *offset + *usr_hdr_buf_len;
			} else{
				*hdr = skb_header_pointer(skb, *offset, pktbuf_len, scratch_buf);
				*last_read = *offset + min_hdr_len;
			}
			if (hdr == NULL) { // This should not happen
				if (scratch_buf != *usr_hdr_buf)
					kfree(scratch_buf);
				return PANDA_STOP_FAIL;
			}
		}
	}


	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata){
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);
	}



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	{
	int type = proto_node->ops.next_proto(*hdr);
	pr_debug("ipv6_frag_node type 0x%x",type);
	if (type < 0)
		return type;

	if (!proto_node->overlay) {
		*offset += hlen;
		*hdr += *offset;
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
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	case IPPROTO_UDP:
		next = CODE_ports_node;
		return PANDA_STOP_OKAY;
	}

	/* Unknown protocol */

	return PANDA_STOP_UNKNOWN_PROTO;
	}

}
static __always_inline int __ports_node_panda_parse_impl(
		const struct panda_parser *parser, const void **hdr,
		size_t len, size_t *offset,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps,
		void *frame, unsigned frame_num, struct sk_buff *skb,
		void **usr_hdr_buf, size_t *usr_hdr_buf_len, size_t *last_read)
{
	const struct panda_parse_node *parse_node =
		(const struct panda_parse_node *)&ports_node;
	const struct panda_proto_node *proto_node = parse_node->proto_node;
	struct panda_ctrl_data ctrl;
	ssize_t hlen;
	int ret;
	void *scratch_buf, *mem;
	ssize_t scratch_buf_len;
	ssize_t pktbuf_len = skb->len;
	ssize_t min_hdr_len = proto_node->min_len;
	//this will not happend
	if (*offset > pktbuf_len)
		return PANDA_STOP_LENGTH;
	if (pktbuf_len - *offset < min_hdr_len)
		return PANDA_STOP_LENGTH;

	//check if it has been read enough to fit the protocol
	if (*last_read - *offset < min_hdr_len){
		if (*usr_hdr_buf_len < min_hdr_len){
			scratch_buf = kmalloc(min_hdr_len, GFP_KERNEL);
			if (scratch_buf == NULL) {
				pr_err("kmalloc failed");
				return PANDA_STOP_FAIL; 
			}
			scratch_buf_len = min_hdr_len;
			//use new temporary buffer for another protocols
			*usr_hdr_buf = scratch_buf;
			*usr_hdr_buf_len = scratch_buf_len;	
		} else {
			scratch_buf = *usr_hdr_buf;
			scratch_buf_len = *usr_hdr_buf_len;
		}
		//check if chunk exceeds skbuff length
		if(*offset + *usr_hdr_buf_len < pktbuf_len){
			*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
			*last_read = *offset + *usr_hdr_buf_len;
		} else{
			*hdr = skb_header_pointer(skb, *offset, pktbuf_len - *offset, scratch_buf);
			*last_read = pktbuf_len;
		}
		if (hdr == NULL) { // This should not happen
			pr_err("failure at read skbuff");
			return PANDA_STOP_FAIL;
		}
	}	
	hlen = min_hdr_len;

	ret = check_pkt_len(*hdr, parse_node->proto_node, len, &hlen);

	if (ret != PANDA_OKAY)
		return ret;
	//check if protocol lenght changed
	if(hlen > min_hdr_len){
		//check if it has been read enough to fit the protocol
		if (*last_read - *offset < hlen){
			if (scratch_buf_len < hlen) {
				mem = krealloc(scratch_buf, hlen, GFP_KERNEL);
				if (mem == NULL) {
					pr_err("realloc failed");
					if (scratch_buf != *usr_hdr_buf)
						kfree(scratch_buf);
					return PANDA_STOP_FAIL;
				}
				scratch_buf = mem;
				scratch_buf_len = hlen;
				//use new temporary buffer for another protocols
				*usr_hdr_buf = scratch_buf;
				*usr_hdr_buf_len = scratch_buf_len;
			}
			//check if chunk exceeds skbuff length
			if (*offset + *usr_hdr_buf_len < pktbuf_len){
				*hdr = skb_header_pointer(skb, *offset, *usr_hdr_buf_len, scratch_buf);
				*last_read = *offset + *usr_hdr_buf_len;
			} else{
				*hdr = skb_header_pointer(skb, *offset, pktbuf_len, scratch_buf);
				*last_read = *offset + min_hdr_len;
			}
			if (hdr == NULL) { // This should not happen
				if (scratch_buf != *usr_hdr_buf)
					kfree(scratch_buf);
				return PANDA_STOP_FAIL;
			}
		}
	}


	ctrl.hdr_len = hlen;
	ctrl.hdr_offset = *offset;

	if (parse_node->ops.extract_metadata){
		parse_node->ops.extract_metadata(*hdr, frame, ctrl);
	}



	if (proto_node->encap) {
		ret = panda_encap_layer(metadata, max_encaps, &frame,
					&frame_num);
		if (ret != PANDA_OKAY)
			return ret;
	}

	next = CODE_IGNORE;
	return PANDA_STOP_OKAY;

}

static inline int panda_parser_simple_ether_panda_parse_ether_node(
		const struct panda_parser *parser, const void *hdr,
		size_t len,
		struct panda_metadata *metadata,
		unsigned int flags, unsigned int max_encaps)
{
	void *frame = metadata->frame_data;
	unsigned int frame_num = 0;
	int ret = PANDA_STOP_OKAY;
	int i;
	size_t last_read = 0;
	size_t offset = 0;
	struct sk_buff *skb = (struct sk_buff*)hdr;
	u8 buff[MIN_STATIC_HDR_SIZE];
	void *usr_hdr_buf = buff;
	ssize_t usr_hdr_buf_len = sizeof(buff);	

	ret = __ether_node_panda_parse_impl(parser, &hdr,
		len, &offset, metadata, flags, max_encaps, frame, frame_num, skb, &usr_hdr_buf, &usr_hdr_buf_len, &last_read);

	for (i = 0; i < PANDA_LOOP_COUNT; i++) {
		if (ret != PANDA_STOP_OKAY)
			break;
		switch (next) {
		case CODE_IGNORE:
			break;
		case CODE_ether_node:
			pr_debug("parsing ether_node");
			ret = __ether_node_panda_parse_impl(parser, &hdr, len,
							  &offset, metadata,
							  flags, max_encaps,
							  frame, frame_num, skb, &usr_hdr_buf, &usr_hdr_buf_len, &last_read);
			break;
		case CODE_ipv4_node:
			pr_debug("parsing ipv4_node");
			ret = __ipv4_node_panda_parse_impl(parser, &hdr, len,
							  &offset, metadata,
							  flags, max_encaps,
							  frame, frame_num, skb, &usr_hdr_buf, &usr_hdr_buf_len, &last_read);
			break;
		case CODE_ipv6_node:
			pr_debug("parsing ipv6_node");
			ret = __ipv6_node_panda_parse_impl(parser, &hdr, len,
							  &offset, metadata,
							  flags, max_encaps,
							  frame, frame_num, skb, &usr_hdr_buf, &usr_hdr_buf_len, &last_read);
			break;
		case CODE_ipv6_check_node:
			pr_debug("parsing ipv6_check_node");
			ret = __ipv6_check_node_panda_parse_impl(parser, &hdr, len,
							  &offset, metadata,
							  flags, max_encaps,
							  frame, frame_num, skb, &usr_hdr_buf, &usr_hdr_buf_len, &last_read);
			break;
		case CODE_ipv6_eh_node:
			pr_debug("parsing ipv6_eh_node");
			ret = __ipv6_eh_node_panda_parse_impl(parser, &hdr, len,
							  &offset, metadata,
							  flags, max_encaps,
							  frame, frame_num, skb, &usr_hdr_buf, &usr_hdr_buf_len, &last_read);
			break;
		case CODE_ipv6_frag_node:
			pr_debug("parsing ipv6_frag_node");
			ret = __ipv6_frag_node_panda_parse_impl(parser, &hdr, len,
							  &offset, metadata,
							  flags, max_encaps,
							  frame, frame_num, skb, &usr_hdr_buf, &usr_hdr_buf_len, &last_read);
			break;
		case CODE_ports_node:
			pr_debug("parsing ports_node");
			ret = __ports_node_panda_parse_impl(parser, &hdr, len,
							  &offset, metadata,
							  flags, max_encaps,
							  frame, frame_num, skb, &usr_hdr_buf, &usr_hdr_buf_len, &last_read);
			break;
		default:
			if(usr_hdr_buf_len > MIN_STATIC_HDR_SIZE)
				kfree(usr_hdr_buf);
			return PANDA_STOP_UNKNOWN_PROTO;
		}
	}
	if(usr_hdr_buf_len > MIN_STATIC_HDR_SIZE)
		kfree(usr_hdr_buf);
	return ret;
}

PANDA_PARSER_KMOD(
	panda_parser_simple_ether,
	"", 
	 &ether_node, 
	panda_parser_simple_ether_panda_parse_ether_node
);
EXPORT_SYMBOL(PANDA_PARSER_KMOD_NAME(panda_parser_simple_ether));

static int __init panda_init(void)
{
       pr_debug("Initializing panda_parser_simple_ether\n");
       return 0;
}

static void __exit panda_exit(void)
{
      pr_debug("Panda module exiting panda_parser_simple_ether\n");
}

module_init(panda_init);
module_exit(panda_exit);

MODULE_AUTHOR("Tom Herbert <tom@expertise.dev>");
MODULE_DESCRIPTION("PANDA parser panda_parser_simple_ether");
MODULE_LICENSE("GPL v2");


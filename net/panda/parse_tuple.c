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
#include <net/panda/parser.h>

PANDA_PARSER_KMOD_EXTERN(panda_parser_simple_ether);

struct panda_tuple {
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

/* Meta data structure for just one frame */
struct panda_parser_big_metadata_one {
	struct panda_metadata panda_data;
	struct panda_tuple frame;
};

int panda_parse_tuple(struct sk_buff *skb, void *frame)
{
	int err;
	struct panda_parser_big_metadata_one mdata;
	size_t pktlen;

	memset(&mdata, 0, sizeof(mdata.panda_data));
	memcpy(&mdata.frame, frame, sizeof(struct panda_tuple));

	WARN_ON(skb->data_len);

	pktlen = skb_mac_header_len(skb) + skb->len;
	pr_err("parsing tuple!");
	err = panda_parse(PANDA_PARSER_KMOD_NAME(panda_parser_simple_ether), skb,
			  pktlen, &mdata.panda_data, 0, 1);

	if (err != PANDA_STOP_OKAY) {
		pr_err("Failed to parse packet! (%d)", err);
		return -1;
	}

	memcpy(frame, &mdata.frame, sizeof(struct panda_tuple));

return 0;
}
EXPORT_SYMBOL(panda_parse_tuple);


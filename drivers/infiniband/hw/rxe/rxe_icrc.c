/*
 * Copyright (c) 2009-2011 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2009-2011 System Fabric Works, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "rxe.h"
#include "rxe_loc.h"

/* Compute a partial ICRC for all the IB transport headers. */
u32 rxe_icrc_hdr(struct rxe_pkt_info *pkt)
{
	u32 crc;
	unsigned int length;
	unsigned int grh_offset;
	unsigned int bth_offset;
	u8 tmp[RXE_LRH_BYTES + RXE_GRH_BYTES + RXE_BTH_BYTES];

	/* This seed is the result of computing a CRC with a seed of
	 * 0xfffffff and 8 bytes of 0xff representing a masked LRH. */
	crc = 0xdebb20e3;

	length = RXE_BTH_BYTES;
	grh_offset = 0;
	bth_offset = 0;

	if (pkt->mask & RXE_LRH_MASK) {
		length += RXE_LRH_BYTES;
		grh_offset += RXE_LRH_BYTES;
		bth_offset += RXE_LRH_BYTES;
	}
	if (pkt->mask & RXE_GRH_MASK) {
		length += RXE_GRH_BYTES;
		bth_offset += RXE_GRH_BYTES;
	}

	memcpy(tmp, pkt->hdr, length);

	if (pkt->mask & RXE_GRH_MASK) {
		tmp[grh_offset + 0] |= 0x0f;	/* GRH: tclass */
		tmp[grh_offset + 1] = 0xff;
		tmp[grh_offset + 2] = 0xff;
		tmp[grh_offset + 3] = 0xff;
		tmp[grh_offset + 7] = 0xff;
	}

	tmp[bth_offset + 4] = 0xff;		/* BTH: resv8a */

	crc = crc32_le(crc, tmp + grh_offset, length - grh_offset);

	/* And finish to compute the CRC on the remainder of the headers. */
	crc = crc32_le(crc, pkt->hdr + length,
		       rxe_opcode[pkt->opcode].length - RXE_BTH_BYTES);

	return crc;
}

/* Compute the ICRC for a packet (incoming or outgoing). */
u32 rxe_icrc_pkt(struct rxe_pkt_info *pkt)
{
	u32 crc;
	int size;

	crc = rxe_icrc_hdr(pkt);

	/* And finish to compute the CRC on the remainder. */
	size = pkt->paylen - rxe_opcode[pkt->opcode].length - RXE_ICRC_SIZE;
	crc = crc32_le(crc, payload_addr(pkt), size);
	crc = ~crc;

	return crc;
}

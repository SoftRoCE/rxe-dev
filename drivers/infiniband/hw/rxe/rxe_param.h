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

#ifndef RXE_PARAM_H
#define RXE_PARAM_H

enum rxe_mtu {
	RXE_MTU_INVALID = 0,
	RXE_MTU_256	= 1,
	RXE_MTU_512	= 2,
	RXE_MTU_1024	= 3,
	RXE_MTU_2048	= 4,
	RXE_MTU_4096	= 5,
	RXE_MTU_8192	= 6,
};

static inline int rxe_mtu_enum_to_int(enum rxe_mtu mtu)
{
	switch (mtu) {
	case RXE_MTU_256:	return	256;
	case RXE_MTU_512:	return	512;
	case RXE_MTU_1024:	return	1024;
	case RXE_MTU_2048:	return	2048;
	case RXE_MTU_4096:	return	4096;
	case RXE_MTU_8192:	return	8192;
	default:		return	-1;
	}
}

static inline enum rxe_mtu rxe_mtu_int_to_enum(int mtu)
{
	if (mtu < 256)
		return 0;
	else if (mtu < 512)
		return RXE_MTU_256;
	else if (mtu < 1024)
		return RXE_MTU_512;
	else if (mtu < 2048)
		return RXE_MTU_1024;
	else if (mtu < 4096)
		return RXE_MTU_2048;
	else if (mtu < 8192)
		return RXE_MTU_4096;
	else
		return RXE_MTU_8192;
}

/* Find the IB mtu for a given network MTU. */
static inline enum rxe_mtu eth_mtu_int_to_enum(int mtu)
{
	mtu -= RXE_MAX_HDR_LENGTH;

	return rxe_mtu_int_to_enum(mtu);
}

/*
 * default/initial rxe device parameter settings
 */
enum rxe_device_param {
	RXE_FW_VER			= 0,
	RXE_MAX_MR_SIZE			= -1ull,
	RXE_PAGE_SIZE_CAP		= 0xfffff000,
	RXE_VENDOR_ID			= 0,
	RXE_VENDOR_PART_ID		= 0,
	RXE_HW_VER			= 0,
	RXE_MAX_QP			= 0x10000,
	RXE_MAX_QP_WR			= 0x4000,
	RXE_MAX_INLINE_DATA		= 400,
	RXE_DEVICE_CAP_FLAGS		= IB_DEVICE_BAD_PKEY_CNTR
					| IB_DEVICE_BAD_QKEY_CNTR
					| IB_DEVICE_AUTO_PATH_MIG
					| IB_DEVICE_CHANGE_PHY_PORT
					| IB_DEVICE_UD_AV_PORT_ENFORCE
					| IB_DEVICE_PORT_ACTIVE_EVENT
					| IB_DEVICE_SYS_IMAGE_GUID
					| IB_DEVICE_RC_RNR_NAK_GEN
					| IB_DEVICE_SRQ_RESIZE,
	RXE_MAX_SGE			= 27,
	RXE_MAX_SGE_RD			= 0,
	RXE_MAX_CQ			= 16384,
	RXE_MAX_LOG_CQE			= 13,
	RXE_MAX_MR			= 2*1024,
	RXE_MAX_PD			= 0x7ffc,
	RXE_MAX_QP_RD_ATOM		= 128,
	RXE_MAX_EE_RD_ATOM		= 0,
	RXE_MAX_RES_RD_ATOM		= 0x3f000,
	RXE_MAX_QP_INIT_RD_ATOM		= 128,
	RXE_MAX_EE_INIT_RD_ATOM		= 0,
	RXE_ATOMIC_CAP			= 1,
	RXE_MAX_EE			= 0,
	RXE_MAX_RDD			= 0,
	RXE_MAX_MW			= 0,
	RXE_MAX_RAW_IPV6_QP		= 0,
	RXE_MAX_RAW_ETHY_QP		= 0,
	RXE_MAX_MCAST_GRP		= 8192,
	RXE_MAX_MCAST_QP_ATTACH		= 56,
	RXE_MAX_TOT_MCAST_QP_ATTACH	= 0x70000,
	RXE_MAX_AH			= 100,
	RXE_MAX_FMR			= 2*1024,
	RXE_MAX_MAP_PER_FMR		= 100,
	RXE_MAX_SRQ			= 960,
	RXE_MAX_SRQ_WR			= 0x4000,
	RXE_MIN_SRQ_WR			= 1,
	RXE_MAX_SRQ_SGE			= 27,
	RXE_MIN_SRQ_SGE			= 1,
	RXE_MAX_FMR_PAGE_LIST_LEN	= 0,
	RXE_MAX_PKEYS			= 64,
	RXE_LOCAL_CA_ACK_DELAY		= 15,

	RXE_MAX_UCONTEXT		= 128,

	RXE_NUM_PORT			= 1,
	RXE_NUM_COMP_VECTORS		= 1,

	RXE_MIN_QP_INDEX		= 16,
	RXE_MAX_QP_INDEX		= 0x00020000,

	RXE_MIN_SRQ_INDEX		= 0x00020001,
	RXE_MAX_SRQ_INDEX		= 0x00040000,

	RXE_MIN_MR_INDEX		= 0x00000001,
	RXE_MAX_MR_INDEX		= 0x00020000,
	RXE_MIN_FMR_INDEX		= 0x00020001,
	RXE_MAX_FMR_INDEX		= 0x00040000,
	RXE_MIN_MW_INDEX		= 0x00040001,
	RXE_MAX_MW_INDEX		= 0x00060000,
};

/*
 * default/initial rxe port parameters
 */
enum rxe_port_param {
	RXE_PORT_STATE			= IB_PORT_DOWN,
	RXE_PORT_MAX_MTU		= RXE_MTU_4096,
	RXE_PORT_ACTIVE_MTU		= RXE_MTU_256,
	RXE_PORT_GID_TBL_LEN		= 32,
	RXE_PORT_PORT_CAP_FLAGS		= 0,
	RXE_PORT_MAX_MSG_SZ		= 0x800000,
	RXE_PORT_BAD_PKEY_CNTR		= 0,
	RXE_PORT_QKEY_VIOL_CNTR		= 0,
	RXE_PORT_LID			= 0,
	RXE_PORT_SM_LID			= 0,
	RXE_PORT_SM_SL			= 0,
	RXE_PORT_LMC			= 0,
	RXE_PORT_MAX_VL_NUM		= 1,
	RXE_PORT_SUBNET_TIMEOUT		= 0,
	RXE_PORT_INIT_TYPE_REPLY	= 0,
	RXE_PORT_ACTIVE_WIDTH		= IB_WIDTH_1X,
	RXE_PORT_ACTIVE_SPEED		= 1,
	RXE_PORT_PKEY_TBL_LEN		= 64,
	RXE_PORT_PHYS_STATE		= 2,
	RXE_PORT_SUBNET_PREFIX		= 0xfe80000000000000ULL,
	RXE_PORT_CC_TBL_LEN		= 128,
	RXE_PORT_CC_TIMER		= 1024,
	RXE_PORT_CC_INCREASE		= 1,
	RXE_PORT_CC_THRESHOLD		= 64,
	RXE_PORT_CC_CCTI_MIN		= 0,
};

/*
 * default/initial port info parameters
 */
enum rxe_port_info_param {
	RXE_PORT_INFO_VL_CAP		= 4,	/* 1-8 */
	RXE_PORT_INFO_MTU_CAP		= 5,	/* 4096 */
	RXE_PORT_INFO_OPER_VL		= 1,	/* 1 */
};

extern int rxe_debug_flags;
extern int rxe_crc_disable;
extern int rxe_nsec_per_packet;
extern int rxe_nsec_per_kbyte;
extern int rxe_max_skb_per_qp;
extern int rxe_max_req_comp_gap;
extern int rxe_max_pkt_per_ack;
extern int rxe_default_mtu;
extern int rxe_fast_comp;
extern int rxe_fast_resp;
extern int rxe_fast_req;
extern int rxe_fast_arb;

#endif /* RXE_PARAM_H */

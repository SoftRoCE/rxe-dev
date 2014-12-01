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

#include <linux/skbuff.h>

#include "rxe.h"
#include "rxe_loc.h"

static int check_type_state(struct rxe_dev *rxe, struct rxe_pkt_info *pkt,
			    struct rxe_qp *qp)
{
	if (unlikely(!qp->valid))
		goto err1;

	switch (qp_type(qp)) {
	case IB_QPT_RC:
		if (unlikely((pkt->opcode >> 5) != 0)) {
			pr_warn("bad qp type\n");
			goto err1;
		}
		break;
	case IB_QPT_UC:
		if (unlikely((pkt->opcode >> 5) != 1)) {
			pr_warn("bad qp type\n");
			goto err1;
		}
		break;
	case IB_QPT_UD:
	case IB_QPT_SMI:
	case IB_QPT_GSI:
		if (unlikely((pkt->opcode >> 5) != 3)) {
			pr_warn("bad qp type\n");
			goto err1;
		}
		break;
	default:
		pr_warn("unsupported qp type\n");
		goto err1;
	}

	if (pkt->mask & RXE_REQ_MASK) {
		if (unlikely(qp->resp.state != QP_STATE_READY))
			goto err1;
	} else if (unlikely(qp->req.state < QP_STATE_READY ||
			qp->req.state > QP_STATE_DRAINED))
			goto err1;

	return 0;

err1:
	return -EINVAL;
}

static int check_keys(struct rxe_dev *rxe, struct rxe_pkt_info *pkt,
		      u32 qpn, struct rxe_qp *qp)
{
	int i;
	int found_pkey = 0;
	struct rxe_port *port = &rxe->port[pkt->port_num - 1];
	u16 pkey = bth_pkey(pkt);

	pkt->pkey_index = 0;

	if (qpn == 1) {
		for (i = 0; i < port->attr.pkey_tbl_len; i++) {
			if (pkey_match(pkey, port->pkey_tbl[i])) {
				pkt->pkey_index = i;
				found_pkey = 1;
				break;
			}
		}

		if (!found_pkey) {
			pr_warn("bad pkey = 0x%x\n", pkey);
			spin_lock_bh(&port->port_lock);
			port->attr.bad_pkey_cntr
				= (port->attr.bad_pkey_cntr >= 0xffff) ?
				   0xffff :
				   port->attr.bad_pkey_cntr + 1;
			spin_unlock_bh(&port->port_lock);
			goto err1;
		}
	} else if (qpn != 0) {
		if (unlikely(!pkey_match(pkey,
					 port->pkey_tbl[qp->attr.pkey_index]
					))) {
			pr_warn("bad pkey = 0x%0x\n", pkey);
			spin_lock_bh(&port->port_lock);
			port->attr.bad_pkey_cntr
				= (port->attr.bad_pkey_cntr >= 0xffff) ?
				   0xffff :
				   port->attr.bad_pkey_cntr + 1;
			spin_unlock_bh(&port->port_lock);
			goto err1;
		}
		pkt->pkey_index = qp->attr.pkey_index;
	}

	if (qp_type(qp) == IB_QPT_UD && qpn != 0 && pkt->mask) {
		u32 qkey = (qpn == 1) ? GSI_QKEY : qp->attr.qkey;

		if (unlikely(deth_qkey(pkt) != qkey)) {
			pr_warn("bad qkey, got 0x%x expected 0x%x\n",
				deth_qkey(pkt), qkey);
			spin_lock_bh(&port->port_lock);
			port->attr.qkey_viol_cntr
				= (port->attr.qkey_viol_cntr >= 0xffff) ?
				   0xffff :
				   port->attr.qkey_viol_cntr + 1;
			spin_unlock_bh(&port->port_lock);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

static int check_addr(struct rxe_dev *rxe, struct rxe_pkt_info *pkt,
		      struct rxe_qp *qp)
{
	struct rxe_port *port = &rxe->port[pkt->port_num - 1];
	union ib_gid *sgid;
	union ib_gid *dgid;

	if (qp_type(qp) != IB_QPT_RC && qp_type(qp) != IB_QPT_UC)
		goto done;

	if (unlikely(pkt->port_num != qp->attr.port_num)) {
		pr_warn("port %d != qp port %d\n",
			pkt->port_num, qp->attr.port_num);
		goto err1;
	}

	if ((pkt->mask & RXE_GRH_MASK) == 0) {
		if (unlikely(qp->pri_av.attr.ah_flags & IB_AH_GRH)) {
			pr_warn("no grh for global qp\n");
			goto err1;
		} else {
			goto done;
		}
	}

	sgid = grh_sgid(pkt);
	dgid = grh_dgid(pkt);

	if (unlikely((qp->pri_av.attr.ah_flags & IB_AH_GRH) == 0)) {
		pr_warn("grh for local qp\n");
		goto err1;
	}

	if (unlikely(dgid->global.subnet_prefix == 0 &&
		     be64_to_cpu(dgid->global.interface_id) <= 1)) {
		pr_warn("bad dgid, subnet_prefix = 0\n");
		goto err1;
	}

	if (unlikely(sgid->raw[0] == 0xff)) {
		pr_warn("bad sgid, multicast gid\n");
		goto err1;
	}

	if (unlikely(sgid->global.subnet_prefix == 0 &&
		     be64_to_cpu(sgid->global.interface_id) <= 1)) {
		pr_warn("bad sgid, subnet prefix = 0 or 1\n");
		goto err1;
	}

	if (unlikely(dgid->global.interface_id !=
	    port->guid_tbl[qp->pri_av.attr.grh.sgid_index])) {
		pr_warn("bad dgid, doesn't match qp\n");
		goto err1;
	}

	if (unlikely(sgid->global.interface_id !=
	    qp->pri_av.attr.grh.dgid.global.interface_id)) {
		pr_warn("bad sgid, doesn't match qp\n");
		goto err1;
	}
done:
	return 0;

err1:
	return -EINVAL;
}

static int hdr_check(struct rxe_pkt_info *pkt)
{
	struct rxe_dev *rxe = pkt->rxe;
	struct rxe_port *port = &rxe->port[pkt->port_num - 1];
	struct rxe_qp *qp = NULL;
	union ib_gid *dgid = NULL;
	u32 qpn = bth_qpn(pkt);
	int index;
	int err;

	if (unlikely(bth_tver(pkt) != BTH_TVER)) {
		pr_warn("bad tver\n");
		goto err1;
	}

	if (qpn != IB_MULTICAST_QPN) {
		index = (qpn == 0) ? port->qp_smi_index :
			((qpn == 1) ? port->qp_gsi_index : qpn);
		qp = rxe_pool_get_index(&rxe->qp_pool, index);
		if (unlikely(!qp)) {
			pr_warn("no qp matches qpn 0x%x\n", qpn);
			goto err1;
		}

		err = check_type_state(rxe, pkt, qp);
		if (unlikely(err))
			goto err2;
	}

	if (pkt->mask & RXE_GRH_MASK) {
		dgid = grh_dgid(pkt);

		if (unlikely(grh_next_hdr(pkt) != GRH_RXE_NEXT_HDR)) {
			pr_warn("bad next hdr\n");
			goto err2;
		}

		if (unlikely(grh_ipver(pkt) != GRH_IPV6)) {
			pr_warn("bad ipver\n");
			goto err2;
		}
	}

	if (qpn != IB_MULTICAST_QPN) {
		err = check_addr(rxe, pkt, qp);
		if (unlikely(err))
			goto err2;

		err = check_keys(rxe, pkt, qpn, qp);
		if (unlikely(err))
			goto err2;
	} else {
		if (unlikely((pkt->mask & RXE_GRH_MASK) == 0)) {
			pr_warn("no grh for mcast qpn\n");
			goto err1;
		}
		if (unlikely(dgid->raw[0] != 0xff)) {
			pr_warn("bad dgid for mcast qpn\n");
			goto err1;
		}
	}

	pkt->qp = qp;
	return 0;

err2:
	if (qp)
		rxe_drop_ref(qp);
err1:
	return -EINVAL;
}

static inline void rxe_rcv_pkt(struct rxe_dev *rxe,
			       struct rxe_pkt_info *pkt,
			       struct sk_buff *skb)
{
	if (pkt->mask & RXE_REQ_MASK)
		rxe_resp_queue_pkt(rxe, pkt->qp, skb);
	else
		rxe_comp_queue_pkt(rxe, pkt->qp, skb);
}

static void rxe_rcv_mcast_pkt(struct rxe_dev *rxe, struct sk_buff *skb)
{
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	struct rxe_mc_grp *mcg;
	struct list_head *l;
	struct sk_buff *skb_copy;
	struct rxe_mc_elem *mce;
	struct rxe_qp *qp;
	int err;

	/* lookup mcast group corresponding to mgid, takes a ref */
	mcg = rxe_pool_get_key(&rxe->mc_grp_pool, grh_dgid(pkt));
	if (!mcg)
		goto err1;	/* mcast group not registered */

	spin_lock_bh(&mcg->mcg_lock);

	list_for_each(l, &mcg->qp_list) {
		mce = container_of(l, struct rxe_mc_elem, qp_list);
		qp = mce->qp;
		pkt = SKB_TO_PKT(skb);

		/* validate qp for incoming packet */
		err = check_type_state(rxe, pkt, qp);
		if (err)
			continue;

		err = check_keys(rxe, pkt, bth_qpn(pkt), qp);
		if (err)
			continue;

		/* if *not* the last qp in the list
		   make a copy of the skb to post to the next qp */
		skb_copy = (l->next != &mcg->qp_list) ?
				skb_clone(skb, GFP_KERNEL) : NULL;

		pkt->qp = qp;
		rxe_add_ref(qp);
		rxe_rcv_pkt(rxe, pkt, skb);

		skb = skb_copy;
		if (!skb)
			break;
	}

	spin_unlock_bh(&mcg->mcg_lock);

	rxe_drop_ref(mcg);	/* drop ref from rxe_pool_get_key. */

err1:
	if (skb)
		kfree_skb(skb);
}

/* rxe_rcv is called from the interface driver
 * on entry
 *	pkt->rxe	= rdma device
 *	pkt->port_num	= rdma device port
 * For rxe_net:
 *	pkt->mask	= RXE_GRH_MASK
 *	pkt->hdr	= &grh	with no lrh
 * For IB transport (e.g. rxe_sample)
 *	pkt->mask	= RXE_LRH_MASK
 *	pkt->hdr	= &lrh with optional grh
 */
int rxe_rcv(struct sk_buff *skb)
{
	int err;
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	struct rxe_dev *rxe = pkt->rxe;

	pkt->offset = 0;

	if (pkt->mask & RXE_LRH_MASK) {
		unsigned int length = __lrh_length(pkt->hdr);
		unsigned int lnh = __lrh_lnh(pkt->hdr);

		if (skb->len < RXE_LRH_BYTES)
			goto drop;

		if (lnh < LRH_LNH_IBA_LOC)
			goto drop;

		pkt->paylen = 4*length - RXE_LRH_BYTES;
		pkt->offset += RXE_LRH_BYTES;

		if (lnh == LRH_LNH_IBA_GBL)
			pkt->mask |= RXE_GRH_MASK;
	}

	if (pkt->mask & RXE_GRH_MASK) {
		if (skb->len < pkt->offset + RXE_GRH_BYTES)
			goto drop;

		pkt->paylen = __grh_paylen(pkt->hdr);
		pkt->offset += RXE_GRH_BYTES;
	}

	if (unlikely(skb->len < pkt->offset + RXE_BTH_BYTES))
		goto drop;

	pkt->opcode = bth_opcode(pkt);
	pkt->psn = bth_psn(pkt);
	pkt->qp = NULL;
	pkt->mask |= rxe_opcode[pkt->opcode].mask;

	if (unlikely(skb->len < header_size(pkt)))
		goto drop;

	err = hdr_check(pkt);
	if (unlikely(err))
		goto drop;

	if (unlikely(bth_qpn(pkt) == IB_MULTICAST_QPN))
		rxe_rcv_mcast_pkt(rxe, skb);
	else
		rxe_rcv_pkt(rxe, pkt, skb);

	return 0;

drop:
	if (pkt->qp)
		rxe_drop_ref(pkt->qp);

	kfree_skb(skb);
	return 0;
}
EXPORT_SYMBOL(rxe_rcv);

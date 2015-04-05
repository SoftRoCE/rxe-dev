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

static inline void account_skb(struct rxe_dev *rxe, struct rxe_qp *qp,
			       int is_request)
{
	if (is_request & RXE_REQ_MASK) {
		atomic_dec(&rxe->req_skb_out);
		atomic_dec(&qp->req_skb_out);
		if (qp->need_req_skb) {
			if (atomic_read(&qp->req_skb_out) <
					RXE_MAX_INFLIGHT_SKBS_PER_QP)
				rxe_run_task(&qp->req.task, 1);
		}
	} else {
		atomic_dec(&rxe->resp_skb_out);
		atomic_dec(&qp->resp_skb_out);
	}
}

static int xmit_one_packet(struct rxe_dev *rxe, struct rxe_qp *qp,
			   struct sk_buff *skb)
{
	int err;
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	int is_request = pkt->mask & RXE_REQ_MASK;

	/* drop pkt if qp is in wrong state to send */
	if (!qp->valid)
		goto drop;

	if (is_request) {
		if (qp->req.state != QP_STATE_READY)
			goto drop;
	} else {
		if (qp->resp.state != QP_STATE_READY)
			goto drop;
	}

	if (pkt->mask & RXE_LOOPBACK_MASK)
		err = rxe->ifc_ops->loopback(skb);
	else
		err = rxe->ifc_ops->send(rxe, skb);

	if (err) {
		rxe->xmit_errors++;
		return err;
	}

	goto done;

drop:
	kfree_skb(skb);
	err = 0;
done:
	account_skb(rxe, qp, is_request);
	return err;
}

/*
 * choose one packet for sending
 */
int rxe_arbiter(void *arg)
{
	int err;
	unsigned long flags;
	struct rxe_dev *rxe = (struct rxe_dev *)arg;
	struct sk_buff *skb;
	struct list_head *qpl;
	struct rxe_qp *qp;

	/* get the next qp's send queue */
	spin_lock_irqsave(&rxe->arbiter.list_lock, flags);
	if (list_empty(&rxe->arbiter.qp_list)) {
		spin_unlock_irqrestore(&rxe->arbiter.list_lock, flags);
		return 1;
	}

	qpl = rxe->arbiter.qp_list.next;
	list_del_init(qpl);
	qp = list_entry(qpl, struct rxe_qp, arbiter_list);
	spin_unlock_irqrestore(&rxe->arbiter.list_lock, flags);

	/* get next packet from queue and try to send it
	   note skb could have already been removed */
	skb = skb_dequeue(&qp->send_pkts);
	if (skb) {
		err = xmit_one_packet(rxe, qp, skb);
		if (err) {
			skb_queue_head(&qp->send_pkts, skb);
			rxe_run_task(&rxe->arbiter.task, 1);
			return 1;
		}
	}

	/* if more work in queue put qp back on the list */
	spin_lock_irqsave(&rxe->arbiter.list_lock, flags);

	if (list_empty(qpl) && !skb_queue_empty(&qp->send_pkts))
		list_add_tail(qpl, &rxe->arbiter.qp_list);

	if (skb)
		rxe->arbiter.skb_count--;

	if (rxe->arbiter.skb_count &&
	    !timer_pending(&rxe->arbiter.timer))
		mod_timer(&rxe->arbiter.timer,
			  jiffies +
			  nsecs_to_jiffies(RXE_NSEC_ARB_TIMER_DELAY));

	spin_unlock_irqrestore(&rxe->arbiter.list_lock, flags);

	return 0;
}

/*
 * queue a packet for sending from a qp
 */
void arbiter_skb_queue(struct rxe_dev *rxe, struct rxe_qp *qp,
		       struct sk_buff *skb)
{
	unsigned long flags;

	/* add packet to send queue */
	skb_queue_tail(&qp->send_pkts, skb);

	/* if not already there add qp to arbiter list */
	spin_lock_irqsave(&rxe->arbiter.list_lock, flags);
	if (list_empty(&qp->arbiter_list))
		list_add_tail(&qp->arbiter_list, &rxe->arbiter.qp_list);

	if (rxe->arbiter.skb_count)
		rxe->arbiter.skb_count++;
	else {
		rxe->arbiter.skb_count++;
		rxe_run_task(&rxe->arbiter.task, 1);
	}

	spin_unlock_irqrestore(&rxe->arbiter.list_lock, flags);
}

void rxe_arbiter_timer(unsigned long arg)
{
	struct rxe_dev *rxe = (struct rxe_dev *)arg;

	rxe_run_task(&rxe->arbiter.task, 0);
}

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
#include "rxe_queue.h"

static int rxe_query_device(struct ib_device *dev, struct ib_device_attr *attr)
{
	struct rxe_dev *rxe = to_rdev(dev);

	*attr = rxe->attr;
	return 0;
}

static int rxe_query_port(struct ib_device *dev,
			  u8 port_num, struct ib_port_attr *attr)
{
	struct rxe_dev *rxe = to_rdev(dev);
	struct rxe_port *port;

	if (unlikely(port_num < 1 || port_num > rxe->num_ports)) {
		pr_warn("invalid port_number %d\n", port_num);
		goto err1;
	}

	port = &rxe->port[port_num - 1];

	*attr = port->attr;
	return 0;

err1:
	return -EINVAL;
}

union ib_gid zgid;

static int rxe_query_gid(struct ib_device *device,
			 u8 port_num, int index, union ib_gid *gid)
{
	int ret;

	if (index > RXE_PORT_GID_TBL_LEN)
		return -EINVAL;

	ret = ib_get_cached_gid(device, port_num, index, gid, NULL);
	if (ret == -EAGAIN) {
		memcpy(gid, &zgid, sizeof(*gid));
		return 0;
	}

	return ret;
}

static struct net_device *rxe_get_netdev(struct ib_device *device,
						 u8 port_num)
{
	struct rxe_dev *rxe = to_rdev(device);

	if (rxe->ndev)
		return rxe->ndev;

	return NULL;
}

static int rxe_modify_gid(struct ib_device *device,
			  u8 port_num, unsigned int index,
			  const union ib_gid *gid,
			  const struct ib_gid_attr *attr,
			  void **context)
{
	return 0;
}

static int rxe_query_pkey(struct ib_device *device,
			  u8 port_num, u16 index, u16 *pkey)
{
	struct rxe_dev *rxe = to_rdev(device);
	struct rxe_port *port;

	if (unlikely(port_num < 1 || port_num > rxe->num_ports)) {
		pr_warn("invalid port_num = %d\n", port_num);
		goto err1;
	}

	port = &rxe->port[port_num - 1];

	if (unlikely(index >= port->attr.pkey_tbl_len)) {
		pr_warn("invalid index = %d\n", index);
		goto err1;
	}

	*pkey = port->pkey_tbl[index];
	return 0;

err1:
	return -EINVAL;
}

static int rxe_modify_device(struct ib_device *dev,
			     int mask, struct ib_device_modify *attr)
{
	struct rxe_dev *rxe = to_rdev(dev);

	if (mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID)
		rxe->attr.sys_image_guid = cpu_to_be64(attr->sys_image_guid);

	if (mask & IB_DEVICE_MODIFY_NODE_DESC) {
		memcpy(rxe->ib_dev.node_desc,
		       attr->node_desc, sizeof(rxe->ib_dev.node_desc));
	}

	return 0;
}

static int rxe_modify_port(struct ib_device *dev,
			   u8 port_num, int mask, struct ib_port_modify *attr)
{
	struct rxe_dev *rxe = to_rdev(dev);
	struct rxe_port *port;

	if (unlikely(port_num < 1 || port_num > rxe->num_ports)) {
		pr_warn("invalid port_num = %d\n", port_num);
		goto err1;
	}

	port = &rxe->port[port_num - 1];

	port->attr.port_cap_flags |= attr->set_port_cap_mask;
	port->attr.port_cap_flags &= ~attr->clr_port_cap_mask;

	if (mask & IB_PORT_RESET_QKEY_CNTR)
		port->attr.qkey_viol_cntr = 0;

	if (mask & IB_PORT_INIT_TYPE)
		/* TODO init type */
		;

	if (mask & IB_PORT_SHUTDOWN)
		/* TODO shutdown port */
		;

	return 0;

err1:
	return -EINVAL;
}

static enum rdma_link_layer rxe_get_link_layer(struct ib_device *dev,
					       u8 port_num)
{
	struct rxe_dev *rxe = to_rdev(dev);

	return rxe->ifc_ops->link_layer(rxe, port_num);
}

static struct ib_ucontext *rxe_alloc_ucontext(struct ib_device *dev,
					      struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(dev);
	struct rxe_ucontext *uc;

	uc = rxe_alloc(&rxe->uc_pool);
	return uc ? &uc->ibuc : ERR_PTR(-ENOMEM);
}

static int rxe_dealloc_ucontext(struct ib_ucontext *ibuc)
{
	struct rxe_ucontext *uc = to_ruc(ibuc);

	rxe_drop_ref(uc);
	return 0;
}

static struct ib_pd *rxe_alloc_pd(struct ib_device *dev,
				  struct ib_ucontext *context,
				  struct ib_udata *udata)
{
	struct rxe_dev *rxe = to_rdev(dev);
	struct rxe_pd *pd;

	pd = rxe_alloc(&rxe->pd_pool);
	return pd ? &pd->ibpd : ERR_PTR(-ENOMEM);
}

static int rxe_dealloc_pd(struct ib_pd *ibpd)
{
	struct rxe_pd *pd = to_rpd(ibpd);

	rxe_drop_ref(pd);
	return 0;
}

static struct ib_ah *rxe_create_ah(struct ib_pd *ibpd, struct ib_ah_attr *attr)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_ah *ah;
	union ib_gid sgid;
	struct ib_gid_attr sgid_attr;

	err = rxe_av_chk_attr(rxe, attr);
	if (err)
		goto err1;

	ah = rxe_alloc(&rxe->ah_pool);
	if (!ah) {
		err = -ENOMEM;
		goto err1;
	}

	rxe_add_ref(pd);
	ah->pd = pd;

	rcu_read_lock();
	err = ib_get_cached_gid(&rxe->ib_dev, attr->port_num,
				attr->grh.sgid_index, &sgid,
				&sgid_attr);
	if (err) {
		pr_err("Failed to query sgid. err = %d\n", err);
		rcu_read_unlock();
		goto err2;
	}
	rcu_read_unlock();

	err = rxe_av_from_attr(rxe, attr->port_num, &ah->av, attr);
	if (err)
		goto err2;

	ah->av.network_type = ib_gid_to_network_type(sgid_attr.gid_type, &sgid);
	err = rxe_av_fill_ip_info(rxe, &ah->av, attr, &sgid);
	if (err)
		goto err2;

	return &ah->ibah;

err2:
	rxe_drop_ref(pd);
	rxe_drop_ref(ah);
err1:
	return ERR_PTR(err);
}

static int rxe_modify_ah(struct ib_ah *ibah, struct ib_ah_attr *attr)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibah->device);
	struct rxe_ah *ah = to_rah(ibah);
	union ib_gid sgid;
	struct ib_gid_attr sgid_attr;

	err = rxe_av_chk_attr(rxe, attr);
	if (err)
		goto err1;

	rcu_read_lock();
	err = ib_get_cached_gid(&rxe->ib_dev, attr->port_num,
				attr->grh.sgid_index, &sgid,
				&sgid_attr);
	if (err) {
		pr_err("Failed to query sgid. err = %d\n", err);
		rcu_read_unlock();
		goto err1;
	}
	rcu_read_unlock();

	err = rxe_av_from_attr(rxe, attr->port_num, &ah->av, attr);
	if (err)
		goto err1;

	ah->av.network_type = ib_gid_to_network_type(sgid_attr.gid_type, &sgid);
	err = rxe_av_fill_ip_info(rxe, &ah->av, attr, &sgid);
err1:
	return err;
}

static int rxe_query_ah(struct ib_ah *ibah, struct ib_ah_attr *attr)
{
	struct rxe_dev *rxe = to_rdev(ibah->device);
	struct rxe_ah *ah = to_rah(ibah);

	rxe_av_to_attr(rxe, &ah->av, attr);
	return 0;
}

static int rxe_destroy_ah(struct ib_ah *ibah)
{
	struct rxe_ah *ah = to_rah(ibah);

	rxe_drop_ref(ah->pd);
	rxe_drop_ref(ah);
	return 0;
}

static int post_one_recv(struct rxe_rq *rq, struct ib_recv_wr *ibwr)
{
	int err;
	int i;
	u32 length;
	struct rxe_recv_wqe *recv_wqe;
	int num_sge = ibwr->num_sge;

	if (unlikely(queue_full(rq->queue))) {
		err = -ENOMEM;
		goto err1;
	}

	if (unlikely(num_sge > rq->max_sge)) {
		err = -EINVAL;
		goto err1;
	}

	length = 0;
	for (i = 0; i < num_sge; i++)
		length += ibwr->sg_list[i].length;

	recv_wqe = producer_addr(rq->queue);
	recv_wqe->wr_id = ibwr->wr_id;
	recv_wqe->num_sge = num_sge;

	memcpy(recv_wqe->dma.sge, ibwr->sg_list,
	       num_sge*sizeof(struct ib_sge));

	recv_wqe->dma.length		= length;
	recv_wqe->dma.resid		= length;
	recv_wqe->dma.num_sge		= num_sge;
	recv_wqe->dma.cur_sge		= 0;
	recv_wqe->dma.sge_offset	= 0;

	/* make sure all changes to the work queue are
	   written before we update the producer pointer */
	wmb();

	advance_producer(rq->queue);
	return 0;

err1:
	return err;
}

static struct ib_srq *rxe_create_srq(struct ib_pd *ibpd,
				     struct ib_srq_init_attr *init,
				     struct ib_udata *udata)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_srq *srq;
	struct ib_ucontext *context = udata ? ibpd->uobject->context : NULL;

	err = rxe_srq_chk_attr(rxe, NULL, &init->attr, IB_SRQ_INIT_MASK);
	if (err)
		goto err1;

	srq = rxe_alloc(&rxe->srq_pool);
	if (!srq) {
		err = -ENOMEM;
		goto err1;
	}

	rxe_add_index(srq);
	rxe_add_ref(pd);
	srq->pd = pd;

	err = rxe_srq_from_init(rxe, srq, init, context, udata);
	if (err)
		goto err2;

	return &srq->ibsrq;

err2:
	rxe_drop_ref(pd);
	rxe_drop_index(srq);
	rxe_drop_ref(srq);
err1:
	return ERR_PTR(err);
}

static int rxe_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
			  enum ib_srq_attr_mask mask,
			  struct ib_udata *udata)
{
	int err;
	struct rxe_srq *srq = to_rsrq(ibsrq);
	struct rxe_dev *rxe = to_rdev(ibsrq->device);

	err = rxe_srq_chk_attr(rxe, srq, attr, mask);
	if (err)
		goto err1;

	err = rxe_srq_from_attr(rxe, srq, attr, mask, udata);
	if (err)
		goto err1;

	return 0;

err1:
	return err;
}

static int rxe_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr)
{
	struct rxe_srq *srq = to_rsrq(ibsrq);

	if (srq->error)
		return -EINVAL;

	attr->max_wr = srq->rq.queue->buf->index_mask;
	attr->max_sge = srq->rq.max_sge;
	attr->srq_limit = srq->limit;
	return 0;
}

static int rxe_destroy_srq(struct ib_srq *ibsrq)
{
	struct rxe_srq *srq = to_rsrq(ibsrq);

	if (srq->cq)
		rxe_drop_ref(srq->cq);

	rxe_drop_ref(srq->pd);
	rxe_drop_index(srq);
	rxe_drop_ref(srq);
	return 0;
}

static int rxe_post_srq_recv(struct ib_srq *ibsrq, struct ib_recv_wr *wr,
			     struct ib_recv_wr **bad_wr)
{
	int err = 0;
	unsigned long flags;
	struct rxe_srq *srq = to_rsrq(ibsrq);

	spin_lock_irqsave(&srq->rq.producer_lock, flags);

	while (wr) {
		err = post_one_recv(&srq->rq, wr);
		if (unlikely(err))
			break;
		wr = wr->next;
	}

	spin_unlock_irqrestore(&srq->rq.producer_lock, flags);

	if (err)
		*bad_wr = wr;

	return err;
}

static struct ib_qp *rxe_create_qp(struct ib_pd *ibpd,
				   struct ib_qp_init_attr *init,
				   struct ib_udata *udata)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_qp *qp;

	err = rxe_qp_chk_init(rxe, init);
	if (err)
		goto err1;

	qp = rxe_alloc(&rxe->qp_pool);
	if (!qp) {
		err = -ENOMEM;
		goto err1;
	}

	rxe_add_index(qp);

	if (udata)
		qp->is_user = 1;

	err = rxe_qp_from_init(rxe, qp, pd, init, udata, ibpd);
	if (err)
		goto err2;

	return &qp->ibqp;

err2:
	rxe_drop_index(qp);
	rxe_drop_ref(qp);
err1:
	return ERR_PTR(err);
}

static int rxe_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int mask, struct ib_udata *udata)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibqp->device);
	struct rxe_qp *qp = to_rqp(ibqp);

	err = rxe_qp_chk_attr(rxe, qp, attr, mask);
	if (err)
		goto err1;

	err = rxe_qp_from_attr(qp, attr, mask, udata);
	if (err)
		goto err1;

	return 0;

err1:
	return err;
}

static int rxe_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			int mask, struct ib_qp_init_attr *init)
{
	struct rxe_qp *qp = to_rqp(ibqp);

	rxe_qp_to_init(qp, init);
	rxe_qp_to_attr(qp, attr, mask);

	return 0;
}

static int rxe_destroy_qp(struct ib_qp *ibqp)
{
	struct rxe_qp *qp = to_rqp(ibqp);

	rxe_qp_destroy(qp);
	rxe_drop_index(qp);
	rxe_drop_ref(qp);
	return 0;
}

static int validate_send_wr(struct rxe_qp *qp, struct ib_send_wr *ibwr,
			    unsigned int mask, unsigned int length)
{
	int num_sge = ibwr->num_sge;
	struct rxe_sq *sq = &qp->sq;

	if (unlikely(num_sge > sq->max_sge))
		goto err1;

	if (unlikely(mask & WR_ATOMIC_MASK)) {
		if (length < 8)
			goto err1;

		if (ibwr->wr.atomic.remote_addr & 0x7)
			goto err1;
	}

	if (unlikely((ibwr->send_flags & IB_SEND_INLINE) &&
		     (length > sq->max_inline)))
		goto err1;

	return 0;

err1:
	return -EINVAL;
}

static int init_send_wqe(struct rxe_qp *qp, struct ib_send_wr *ibwr,
			 unsigned int mask, unsigned int length,
			 struct rxe_send_wqe *wqe)
{
	int num_sge = ibwr->num_sge;
	struct ib_sge *sge;
	int i;
	u8 *p;

	memcpy(&wqe->ibwr, ibwr, sizeof(wqe->ibwr));

	if (qp_type(qp) == IB_QPT_UD ||
	    qp_type(qp) == IB_QPT_SMI ||
	    qp_type(qp) == IB_QPT_GSI)
		memcpy(&wqe->av, &to_rah(ibwr->wr.ud.ah)->av, sizeof(wqe->av));

	if (unlikely(ibwr->send_flags & IB_SEND_INLINE)) {
		p = wqe->dma.inline_data;

		sge = ibwr->sg_list;
		for (i = 0; i < num_sge; i++, sge++) {
			if (qp->is_user && copy_from_user(p, (__user void *)
					    (uintptr_t)sge->addr, sge->length))
				return -EFAULT;

			memcpy(p, (void *)(uintptr_t)sge->addr, sge->length);
			p += sge->length;
		}
	} else
		memcpy(wqe->dma.sge, ibwr->sg_list,
		       num_sge*sizeof(struct ib_sge));

	wqe->iova		= (mask & WR_ATOMIC_MASK) ?
					ibwr->wr.atomic.remote_addr :
					ibwr->wr.rdma.remote_addr;
	wqe->mask		= mask;
	wqe->dma.length		= length;
	wqe->dma.resid		= length;
	wqe->dma.num_sge	= num_sge;
	wqe->dma.cur_sge	= 0;
	wqe->dma.sge_offset	= 0;
	wqe->state		= wqe_state_posted;
	wqe->ssn		= atomic_add_return(1, &qp->ssn);

	return 0;
}

static int post_one_send(struct rxe_qp *qp, struct ib_send_wr *ibwr,
			 unsigned mask, u32 length)
{
	int err;
	struct rxe_sq *sq = &qp->sq;
	struct rxe_send_wqe *send_wqe;
	unsigned long flags;

	err = validate_send_wr(qp, ibwr, mask, length);
	if (err)
		return err;

	spin_lock_irqsave(&qp->sq.sq_lock, flags);

	if (unlikely(queue_full(sq->queue))) {
		err = -ENOMEM;
		goto err1;
	}

	send_wqe = producer_addr(sq->queue);

	err = init_send_wqe(qp, ibwr, mask, length, send_wqe);
	if (unlikely(err))
		goto err1;

	/* make sure all changes to the work queue are
	   written before we update the producer pointer */
	wmb();

	advance_producer(sq->queue);
	spin_unlock_irqrestore(&qp->sq.sq_lock, flags);

	return 0;

err1:
	spin_unlock_irqrestore(&qp->sq.sq_lock, flags);
	return err;
}

static int rxe_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
			 struct ib_send_wr **bad_wr)
{
	int err = 0;
	struct rxe_qp *qp = to_rqp(ibqp);
	unsigned int mask;
	unsigned int length = 0;
	int i;
	int must_sched;

	if (unlikely(!qp->valid || qp->req.state == QP_STATE_ERROR)) {
		*bad_wr = wr;
		return -EINVAL;
	}

	if (unlikely(qp->req.state < QP_STATE_READY)) {
		*bad_wr = wr;
		return -EINVAL;
	}

	while (wr) {
		mask = wr_opcode_mask(wr->opcode, qp);
		if (unlikely(!mask)) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}

		if (unlikely((wr->send_flags & IB_SEND_INLINE) &&
			     !(mask & WR_INLINE_MASK))) {
			err = -EINVAL;
			*bad_wr = wr;
			break;
		}

		length = 0;
		for (i = 0; i < wr->num_sge; i++)
			length += wr->sg_list[i].length;

		err = post_one_send(qp, wr, mask, length);

		if (err) {
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}

	must_sched = queue_count(qp->sq.queue) > 1;
	rxe_run_task(&qp->req.task, must_sched);

	return err;
}

static int rxe_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *wr,
			 struct ib_recv_wr **bad_wr)
{
	int err = 0;
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_rq *rq = &qp->rq;
	unsigned long flags;

	if (unlikely((qp_state(qp) < IB_QPS_INIT) || !qp->valid)) {
		*bad_wr = wr;
		err = -EINVAL;
		goto err1;
	}

	if (unlikely(qp->srq)) {
		*bad_wr = wr;
		err = -EINVAL;
		goto err1;
	}

	if (unlikely(qp->is_user)) {
		*bad_wr = wr;
		err = -EINVAL;
		goto err1;
	}

	spin_lock_irqsave(&rq->producer_lock, flags);

	while (wr) {
		err = post_one_recv(rq, wr);
		if (unlikely(err)) {
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}

	spin_unlock_irqrestore(&rq->producer_lock, flags);

err1:
	return err;
}

static struct ib_cq *rxe_create_cq(struct ib_device *dev, int cqe,
				   int comp_vector,
				   struct ib_ucontext *context,
				   struct ib_udata *udata)
{
	int err;
	struct rxe_dev *rxe = to_rdev(dev);
	struct rxe_cq *cq;

	err = rxe_cq_chk_attr(rxe, NULL, cqe, comp_vector, udata);
	if (err)
		goto err1;

	cq = rxe_alloc(&rxe->cq_pool);
	if (!cq) {
		err = -ENOMEM;
		goto err1;
	}

	err = rxe_cq_from_init(rxe, cq, cqe, comp_vector, context, udata);
	if (err)
		goto err2;

	return &cq->ibcq;

err2:
	rxe_drop_ref(cq);
err1:
	return ERR_PTR(err);
}

static int rxe_destroy_cq(struct ib_cq *ibcq)
{
	struct rxe_cq *cq = to_rcq(ibcq);

	rxe_drop_ref(cq);
	return 0;
}

static int rxe_resize_cq(struct ib_cq *ibcq, int cqe, struct ib_udata *udata)
{
	int err;
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_dev *rxe = to_rdev(ibcq->device);

	err = rxe_cq_chk_attr(rxe, cq, cqe, 0, udata);
	if (err)
		goto err1;

	err = rxe_cq_resize_queue(cq, cqe, udata);
	if (err)
		goto err1;

	return 0;

err1:
	return err;
}

static int rxe_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	int i;
	struct rxe_cq *cq = to_rcq(ibcq);
	struct rxe_cqe *cqe;

	for (i = 0; i < num_entries; i++) {
		cqe = queue_head(cq->queue);
		if (!cqe)
			break;

		memcpy(wc++, &cqe->ibwc, sizeof(*wc));
		advance_consumer(cq->queue);
	}

	return i;
}

static int rxe_peek_cq(struct ib_cq *ibcq, int wc_cnt)
{
	struct rxe_cq *cq = to_rcq(ibcq);
	int count = queue_count(cq->queue);

	return (count > wc_cnt) ? wc_cnt : count;
}

static int rxe_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct rxe_cq *cq = to_rcq(ibcq);

	if (cq->notify != IB_CQ_NEXT_COMP)
		cq->notify = flags & IB_CQ_SOLICITED_MASK;

	return 0;
}

static int rxe_req_ncomp_notif(struct ib_cq *ibcq, int wc_cnt)
{
	return -EINVAL;
}

static struct ib_mr *rxe_get_dma_mr(struct ib_pd *ibpd, int access)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mem *mr;
	int err;

	mr = rxe_alloc(&rxe->mr_pool);
	if (!mr) {
		err = -ENOMEM;
		goto err1;
	}

	rxe_add_index(mr);

	rxe_add_ref(pd);

	err = rxe_mem_init_dma(rxe, pd, access, mr);
	if (err)
		goto err2;

	return &mr->ibmr;

err2:
	rxe_drop_ref(pd);
	rxe_drop_index(mr);
	rxe_drop_ref(mr);
err1:
	return ERR_PTR(err);
}

static struct ib_mr *rxe_reg_phys_mr(struct ib_pd *ibpd,
				     struct ib_phys_buf *phys_buf_array,
				     int num_phys_buf,
				     int access, u64 *iova_start)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mem *mr;
	u64 iova = *iova_start;

	mr = rxe_alloc(&rxe->mr_pool);
	if (!mr) {
		err = -ENOMEM;
		goto err1;
	}

	rxe_add_index(mr);

	rxe_add_ref(pd);

	err = rxe_mem_init_phys(rxe, pd, access, iova,
				phys_buf_array, num_phys_buf, mr);
	if (err)
		goto err2;

	return &mr->ibmr;

err2:
	rxe_drop_ref(pd);
	rxe_drop_index(mr);
	rxe_drop_ref(mr);
err1:
	return ERR_PTR(err);
}

static struct ib_mr *rxe_reg_user_mr(struct ib_pd *ibpd,
				     u64 start,
				     u64 length,
				     u64 iova,
				     int access, struct ib_udata *udata)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mem *mr;

	mr = rxe_alloc(&rxe->mr_pool);
	if (!mr) {
		err = -ENOMEM;
		goto err2;
	}

	rxe_add_index(mr);

	rxe_add_ref(pd);

	err = rxe_mem_init_user(rxe, pd, start, length, iova,
				access, udata, mr);
	if (err)
		goto err3;

	return &mr->ibmr;

err3:
	rxe_drop_ref(pd);
	rxe_drop_index(mr);
	rxe_drop_ref(mr);
err2:
	return ERR_PTR(err);
}

static int rxe_dereg_mr(struct ib_mr *ibmr)
{
	struct rxe_mem *mr = to_rmr(ibmr);

	mr->state = RXE_MEM_STATE_ZOMBIE;
	rxe_drop_ref(mr->pd);
	rxe_drop_index(mr);
	rxe_drop_ref(mr);
	return 0;
}

static struct ib_mr *rxe_alloc_fast_reg_mr(struct ib_pd *ibpd, int max_pages)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mem *mr;
	int err;

	mr = rxe_alloc(&rxe->mr_pool);
	if (!mr) {
		err = -ENOMEM;
		goto err1;
	}

	rxe_add_index(mr);

	rxe_add_ref(pd);

	err = rxe_mem_init_fast(rxe, pd, max_pages, mr);
	if (err)
		goto err2;

	return &mr->ibmr;

err2:
	rxe_drop_ref(pd);
	rxe_drop_index(mr);
	rxe_drop_ref(mr);
err1:
	return ERR_PTR(err);
}

static struct ib_fast_reg_page_list *
	rxe_alloc_fast_reg_page_list(struct ib_device *device,
				     int page_list_len)
{
	struct rxe_fast_reg_page_list *frpl;
	int err;

	frpl = kmalloc(sizeof(*frpl), GFP_KERNEL);
	if (!frpl) {
		err = -ENOMEM;
		goto err1;
	}

	frpl->ibfrpl.page_list = kmalloc_array(page_list_len, sizeof(u64),
						GFP_KERNEL);
	if (!frpl->ibfrpl.page_list) {
		err = -ENOMEM;
		goto err2;
	}

	return &frpl->ibfrpl;

err2:
	kfree(frpl);
err1:
	return ERR_PTR(err);
}

static void rxe_free_fast_reg_page_list(struct ib_fast_reg_page_list *ibfrpl)
{
	struct rxe_fast_reg_page_list *frpl = to_rfrpl(ibfrpl);

	kfree(frpl->ibfrpl.page_list);
	kfree(frpl);
}

static int rxe_rereg_phys_mr(struct ib_mr *ibmr, int mr_rereg_mask,
			     struct ib_pd *ibpd,
			     struct ib_phys_buf *phys_buf_array,
			     int num_phys_buf, int mr_access_flags,
			     u64 *iova_start)
{
	return -EINVAL;
}

static struct ib_mw *rxe_alloc_mw(struct ib_pd *ibpd, enum ib_mw_type type)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mem *mw;
	int err;

	if (type != IB_MW_TYPE_1)
		return ERR_PTR(-EINVAL);

	mw = rxe_alloc(&rxe->mw_pool);
	if (!mw) {
		err = -ENOMEM;
		goto err1;
	}

	rxe_add_index(mw);

	rxe_add_ref(pd);

	err = rxe_mem_init_mw(rxe, pd, mw);
	if (err)
		goto err2;

	return &mw->ibmw;

err2:
	rxe_drop_ref(pd);
	rxe_drop_index(mw);
	rxe_drop_ref(mw);
err1:
	return ERR_PTR(err);
}

static int rxe_bind_mw(struct ib_qp *ibqp,
		       struct ib_mw *ibmw, struct ib_mw_bind *mw_bind)
{
	return -EINVAL;
}

static int rxe_dealloc_mw(struct ib_mw *ibmw)
{
	struct rxe_mem *mw = to_rmw(ibmw);

	mw->state = RXE_MEM_STATE_ZOMBIE;
	rxe_drop_ref(mw->pd);
	rxe_drop_index(mw);
	rxe_drop_ref(mw);
	return 0;
}

static struct ib_fmr *rxe_alloc_fmr(struct ib_pd *ibpd,
				    int access, struct ib_fmr_attr *attr)
{
	struct rxe_dev *rxe = to_rdev(ibpd->device);
	struct rxe_pd *pd = to_rpd(ibpd);
	struct rxe_mem *fmr;
	int err;

	fmr = rxe_alloc(&rxe->fmr_pool);
	if (!fmr) {
		err = -ENOMEM;
		goto err1;
	}

	rxe_add_index(fmr);

	rxe_add_ref(pd);

	err = rxe_mem_init_fmr(rxe, pd, access, attr, fmr);
	if (err)
		goto err2;

	return &fmr->ibfmr;

err2:
	rxe_drop_ref(pd);
	rxe_drop_index(fmr);
	rxe_drop_ref(fmr);
err1:
	return ERR_PTR(err);
}

static int rxe_map_phys_fmr(struct ib_fmr *ibfmr,
			    u64 *page_list, int list_length, u64 iova)
{
	struct rxe_mem *fmr = to_rfmr(ibfmr);
	struct rxe_dev *rxe = to_rdev(ibfmr->device);

	return rxe_mem_map_pages(rxe, fmr, page_list, list_length, iova);
}

static int rxe_unmap_fmr(struct list_head *fmr_list)
{
	struct rxe_mem *fmr;

	list_for_each_entry(fmr, fmr_list, ibfmr.list) {
		if (fmr->state != RXE_MEM_STATE_VALID)
			continue;

		fmr->va = 0;
		fmr->iova = 0;
		fmr->length = 0;
		fmr->num_buf = 0;
		fmr->state = RXE_MEM_STATE_FREE;
	}

	return 0;
}

static int rxe_dealloc_fmr(struct ib_fmr *ibfmr)
{
	struct rxe_mem *fmr = to_rfmr(ibfmr);

	fmr->state = RXE_MEM_STATE_ZOMBIE;
	rxe_drop_ref(fmr->pd);
	rxe_drop_index(fmr);
	rxe_drop_ref(fmr);
	return 0;
}

static int rxe_attach_mcast(struct ib_qp *ibqp, union ib_gid *mgid, u16 mlid)
{
	int err;
	struct rxe_dev *rxe = to_rdev(ibqp->device);
	struct rxe_qp *qp = to_rqp(ibqp);
	struct rxe_mc_grp *grp;

	/* takes a ref on grp if successful */
	err = rxe_mcast_get_grp(rxe, mgid, mlid, &grp);
	if (err)
		return err;

	err = rxe_mcast_add_grp_elem(rxe, qp, grp);

	rxe_drop_ref(grp);
	return err;
}

static int rxe_detach_mcast(struct ib_qp *ibqp, union ib_gid *mgid, u16 mlid)
{
	struct rxe_dev *rxe = to_rdev(ibqp->device);
	struct rxe_qp *qp = to_rqp(ibqp);

	return rxe_mcast_drop_grp_elem(rxe, qp, mgid, mlid);
}

static ssize_t rxe_show_skb_num(struct device *device,
				struct device_attribute *attr, char *buf)
{
	struct rxe_dev *rxe = container_of(device, struct rxe_dev,
					   ib_dev.dev);

	return sprintf(buf, "req_in:%d resp_in:%d req_out:%d resp_out:%d\n",
		atomic_read(&rxe->req_skb_in),
		atomic_read(&rxe->resp_skb_in),
		atomic_read(&rxe->req_skb_out),
		atomic_read(&rxe->resp_skb_out));
}

static DEVICE_ATTR(skb_num, S_IRUGO, rxe_show_skb_num, NULL);

static ssize_t rxe_show_parent(struct device *device,
			       struct device_attribute *attr, char *buf)
{
	struct rxe_dev *rxe = container_of(device, struct rxe_dev,
					   ib_dev.dev);
	char *name;

	name = rxe->ifc_ops->parent_name(rxe, 1);
	return snprintf(buf, 16, "%s\n", name);
}

static DEVICE_ATTR(parent, S_IRUGO, rxe_show_parent, NULL);

static struct device_attribute *rxe_dev_attributes[] = {
	&dev_attr_skb_num,
	&dev_attr_parent,
};

int rxe_register_device(struct rxe_dev *rxe)
{
	int err;
	int i;
	struct ib_device *dev = &rxe->ib_dev;

	strlcpy(dev->name, "rxe%d", IB_DEVICE_NAME_MAX);
	strlcpy(dev->node_desc, "rxe", sizeof(dev->node_desc));

	dev->owner = THIS_MODULE;
	dev->node_type = RDMA_NODE_IB_CA;
	dev->phys_port_cnt = rxe->num_ports;
	dev->num_comp_vectors = RXE_NUM_COMP_VECTORS;
	dev->dma_device = rxe->ifc_ops->dma_device(rxe);
	dev->local_dma_lkey = 0;	/* TODO */
	dev->node_guid = rxe->ifc_ops->node_guid(rxe);
	dev->dma_ops = &rxe_dma_mapping_ops;

	dev->uverbs_abi_ver = RXE_UVERBS_ABI_VERSION;
	dev->uverbs_cmd_mask = (1ull << IB_USER_VERBS_CMD_GET_CONTEXT)
	    | (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)
	    | (1ull << IB_USER_VERBS_CMD_QUERY_DEVICE)
	    | (1ull << IB_USER_VERBS_CMD_QUERY_PORT)
	    | (1ull << IB_USER_VERBS_CMD_ALLOC_PD)
	    | (1ull << IB_USER_VERBS_CMD_DEALLOC_PD)
	    | (1ull << IB_USER_VERBS_CMD_CREATE_SRQ)
	    | (1ull << IB_USER_VERBS_CMD_MODIFY_SRQ)
	    | (1ull << IB_USER_VERBS_CMD_QUERY_SRQ)
	    | (1ull << IB_USER_VERBS_CMD_DESTROY_SRQ)
	    | (1ull << IB_USER_VERBS_CMD_POST_SRQ_RECV)
	    | (1ull << IB_USER_VERBS_CMD_CREATE_QP)
	    | (1ull << IB_USER_VERBS_CMD_MODIFY_QP)
	    | (1ull << IB_USER_VERBS_CMD_QUERY_QP)
	    | (1ull << IB_USER_VERBS_CMD_DESTROY_QP)
	    | (1ull << IB_USER_VERBS_CMD_POST_SEND)
	    | (1ull << IB_USER_VERBS_CMD_POST_RECV)
	    | (1ull << IB_USER_VERBS_CMD_CREATE_CQ)
	    | (1ull << IB_USER_VERBS_CMD_RESIZE_CQ)
	    | (1ull << IB_USER_VERBS_CMD_DESTROY_CQ)
	    | (1ull << IB_USER_VERBS_CMD_POLL_CQ)
	    | (1ull << IB_USER_VERBS_CMD_PEEK_CQ)
	    | (1ull << IB_USER_VERBS_CMD_REQ_NOTIFY_CQ)
	    | (1ull << IB_USER_VERBS_CMD_REG_MR)
	    | (1ull << IB_USER_VERBS_CMD_DEREG_MR)
	    | (1ull << IB_USER_VERBS_CMD_CREATE_AH)
	    | (1ull << IB_USER_VERBS_CMD_MODIFY_AH)
	    | (1ull << IB_USER_VERBS_CMD_QUERY_AH)
	    | (1ull << IB_USER_VERBS_CMD_DESTROY_AH)
	    | (1ull << IB_USER_VERBS_CMD_ATTACH_MCAST)
	    | (1ull << IB_USER_VERBS_CMD_DETACH_MCAST)
	    ;

	dev->query_device = rxe_query_device;
	dev->modify_device = rxe_modify_device;
	dev->query_port = rxe_query_port;
	dev->modify_port = rxe_modify_port;
	dev->get_link_layer = rxe_get_link_layer;
	dev->query_gid = rxe_query_gid;
	dev->get_netdev = rxe_get_netdev;
	dev->modify_gid = rxe_modify_gid;
	dev->query_pkey = rxe_query_pkey;
	dev->alloc_ucontext = rxe_alloc_ucontext;
	dev->dealloc_ucontext = rxe_dealloc_ucontext;
	dev->mmap = rxe_mmap;
	dev->alloc_pd = rxe_alloc_pd;
	dev->dealloc_pd = rxe_dealloc_pd;
	dev->create_ah = rxe_create_ah;
	dev->modify_ah = rxe_modify_ah;
	dev->query_ah = rxe_query_ah;
	dev->destroy_ah = rxe_destroy_ah;
	dev->create_srq = rxe_create_srq;
	dev->modify_srq = rxe_modify_srq;
	dev->query_srq = rxe_query_srq;
	dev->destroy_srq = rxe_destroy_srq;
	dev->post_srq_recv = rxe_post_srq_recv;
	dev->create_qp = rxe_create_qp;
	dev->modify_qp = rxe_modify_qp;
	dev->query_qp = rxe_query_qp;
	dev->destroy_qp = rxe_destroy_qp;
	dev->post_send = rxe_post_send;
	dev->post_recv = rxe_post_recv;
	dev->create_cq = rxe_create_cq;
	dev->modify_cq = NULL;
	dev->destroy_cq = rxe_destroy_cq;
	dev->resize_cq = rxe_resize_cq;
	dev->poll_cq = rxe_poll_cq;
	dev->peek_cq = rxe_peek_cq;
	dev->req_notify_cq = rxe_req_notify_cq;
	dev->req_ncomp_notif = rxe_req_ncomp_notif;
	dev->get_dma_mr = rxe_get_dma_mr;
	dev->reg_phys_mr = rxe_reg_phys_mr;
	dev->reg_user_mr = rxe_reg_user_mr;
	dev->rereg_phys_mr = rxe_rereg_phys_mr;
	dev->dereg_mr = rxe_dereg_mr;
	dev->alloc_fast_reg_mr = rxe_alloc_fast_reg_mr;
	dev->alloc_fast_reg_page_list = rxe_alloc_fast_reg_page_list;
	dev->free_fast_reg_page_list = rxe_free_fast_reg_page_list;
	dev->alloc_mw = rxe_alloc_mw;
	dev->bind_mw = rxe_bind_mw;
	dev->dealloc_mw = rxe_dealloc_mw;
	dev->alloc_fmr = rxe_alloc_fmr;
	dev->map_phys_fmr = rxe_map_phys_fmr;
	dev->unmap_fmr = rxe_unmap_fmr;
	dev->dealloc_fmr = rxe_dealloc_fmr;
	dev->attach_mcast = rxe_attach_mcast;
	dev->detach_mcast = rxe_detach_mcast;
	dev->process_mad = NULL;

	err = ib_register_device(dev, NULL);
	if (err) {
		pr_warn("rxe_register_device failed, err = %d\n", err);
		goto err1;
	}

	for (i = 0; i < ARRAY_SIZE(rxe_dev_attributes); ++i) {
		err = device_create_file(&dev->dev, rxe_dev_attributes[i]);
		if (err) {
			pr_warn("device_create_file failed, i = %d, err = %d\n",
				i, err);
			goto err2;
		}
	}

	return 0;

err2:
	ib_unregister_device(dev);
err1:
	return err;
}

int rxe_unregister_device(struct rxe_dev *rxe)
{
	int i;
	struct ib_device *dev = &rxe->ib_dev;

	for (i = 0; i < ARRAY_SIZE(rxe_dev_attributes); ++i)
		device_remove_file(&dev->dev, rxe_dev_attributes[i]);

	ib_unregister_device(dev);

	return 0;
}

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

#ifndef RXE_LOC_H
#define RXE_LOC_H

/* local declarations shared between rxe files */

/* rxe_v.c */
int rxe_av_chk_attr(struct rxe_dev *rxe, struct ib_ah_attr *attr);

int rxe_av_from_attr(struct rxe_dev *rxe, u8 port_num,
		     struct rxe_av *av, struct ib_ah_attr *attr);

int rxe_av_to_attr(struct rxe_dev *rxe, struct rxe_av *av,
		   struct ib_ah_attr *attr);

int rxe_av_fill_ip_info(struct rxe_dev *rxe, struct rxe_av *av,
		    struct ib_ah_attr *attr, union ib_gid *sgid);

/* rxe_cq.c */
int rxe_cq_chk_attr(struct rxe_dev *rxe, struct rxe_cq *cq,
		    int cqe, int comp_vector, struct ib_udata *udata);

int rxe_cq_from_init(struct rxe_dev *rxe, struct rxe_cq *cq, int cqe,
		     int comp_vector, struct ib_ucontext *context,
		     struct ib_udata *udata);

int rxe_cq_resize_queue(struct rxe_cq *cq, int new_cqe, struct ib_udata *udata);

int rxe_cq_post(struct rxe_cq *cq, struct rxe_cqe *cqe, int solicited);

void rxe_cq_cleanup(void *arg);

/* rxe_mcast.c */
int rxe_mcast_get_grp(struct rxe_dev *rxe, union ib_gid *mgid, u16 mlid,
		      struct rxe_mc_grp **grp_p);

int rxe_mcast_add_grp_elem(struct rxe_dev *rxe, struct rxe_qp *qp,
			   struct rxe_mc_grp *grp);

int rxe_mcast_drop_grp_elem(struct rxe_dev *rxe, struct rxe_qp *qp,
			    union ib_gid *mgid, u16 mlid);

void rxe_drop_all_mcast_groups(struct rxe_qp *qp);

void rxe_mc_cleanup(void *arg);

/* rxe_mmap.c */

/* must match struct in librxe */
struct mminfo {
	__u64			offset;
	__u32			size;
	__u32			pad;
};

struct rxe_mmap_info {
	struct list_head	pending_mmaps;
	struct ib_ucontext	*context;
	struct kref		ref;
	void			*obj;

	struct mminfo info;
};

void rxe_mmap_release(struct kref *ref);

struct rxe_mmap_info *rxe_create_mmap_info(struct rxe_dev *dev,
					   u32 size,
					   struct ib_ucontext *context,
					   void *obj);

int rxe_mmap(struct ib_ucontext *context, struct vm_area_struct *vma);

/* rxe_mr.c */
enum copy_direction {
	direction_in,
	direction_out,
};

#define DMA_BAD_ADDER ((u64) 0)

int rxe_mem_init_dma(struct rxe_dev *rxe, struct rxe_pd *pd,
		     int access, struct rxe_mem *mem);

int rxe_mem_init_phys(struct rxe_dev *rxe, struct rxe_pd *pd,
		      int access, u64 iova, struct ib_phys_buf *buf,
		      int num_buf, struct rxe_mem *mem);

int rxe_mem_init_user(struct rxe_dev *rxe, struct rxe_pd *pd, u64 start,
		      u64 length, u64 iova, int access, struct ib_udata *udata,
		      struct rxe_mem *mr);

int rxe_mem_init_fast(struct rxe_dev *rxe, struct rxe_pd *pd,
		      int max_pages, struct rxe_mem *mem);

int rxe_mem_init_mw(struct rxe_dev *rxe, struct rxe_pd *pd,
		    struct rxe_mem *mw);

int rxe_mem_init_fmr(struct rxe_dev *rxe, struct rxe_pd *pd, int access,
		     struct ib_fmr_attr *attr, struct rxe_mem *fmr);

int rxe_mem_copy(struct rxe_mem *mem, u64 iova, void *addr,
		 int length, enum copy_direction dir, u32 *crcp);

int copy_data(struct rxe_dev *rxe, struct rxe_pd *pd, int access,
	      struct rxe_dma_info *dma, void *addr, int length,
	      enum copy_direction dir, u32 *crcp);

void *iova_to_vaddr(struct rxe_mem *mem, u64 iova, int length);

enum lookup_type {
	lookup_local,
	lookup_remote,
};

struct rxe_mem *lookup_mem(struct rxe_pd *pd, int access, u32 key,
			   enum lookup_type type);

int mem_check_range(struct rxe_mem *mem, u64 iova, size_t length);

int rxe_mem_map_pages(struct rxe_dev *rxe, struct rxe_mem *mem,
		      u64 *page, int num_pages, u64 iova);

void rxe_mem_cleanup(void *arg);

int advance_dma_data(struct rxe_dma_info *dma, unsigned int length);

/* rxe_qp.c */
int rxe_qp_chk_init(struct rxe_dev *rxe, struct ib_qp_init_attr *init);

int rxe_qp_from_init(struct rxe_dev *rxe, struct rxe_qp *qp, struct rxe_pd *pd,
		     struct ib_qp_init_attr *init, struct ib_udata *udata,
		     struct ib_pd *ibpd);

int rxe_qp_to_init(struct rxe_qp *qp, struct ib_qp_init_attr *init);

int rxe_qp_chk_attr(struct rxe_dev *rxe, struct rxe_qp *qp,
		    struct ib_qp_attr *attr, int mask);

int rxe_qp_from_attr(struct rxe_qp *qp, struct ib_qp_attr *attr,
		     int mask, struct ib_udata *udata);

int rxe_qp_to_attr(struct rxe_qp *qp, struct ib_qp_attr *attr, int mask);

void rxe_qp_error(struct rxe_qp *qp);

void rxe_qp_destroy(struct rxe_qp *qp);

void rxe_qp_cleanup(void *arg);

static inline int qp_num(struct rxe_qp *qp)
{
	return qp->ibqp.qp_num;
}

static inline enum ib_qp_type qp_type(struct rxe_qp *qp)
{
	return qp->ibqp.qp_type;
}

static inline enum ib_qp_state qp_state(struct rxe_qp *qp)
{
	return qp->attr.qp_state;
}

static inline int qp_mtu(struct rxe_qp *qp)
{
	if (qp->ibqp.qp_type == IB_QPT_RC || qp->ibqp.qp_type == IB_QPT_UC)
		return qp->attr.path_mtu;
	else
		return RXE_PORT_MAX_MTU;
}

#define RCV_WQE_SIZE(max_sge) (sizeof(struct rxe_recv_wqe) + \
			       (max_sge)*sizeof(struct ib_sge))

void free_rd_atomic_resource(struct rxe_qp *qp, struct resp_res *res);

static inline void rxe_advance_resp_resource(struct rxe_qp *qp)
{
	qp->resp.res_head++;
	if (unlikely(qp->resp.res_head == qp->attr.max_rd_atomic))
		qp->resp.res_head = 0;
}

void retransmit_timer(unsigned long data);
void rnr_nak_timer(unsigned long data);

void dump_qp(struct rxe_qp *qp);

/* rxe_srq.c */
#define IB_SRQ_INIT_MASK (~IB_SRQ_LIMIT)

int rxe_srq_chk_attr(struct rxe_dev *rxe, struct rxe_srq *srq,
		     struct ib_srq_attr *attr, enum ib_srq_attr_mask mask);

int rxe_srq_from_init(struct rxe_dev *rxe, struct rxe_srq *srq,
		      struct ib_srq_init_attr *init,
		      struct ib_ucontext *context, struct ib_udata *udata);

int rxe_srq_from_attr(struct rxe_dev *rxe, struct rxe_srq *srq,
		      struct ib_srq_attr *attr, enum ib_srq_attr_mask mask,
		      struct ib_udata *udata);

void rxe_srq_cleanup(void *arg);

extern struct ib_dma_mapping_ops rxe_dma_mapping_ops;

void rxe_release(struct kref *kref);

void arbiter_skb_queue(struct rxe_dev *rxe,
		       struct rxe_qp *qp, struct sk_buff *skb);

void rxe_arbiter_timer(unsigned long arg);

int rxe_arbiter(void *arg);
int rxe_completer(void *arg);
int rxe_requester(void *arg);
int rxe_responder(void *arg);

u32 rxe_icrc_hdr(struct rxe_pkt_info *pkt);
u32 rxe_icrc_pkt(struct rxe_pkt_info *pkt);

void rxe_resp_queue_pkt(struct rxe_dev *rxe,
			struct rxe_qp *qp, struct sk_buff *skb);

void rxe_comp_queue_pkt(struct rxe_dev *rxe,
			struct rxe_qp *qp, struct sk_buff *skb);

static inline unsigned wr_opcode_mask(int opcode, struct rxe_qp *qp)
{
	return rxe_wr_opcode_info[opcode].mask[qp->ibqp.qp_type];
}

#endif /* RXE_LOC_H */

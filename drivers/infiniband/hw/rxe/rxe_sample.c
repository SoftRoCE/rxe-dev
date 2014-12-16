/*
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

/*
 * sample driver for IB transport over rxe
 * implements a simple loopback device on module load
 */

#include <linux/skbuff.h>

#include <linux/device.h>

#include "rxe.h"

MODULE_AUTHOR("Bob Pearson");
MODULE_DESCRIPTION("RDMA transport over Converged Enhanced Ethernet");
MODULE_LICENSE("Dual BSD/GPL");

static __be64 node_guid(struct rxe_dev *rxe)
{
	return cpu_to_be64(0x3333333333333333ULL);
}

static __be64 port_guid(struct rxe_dev *rxe, unsigned int port_num)
{
	return cpu_to_be64(0x4444444444444444ULL);
}

/*
 * the ofed core requires that we provide a valid device
 * object for registration
 */
static struct class *my_class;
static struct device *my_dev;

static struct device *dma_device(struct rxe_dev *rxe)
{
	return my_dev;
}

static int mcast_add(struct rxe_dev *rxe, union ib_gid *mgid)
{
	return 0;
}

static int mcast_delete(struct rxe_dev *rxe, union ib_gid *mgid)
{
	return 0;
}

/* just loopback packet */
static int send(struct rxe_dev *rxe, struct sk_buff *skb)
{
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);

	pkt->rxe = rxe;
	pkt->mask = RXE_LRH_MASK;

	return rxe_rcv(skb);
}

static struct sk_buff *init_packet(struct rxe_dev *rxe, struct rxe_av *av,
				   int paylen, int align)
{
	struct sk_buff *skb;
	struct rxe_pkt_info *pkt;

	paylen += RXE_LRH_BYTES;

	if (av->attr.ah_flags & IB_AH_GRH)
		paylen += RXE_GRH_BYTES;

	skb = alloc_skb(paylen, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb->dev	= NULL;
	skb->protocol	= 0;

	pkt		= SKB_TO_PKT(skb);
	pkt->rxe	= rxe;
	pkt->port_num	= 1;
	pkt->hdr	= skb_put(skb, paylen);
	pkt->mask	= RXE_LRH_MASK;
	if (av->attr.ah_flags & IB_AH_GRH)
		pkt->mask	|= RXE_GRH_MASK;

	return skb;
}

static int init_av(struct rxe_dev *rxe, struct ib_ah_attr *attr,
		   struct rxe_av *av)
{
	if (!av->attr.dlid)
		av->attr.dlid = 1;
	return 0;
}

static char *parent_name(struct rxe_dev *rxe, unsigned int port_num)
{
	return "sample";
}

static enum rdma_link_layer link_layer(struct rxe_dev *rxe,
				       unsigned int port_num)
{
	return IB_LINK_LAYER_INFINIBAND;
}

static struct rxe_ifc_ops ifc_ops = {
	.node_guid	= node_guid,
	.port_guid	= port_guid,
	.dma_device	= dma_device,
	.mcast_add	= mcast_add,
	.mcast_delete	= mcast_delete,
	.send		= send,
	.init_packet	= init_packet,
	.init_av	= init_av,
	.parent_name	= parent_name,
	.link_layer	= link_layer,
};

static struct rxe_dev *rxe_sample;

static int rxe_sample_add(void)
{
	int err;
	struct rxe_port *port;

	rxe_sample = (struct rxe_dev *)ib_alloc_device(sizeof(*rxe_sample));
	if (!rxe_sample) {
		err = -ENOMEM;
		goto err1;
	}

	rxe_sample->ifc_ops = &ifc_ops;

	err = rxe_add(rxe_sample, 4500);
	if (err)
		goto err2;

	/* bit of a hack */
	port = &rxe_sample->port[0];
	port->attr.state = IB_PORT_ACTIVE;
	port->attr.phys_state = 5;
	port->attr.max_mtu = IB_MTU_4096;
	port->attr.active_mtu = IB_MTU_4096;
	port->mtu_cap = IB_MTU_4096;
	port->attr.lid = 1;

	pr_info("rxe_sample: added %s\n",
		rxe_sample->ib_dev.name);
	return 0;

err2:
	ib_dealloc_device(&rxe_sample->ib_dev);
err1:
	return err;
}

static void rxe_sample_remove(void)
{
	if (!rxe_sample)
		goto done;

	rxe_remove(rxe_sample);

	pr_info("rxe_sample: removed %s\n",
		rxe_sample->ib_dev.name);
done:
	return;
}

static int __init rxe_sample_init(void)
{
	int err;

	rxe_crc_disable = 1;

	my_class = class_create(THIS_MODULE, "foo");
	my_dev = device_create(my_class, NULL, 0, NULL, "bar");

	err = rxe_sample_add();
	return err;
}

static void __exit rxe_sample_exit(void)
{
	rxe_sample_remove();

	device_destroy(my_class, my_dev->devt);
	class_destroy(my_class);
}

module_init(rxe_sample_init);
module_exit(rxe_sample_exit);

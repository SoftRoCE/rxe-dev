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
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <net/sch_generic.h>
#include <linux/netfilter.h>
#include <rdma/ib_addr.h>

#include "rxe.h"
#include "rxe_net.h"

MODULE_AUTHOR("Bob Pearson, Frank Zago, John Groves");
MODULE_DESCRIPTION("RDMA transport over Converged Enhanced Ethernet");
MODULE_LICENSE("Dual BSD/GPL");

static int rxe_eth_proto_id = ETH_P_RXE;
module_param_named(eth_proto_id, rxe_eth_proto_id, int, 0644);
MODULE_PARM_DESC(eth_proto_id, "Ethernet protocol ID (default/correct=0x8915)");

static int rxe_loopback_mad_grh_fix = 1;
module_param_named(loopback_mad_grh_fix, rxe_loopback_mad_grh_fix, int, 0644);
MODULE_PARM_DESC(loopback_mad_grh_fix, "Allow MADs to self without GRH");

/*
 * note: this table is a replacement for a protocol specific pointer
 * in struct net_device which exists for other ethertypes
 * this allows us to not have to patch that data structure
 * eventually we want to get our own when we're famous
 */
struct rxe_net_info net_info[RXE_MAX_IF_INDEX];
spinlock_t net_info_lock; /* spinlock for net_info array */

static int rxe_net_rcv(struct sk_buff *skb,
		       struct net_device *ndev,
		       struct packet_type *ptype,
		       struct net_device *orig_dev);

static __be64 rxe_mac_to_eui64(struct net_device *ndev)
{
	unsigned char *mac_addr = ndev->dev_addr;
	__be64 eui64;
	unsigned char *dst = (unsigned char *)&eui64;

	dst[0] = mac_addr[0] ^ 2;
	dst[1] = mac_addr[1];
	dst[2] = mac_addr[2];
	dst[3] = 0xff;
	dst[4] = 0xfe;
	dst[5] = mac_addr[3];
	dst[6] = mac_addr[4];
	dst[7] = mac_addr[5];

	return eui64;
}

/* callback when rxe gets released */
static void release(struct rxe_dev *rxe)
{
	module_put(THIS_MODULE);
}

static __be64 node_guid(struct rxe_dev *rxe)
{
	return rxe_mac_to_eui64(rxe->ndev);
}

static __be64 port_guid(struct rxe_dev *rxe, unsigned int port_num)
{
	return rxe_mac_to_eui64(rxe->ndev);
}

static struct device *dma_device(struct rxe_dev *rxe)
{
	struct net_device *ndev;

	ndev = rxe->ndev;

	if (ndev->priv_flags & IFF_802_1Q_VLAN)
		ndev = vlan_dev_real_dev(ndev);

	return ndev->dev.parent;
}

static int mcast_add(struct rxe_dev *rxe, union ib_gid *mgid)
{
	int err;
	unsigned char ll_addr[ETH_ALEN];

	ipv6_eth_mc_map((struct in6_addr *)mgid->raw, ll_addr);
	err = dev_mc_add(rxe->ndev, ll_addr);

	return err;
}

static int mcast_delete(struct rxe_dev *rxe, union ib_gid *mgid)
{
	int err;
	unsigned char ll_addr[ETH_ALEN];

	ipv6_eth_mc_map((struct in6_addr *)mgid->raw, ll_addr);
	err = dev_mc_del(rxe->ndev, ll_addr);

	return err;
}

static inline int get_xps_queue(struct net_device *dev, struct sk_buff *skb)
{
	return -1;
}

static u16 __netdev_pick_tx(struct net_device *dev, struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	int queue_index = sk_tx_queue_get(sk);

	if (queue_index < 0 || skb->ooo_okay ||
	    queue_index >= dev->real_num_tx_queues) {
		int new_index = get_xps_queue(dev, skb);

		if (new_index < 0)
			new_index = skb_tx_hash(dev, skb);

		if (queue_index != new_index && sk &&
		    rcu_access_pointer(sk->sk_dst_cache))
			sk_tx_queue_set(sk, new_index);

		queue_index = new_index;
	}

	return queue_index;
}

static inline int queue_deactivated(struct sk_buff *skb)
{
	const struct net_device_ops *ops = skb->dev->netdev_ops;
	u16 queue_index = 0;
	struct netdev_queue *txq;

	if (ops->ndo_select_queue)
		queue_index = ops->ndo_select_queue(skb->dev, skb, NULL,
						    __netdev_pick_tx);
	else if (skb->dev->real_num_tx_queues > 1)
		queue_index = skb_tx_hash(skb->dev, skb);

	txq = netdev_get_tx_queue(skb->dev, queue_index);
	return txq->qdisc->state & 2;
}

static int send_finish(struct sk_buff *skb)
{
	return dev_queue_xmit(skb);
}

static int send(struct rxe_dev *rxe, struct sk_buff *skb)
{
	if (queue_deactivated(skb))
		return RXE_QUEUE_STOPPED;

	if (netif_queue_stopped(skb->dev))
		return RXE_QUEUE_STOPPED;

	return NF_HOOK(NFPROTO_RXE, NF_RXE_OUT, skb, rxe->ndev, NULL,
		send_finish);
}

static int loopback_finish(struct sk_buff *skb)
{
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	struct packet_type *ptype = NULL;
	struct net_device *orig_dev = pkt->rxe->ndev;

	return rxe_net_rcv(skb, pkt->rxe->ndev, ptype, orig_dev);
}

static int loopback(struct rxe_dev *rxe, struct sk_buff *skb)
{
	return NF_HOOK(NFPROTO_RXE, NF_RXE_OUT, skb, rxe->ndev, NULL,
		loopback_finish);
}

static inline int addr_same(struct rxe_dev *rxe, struct rxe_av *av)
{
	int port_num = 1;

	return rxe->port[port_num - 1].guid_tbl[0]
			== av->attr.grh.dgid.global.interface_id;
}

static struct sk_buff *init_packet(struct rxe_dev *rxe, struct rxe_av *av,
				   int paylen, int align)
{
	struct sk_buff *skb;
	struct rxe_pkt_info *pkt;
	int pad;

	/* finish computing (negative)alignment MOD 16 of IB payload */
	pad = (-(RXE_GRH_BYTES + LL_RESERVED_SPACE(rxe->ndev) + align)) &
		RXE_SKB_ALIGN_PAD_MASK;

	skb = alloc_skb(paylen + RXE_GRH_BYTES +
			LL_RESERVED_SPACE(rxe->ndev) + pad, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, LL_RESERVED_SPACE(rxe->ndev) + pad);
	skb_reset_network_header(skb);

	skb->dev	= rxe->ndev;
	skb->protocol	= htons(rxe_eth_proto_id);

	pkt		= SKB_TO_PKT(skb);
	pkt->rxe	= rxe;
	pkt->port_num	= 1;
	pkt->hdr	= skb_put(skb, RXE_GRH_BYTES + paylen);
	pkt->mask	= RXE_GRH_MASK;

	dev_hard_header(skb, rxe->ndev, rxe_eth_proto_id,
			av->ll_addr, rxe->ndev->dev_addr, skb->len);

	if (addr_same(rxe, av))
		pkt->mask |= RXE_LOOPBACK_MASK;

	return skb;
}

static int init_av(struct rxe_dev *rxe, struct ib_ah_attr *attr,
		   struct rxe_av *av)
{
	struct in6_addr *in6 = (struct in6_addr *)attr->grh.dgid.raw;

	/* grh required for rxe_net */
	if ((attr->ah_flags & IB_AH_GRH) == 0) {
		if (rxe_loopback_mad_grh_fix) {
			/* temporary fix so that we can handle mad's to self
			   without grh's included add grh pointing to self */
			attr->ah_flags |= IB_AH_GRH;
			attr->grh.dgid.global.subnet_prefix
				= rxe->port[0].subnet_prefix;
			attr->grh.dgid.global.interface_id
				= rxe->port[0].guid_tbl[0];
			av->attr = *attr;
		} else {
			pr_info("rxe_net: attempting to init av without grh\n");
			return -EINVAL;
		}
	}

	if (rdma_link_local_addr(in6)) {
		rdma_get_ll_mac(in6, av->ll_addr);
	} else if (rdma_is_multicast_addr(in6)) {
		rdma_get_mcast_mac(in6, av->ll_addr);
	} else {
		int i;
		char addr[64];

		for (i = 0; i < 16; i++)
			sprintf(addr+2*i, "%02x", attr->grh.dgid.raw[i]);

		pr_info("rxe_net: non local subnet address not supported %s\n",
			addr);
		return -EINVAL;
	}

	return 0;
}

/*
 * this is required by rxe_cfg to match rxe devices in
 * /sys/class/infiniband up with their underlying ethernet devices
 */
static char *parent_name(struct rxe_dev *rxe, unsigned int port_num)
{
	return rxe->ndev->name;
}

static enum rdma_link_layer link_layer(struct rxe_dev *rxe,
				       unsigned int port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

static struct rxe_ifc_ops ifc_ops = {
	.release	= release,
	.node_guid	= node_guid,
	.port_guid	= port_guid,
	.dma_device	= dma_device,
	.mcast_add	= mcast_add,
	.mcast_delete	= mcast_delete,
	.send		= send,
	.loopback	= loopback,
	.init_packet	= init_packet,
	.init_av	= init_av,
	.parent_name	= parent_name,
	.link_layer	= link_layer,
};

/* Caller must hold net_info_lock */
void rxe_net_add(struct net_device *ndev)
{
	int err;
	struct rxe_dev *rxe;
	unsigned port_num;

	__module_get(THIS_MODULE);

	rxe = (struct rxe_dev *)ib_alloc_device(sizeof(*rxe));
	if (!rxe) {
		err = -ENOMEM;
		goto err1;
	}

	/* for now we always assign port = 1 */
	port_num = 1;

	rxe->ifc_ops = &ifc_ops;

	rxe->ndev = ndev;

	err = rxe_add(rxe, ndev->mtu);
	if (err)
		goto err2;

	pr_info("rxe_net: added %s to %s\n",
		rxe->ib_dev.name, ndev->name);

	net_info[ndev->ifindex].rxe = rxe;
	net_info[ndev->ifindex].port = port_num;
	net_info[ndev->ifindex].ndev = ndev;
	return;

err2:
	ib_dealloc_device(&rxe->ib_dev);
err1:
	module_put(THIS_MODULE);
}

/* Caller must hold net_info_lock */
void rxe_net_up(struct net_device *ndev)
{
	struct rxe_dev *rxe;
	struct rxe_port *port;
	u8 port_num;

	if (ndev->ifindex >= RXE_MAX_IF_INDEX)
		goto out;

	net_info[ndev->ifindex].status = IB_PORT_ACTIVE;

	rxe = net_to_rxe(ndev);
	if (!rxe)
		goto out;

	port_num = net_to_port(ndev);
	port = &rxe->port[port_num-1];
	port->attr.state = IB_PORT_ACTIVE;
	port->attr.phys_state = IB_PHYS_STATE_LINK_UP;

	pr_info("rxe_net: set %s active for %s\n",
		rxe->ib_dev.name, ndev->name);
out:
	return;
}

/* Caller must hold net_info_lock */
void rxe_net_down(struct net_device *ndev)
{
	struct rxe_dev *rxe;
	struct rxe_port *port;
	u8 port_num;

	if (ndev->ifindex >= RXE_MAX_IF_INDEX)
		goto out;

	net_info[ndev->ifindex].status = IB_PORT_DOWN;

	rxe = net_to_rxe(ndev);
	if (!rxe)
		goto out;

	port_num = net_to_port(ndev);
	port = &rxe->port[port_num-1];
	port->attr.state = IB_PORT_DOWN;
	port->attr.phys_state = 3;

	pr_info("rxe_net: set %s down for %s\n",
		rxe->ib_dev.name, ndev->name);
out:
	return;
}

static int can_support_rxe(struct net_device *ndev)
{
	int rc = 0;

	if (ndev->ifindex >= RXE_MAX_IF_INDEX) {
		pr_debug("%s index %d: too large for rxe ndev table\n",
			 ndev->name, ndev->ifindex);
		goto out;
	}

	/* Let's says we support all ethX devices */
	if (ndev->type == ARPHRD_ETHER)
		rc = 1;

out:
	return rc;
}

static int rxe_notify(struct notifier_block *not_blk,
		      unsigned long event,
		      void *arg)
{
	struct rxe_dev *rxe;
	struct net_device *ndev = netdev_notifier_info_to_dev(arg);

	if (!can_support_rxe(ndev))
		goto out;

	spin_lock_bh(&net_info_lock);
	switch (event) {
	case NETDEV_REGISTER:
		/* Keep a record of this NIC. */
		net_info[ndev->ifindex].status = IB_PORT_DOWN;
		net_info[ndev->ifindex].rxe = NULL;
		net_info[ndev->ifindex].port = 1;
		net_info[ndev->ifindex].ndev = ndev;
		break;

	case NETDEV_UNREGISTER:
		if (net_info[ndev->ifindex].rxe) {
			rxe = net_info[ndev->ifindex].rxe;
			net_info[ndev->ifindex].rxe = NULL;
			spin_unlock_bh(&net_info_lock);
			rxe_remove(rxe);
			spin_lock_bh(&net_info_lock);
		}
		net_info[ndev->ifindex].status = 0;
		net_info[ndev->ifindex].port = 0;
		net_info[ndev->ifindex].ndev = NULL;
		break;

	case NETDEV_UP:
		rxe_net_up(ndev);
		break;

	case NETDEV_DOWN:
		rxe_net_down(ndev);
		break;

	case NETDEV_CHANGEMTU:
		rxe = net_to_rxe(ndev);
		if (rxe) {
			pr_info("rxe_net: %s changed mtu to %d\n",
				ndev->name, ndev->mtu);
			rxe_set_mtu(rxe, ndev->mtu, net_to_port(ndev));
		}
		break;

	case NETDEV_REBOOT:
	case NETDEV_CHANGE:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGENAME:
	case NETDEV_FEAT_CHANGE:
	default:
		pr_info("rxe_net: ignoring netdev event = %ld for %s\n",
			event, ndev->name);
		break;
	}
	spin_unlock_bh(&net_info_lock);

out:
	return NOTIFY_OK;
}

static int rxe_net_rcv(struct sk_buff *skb,
		       struct net_device *ndev,
		       struct packet_type *ptype,
		       struct net_device *orig_dev)
{
	struct rxe_dev *rxe = net_to_rxe(ndev);
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	int rc = 0;

	if (!rxe)
		goto drop;

	/* TODO: We can receive packets in fragments. For now we
	 * linearize and it's costly because we may copy a lot of
	 * data. We should handle that case better. */
	if (skb_linearize(skb))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb) {
		/* still return null */
		goto out;
	}

	/* set required fields in pkt */
	pkt->rxe = rxe;
	pkt->port_num = net_to_port(ndev);
	pkt->hdr = skb_network_header(skb);
	pkt->mask = RXE_GRH_MASK;

	rc = NF_HOOK(NFPROTO_RXE, NF_RXE_IN, skb, ndev, NULL, rxe_rcv);
out:
	return rc;

drop:
	kfree_skb(skb);
	return 0;
}

static struct packet_type rxe_packet_type = {
	.func = rxe_net_rcv,
};

static struct notifier_block rxe_net_notifier = {
	.notifier_call = rxe_notify,
};

static int __init rxe_net_init(void)
{
	int err;

	spin_lock_init(&net_info_lock);

	if (rxe_eth_proto_id != ETH_P_RXE)
		pr_info("rxe_net: protoid set to 0x%x\n",
			rxe_eth_proto_id);

	rxe_packet_type.type = cpu_to_be16(rxe_eth_proto_id);
	dev_add_pack(&rxe_packet_type);

	err = register_netdevice_notifier(&rxe_net_notifier);

	pr_info("rxe_net: loaded\n");

	return err;
}

static void __exit rxe_net_exit(void)
{
	unregister_netdevice_notifier(&rxe_net_notifier);
	dev_remove_pack(&rxe_packet_type);

	pr_info("rxe_net: unloaded\n");
}

module_init(rxe_net_init);
module_exit(rxe_net_exit);

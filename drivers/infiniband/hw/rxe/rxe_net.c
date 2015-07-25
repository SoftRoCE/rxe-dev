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
#include <net/udp_tunnel.h>
#include <net/sch_generic.h>
#include <linux/netfilter.h>
#include <rdma/ib_addr.h>
#include <net/ip6_tunnel.h>

#include "rxe.h"
#include "rxe_net.h"
#include "rxe_loc.h"

/*
 * note: this table is a replacement for a protocol specific pointer
 * in struct net_device which exists for other ethertypes
 * this allows us to not have to patch that data structure
 * eventually we want to get our own when we're famous
 */
struct list_head net_info_list;
spinlock_t net_info_lock; /* spinlock for net_info list */

struct rxe_addr_info addr_info;


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

static struct rtable *rxe_find_route4(struct in_addr *saddr,
				      struct in_addr *daddr)
{
	struct rtable *rt;
	struct flowi4 fl;

	memset(&fl, 0, sizeof(fl));
	memcpy(&fl.saddr, saddr, sizeof(*saddr));
	memcpy(&fl.daddr, daddr, sizeof(*daddr));
	fl.flowi4_proto = IPPROTO_UDP;

	rt = ip_route_output_key(&init_net, &fl);
	if (IS_ERR(rt)) {
		pr_err("no route to %pI4\n", &daddr->s_addr);
		return NULL;
	}

	return rt;
}

static struct dst_entry *rxe_find_route6(struct net_device *ndev,
					 struct in6_addr *saddr,
					 struct in6_addr *daddr)
{
	struct dst_entry *ndst;
	struct flowi6 fl6;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_oif = ndev->ifindex;
	memcpy(&fl6.saddr, saddr, sizeof(*saddr));
	memcpy(&fl6.daddr, daddr, sizeof(*daddr));
	fl6.flowi6_proto = IPPROTO_UDP;

	if (ipv6_stub->ipv6_dst_lookup(addr_info.sock6->sk, &ndst, &fl6)) {
		pr_err("no route to %pI6\n", daddr);
		goto put;
	}

	if (ndst->error) {
		pr_err("no route to %pI6\n", daddr);
		goto put;
	}

	return ndst;
put:
	dst_release(ndst);
	return NULL;
}

static int rxe_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct udphdr *udph;
	struct net_device *ndev = skb->dev;
	struct rxe_net_info_list *net_info_item =
			net_info_list_get(ndev->ifindex, 0);
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);

	if (!net_info_item || !net_info_item->rxe)
		goto drop;

	if (skb_linearize(skb)) {
		pr_err("skb_linearize failed\n");
		goto drop;
	}

	udph = udp_hdr(skb);
	pkt->rxe = net_info_item->rxe;
	pkt->port_num = net_info_item->port;
	pkt->hdr = (u8 *)(udph + 1);
	pkt->mask = RXE_GRH_MASK;
	pkt->paylen = be16_to_cpu(udph->len) - sizeof(*udph);

	return rxe_rcv(skb);
drop:
	kfree_skb(skb);
	return 0;
}

static struct socket *rxe_setup_udp_tunnel(struct net *net, bool ipv6,
					   __be16 port)
{
	int err;
	struct socket *sock;
	struct udp_port_cfg udp_cfg;
	struct udp_tunnel_sock_cfg tnl_cfg;

	memset(&udp_cfg, 0, sizeof(udp_cfg));

	if (ipv6) {
		udp_cfg.family = AF_INET6;
		udp_cfg.reuse_port = true;
	} else {
		udp_cfg.family = AF_INET;
		udp_cfg.reuse_port = true;
		udp_cfg.local_ip.s_addr = htonl(INADDR_ANY);
	}

	udp_cfg.local_udp_port = port;

	/* Create UDP socket */
	err = udp_sock_create(net, &udp_cfg, &sock);
	if (err < 0) {
		pr_err("failed to create udp socket. err = %d\n", err);
		return ERR_PTR(err);
	}

	tnl_cfg.sk_user_data = NULL;
	tnl_cfg.encap_type = 1;
	tnl_cfg.encap_rcv = rxe_udp_encap_recv;
	tnl_cfg.encap_destroy = NULL;

	/* Setup UDP tunnel */
	setup_udp_tunnel_sock(net, sock, &tnl_cfg);

	return sock;
}

static void rxe_release_udp_tunnel(struct socket *sk)
{
	udp_tunnel_sock_release(sk);
}

static int send(struct rxe_dev *rxe, struct sk_buff *skb)
{
	int sent_bytes = 0;
	struct sk_buff *nskb;
	size_t payload;
	struct rxe_pkt_info *npkt = SKB_TO_PKT(skb);
	bool csum_nocheck = true;
	struct rxe_pkt_info *pkt = SKB_TO_PKT(skb);
	struct rxe_av *av;
	int err;
	u32 *crc;
	struct iphdr *iph;

	if (qp_type(pkt->qp) == IB_QPT_RC || qp_type(pkt->qp) == IB_QPT_UC)
		av = &pkt->qp->pri_av;
	else
		av = &pkt->wqe->av;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if (!nskb)
		return -ENOMEM;

	if (av->network_type == RDMA_NETWORK_IPV4) {
		__be16 df = htons(IP_DF);
		bool xnet = false;
		struct in_addr *saddr = &av->sgid_addr._sockaddr_in.sin_addr;
		struct in_addr *daddr = &av->dgid_addr._sockaddr_in.sin_addr;
		struct rtable *rt = rxe_find_route4(saddr, daddr);

		if (!rt) {
			kfree(nskb);
			return -EHOSTUNREACH;
		}

		udp_tunnel_prepare_skb(rt, nskb, saddr->s_addr,
				       daddr->s_addr,
				       av->attr.grh.traffic_class,
				       av->attr.grh.hop_limit,
				       df, htons(0xc000),
				       htons(ROCE_V2_UDP_DPORT),
				       xnet,
				       csum_nocheck);

		sent_bytes = nskb->len;
		iptunnel_prepare(rt, nskb, saddr->s_addr,
				 daddr->s_addr, IPPROTO_UDP,
				 av->attr.grh.traffic_class,
				 av->attr.grh.hop_limit, df, xnet);

		iph = ip_hdr(nskb);
		iph->tot_len = htons(nskb->len);
		ip_send_check(iph);

		/* CRC */
		npkt = SKB_TO_PKT(nskb);
		payload = payload_size(npkt);
		crc = payload_addr(npkt) + payload;
		*crc = rxe_icrc_pkt(npkt);

		err = ip_local_out_sk(nskb->sk, nskb);
		if (unlikely(net_xmit_eval(err)))
			sent_bytes = 0;

	} else if (av->network_type == RDMA_NETWORK_IPV6) {
		struct in6_addr *saddr = &av->sgid_addr._sockaddr_in6.sin6_addr;
		struct in6_addr *daddr = &av->dgid_addr._sockaddr_in6.sin6_addr;
		struct dst_entry *dst = rxe_find_route6(rxe->ndev,
							saddr, daddr);

		if (!dst) {
			kfree(nskb);
			return -EHOSTUNREACH;
		}

		udp_tunnel6_prepare_skb(dst, nskb, rxe->ndev,
					saddr, daddr,
					av->attr.grh.traffic_class,
					av->attr.grh.hop_limit,
					htons(0xc000),
					htons(ROCE_V2_UDP_DPORT),
					csum_nocheck);

		ip6_set_len(nskb);

		/* CRC */
		npkt = SKB_TO_PKT(nskb);
		payload = payload_size(npkt);
		crc = payload_addr(npkt) + payload;
		*crc = rxe_icrc_pkt(npkt);

		sent_bytes = ip6tunnel_xmit(nskb->sk, nskb, rxe->ndev);
	}

	if (sent_bytes > 0) {
		kfree_skb(skb);
		return 0;
	}

	return sent_bytes < 0 ? sent_bytes : -EAGAIN;
}

static int loopback(struct sk_buff *skb)
{
	return rxe_rcv(skb);
}

static inline int addr_same(struct rxe_dev *rxe, struct rxe_av *av)
{
	int port_num = 1;

	return rxe->port[port_num - 1].guid_tbl[0]
			== av->attr.grh.dgid.global.interface_id;
}

static struct sk_buff *init_packet(struct rxe_dev *rxe, struct rxe_av *av,
				   int paylen)
{
	struct sk_buff *skb;
	struct rxe_pkt_info *pkt;
	unsigned int hdr_len = sizeof(struct ethhdr) +
			       sizeof(struct udphdr);

	if (av->network_type == RDMA_NETWORK_IPV4)
		hdr_len += sizeof(struct iphdr);
	else
		hdr_len += sizeof(struct ipv6hdr);

	skb = alloc_skb(paylen + hdr_len + LL_RESERVED_SPACE(rxe->ndev),
			GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, hdr_len + LL_RESERVED_SPACE(rxe->ndev));

	skb->dev	= rxe->ndev;
	if (av->network_type == RDMA_NETWORK_IPV4)
		skb->protocol = htons(ETH_P_IP);
	else
		skb->protocol = htons(ETH_P_IPV6);

	pkt		= SKB_TO_PKT(skb);
	pkt->rxe	= rxe;
	pkt->port_num	= 1;
	pkt->hdr	= skb_put(skb, paylen);
	pkt->mask	= RXE_GRH_MASK;

	if (addr_same(rxe, av))
		pkt->mask |= RXE_LOOPBACK_MASK;

	return skb;
}

static int init_av(struct rxe_dev *rxe, struct ib_ah_attr *attr,
		   struct rxe_av *av)
{
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
void rxe_net_add(struct rxe_net_info_list *info_item)
{
	int err;
	struct rxe_dev *rxe;

	__module_get(THIS_MODULE);

	rxe = (struct rxe_dev *)ib_alloc_device(sizeof(*rxe));
	if (!rxe) {
		err = -ENOMEM;
		goto err1;
	}

	rxe->ifc_ops = &ifc_ops;
	rxe->ndev = info_item->ndev;

	err = rxe_add(rxe, info_item->ndev->mtu);
	if (err)
		goto err2;

	pr_info("rxe: added %s to %s\n",
		rxe->ib_dev.name, info_item->ndev->name);

	info_item->rxe = rxe;
	/* for now we always assign port = 1 */
	info_item->port = 1;

	return;

err2:
	ib_dealloc_device(&rxe->ib_dev);
err1:
	module_put(THIS_MODULE);
}

/* Caller must hold net_info_lock */
void rxe_net_up(struct net_device *ndev, struct rxe_net_info_list *info_item)
{
	struct rxe_port *port;

	info_item->status = IB_PORT_ACTIVE;

	if (!info_item->rxe)
		return;

	port = &info_item->rxe->port[info_item->port-1];
	port->attr.state = IB_PORT_ACTIVE;
	port->attr.phys_state = IB_PHYS_STATE_LINK_UP;

	pr_info("rxe: set %s active for %s\n",
		info_item->rxe->ib_dev.name, ndev->name);
}

/* Caller must hold net_info_lock */
void rxe_net_down(struct net_device *ndev, struct rxe_net_info_list *info_item)
{
	struct rxe_port *port;

	info_item->status = IB_PORT_DOWN;

	if (!info_item->rxe)
		return;

	port = &info_item->rxe->port[info_item->port-1];
	port->attr.state = IB_PORT_DOWN;
	port->attr.phys_state = 3;

	pr_info("rxe: set %s down for %s\n",
		info_item->rxe->ib_dev.name, ndev->name);
}

static int can_support_rxe(struct net_device *ndev)
{
	/* Let's says we support all ethX devices */
	return (ndev->type == ARPHRD_ETHER);
}

static int rxe_notify(struct notifier_block *not_blk,
		      unsigned long event,
		      void *arg)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(arg);
	struct rxe_net_info_list *net_info_item;

	if (!can_support_rxe(ndev))
		goto out;

	spin_lock_bh(&net_info_lock);
	net_info_item = net_info_list_get(ndev->ifindex, 1);
	switch (event) {
	case NETDEV_REGISTER:
		/* Keep a record of this NIC. */
		net_info_item->status = IB_PORT_DOWN;
		net_info_item->rxe = NULL;
		net_info_item->port = 1;
		net_info_item->ndev = ndev;
		break;

	case NETDEV_UNREGISTER:
		if (net_info_item->rxe) {
			struct rxe_dev *rxe = net_info_item->rxe;

			net_info_item->rxe = NULL;
			spin_unlock_bh(&net_info_lock);
			rxe_remove(rxe);
			spin_lock_bh(&net_info_lock);
		}
		list_del(&net_info_item->list);
		kfree(net_info_item);
		break;

	case NETDEV_UP:
		rxe_net_up(ndev, net_info_item);
		break;

	case NETDEV_DOWN:
		rxe_net_down(ndev, net_info_item);
		break;

	case NETDEV_CHANGEMTU:
		if (net_info_item->rxe) {
			pr_info("rxe: %s changed mtu to %d\n",
				ndev->name, ndev->mtu);
			rxe_set_mtu(net_info_item->rxe, ndev->mtu,
				    net_info_item->port);
		}
		break;

	case NETDEV_REBOOT:
	case NETDEV_CHANGE:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGENAME:
	case NETDEV_FEAT_CHANGE:
	default:
		pr_info("rxe: ignoring netdev event = %ld for %s\n",
			event, ndev->name);
		break;
	}
	spin_unlock_bh(&net_info_lock);

out:
	return NOTIFY_OK;
}

struct rxe_net_info_list *net_info_list_add(int index)
{
	struct rxe_net_info_list *net_info_item;

	net_info_item = kzalloc(sizeof(*net_info_item), GFP_KERNEL);
	if (net_info_item) {
		net_info_item->ifindex = index;
		INIT_LIST_HEAD(&net_info_item->list);
		list_add(&net_info_item->list, &net_info_list);
	}

	return net_info_item;
}

struct rxe_net_info_list *net_info_list_get(int index, int add_if_missing)
{
	struct rxe_net_info_list *net_info_item;

	if (list_empty(&net_info_list))
		goto out;

	list_for_each_entry(net_info_item, &net_info_list, list)
		if (net_info_item->ifindex == index)
			return net_info_item;

out:
	return add_if_missing ? net_info_list_add(index) : NULL;
}

static void net_info_list_release(void)
{
	struct rxe_net_info_list *net_info_item, *net_info_temp;

	if (!list_empty(&net_info_list))
		list_for_each_entry_safe(net_info_item, net_info_temp,
					 &net_info_list, list)
			kfree(net_info_item);
}

static struct notifier_block rxe_net_notifier = {
	.notifier_call = rxe_notify,
};

int rxe_net_init(void)
{
	int err;

	INIT_LIST_HEAD(&net_info_list);
	spin_lock_init(&net_info_lock);

	addr_info.sock4 = rxe_setup_udp_tunnel(&init_net, 0,
					       htons(ROCE_V2_UDP_DPORT));
	if (IS_ERR(addr_info.sock4)) {
		addr_info.sock4 = NULL;
		pr_err("rxe: Failed to create IPv4 UDP tunnel\n");
		return -1;
	}

	addr_info.sock6 = rxe_setup_udp_tunnel(&init_net, 1,
					       htons(ROCE_V2_UDP_DPORT));
	if (IS_ERR(addr_info.sock6)) {
		addr_info.sock6 = NULL;
		rxe_release_udp_tunnel(addr_info.sock4);
		pr_err("rxe_net: Failed to create IPv6 UDP tunnel\n");
		return -1;
	}

	err = register_netdevice_notifier(&rxe_net_notifier);

	return err;
}

void rxe_net_exit(void)
{
	if (addr_info.sock6)
		rxe_release_udp_tunnel(addr_info.sock6);
	if (addr_info.sock4)
		rxe_release_udp_tunnel(addr_info.sock4);

	spin_lock_bh(&net_info_lock);
	net_info_list_release();
	spin_unlock_bh(&net_info_lock);

	unregister_netdevice_notifier(&rxe_net_notifier);
}

/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
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
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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

#ifndef _CORE_PRIV_H
#define _CORE_PRIV_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <net/net_namespace.h>

#include <rdma/ib_verbs.h>

extern struct workqueue_struct *roce_gid_mgmt_wq;

int  ib_device_register_sysfs(struct ib_device *device,
			      int (*port_callback)(struct ib_device *,
						   u8, struct kobject *));
void ib_device_unregister_sysfs(struct ib_device *device);

int  ib_sysfs_setup(void);
void ib_sysfs_cleanup(void);

int  ib_cache_setup(void);
void ib_cache_cleanup(void);

int ib_resolve_eth_l2_attrs(struct ib_qp *qp,
			    struct ib_qp_attr *qp_attr, int *qp_attr_mask);

typedef void (*roce_netdev_callback)(struct ib_device *device, u8 port,
	      struct net_device *idev, void *cookie);

typedef int (*roce_netdev_filter)(struct ib_device *device, u8 port,
	     struct net_device *idev, void *cookie);

void ib_dev_roce_ports_of_netdev(struct ib_device *ib_dev,
				 roce_netdev_filter filter,
				 void *filter_cookie,
				 roce_netdev_callback cb,
				 void *cookie);
void ib_enum_roce_ports_of_netdev(roce_netdev_filter filter,
				  void *filter_cookie,
				  roce_netdev_callback cb,
				  void *cookie);

int roce_gid_cache_get_gid(struct ib_device *ib_dev, u8 port, int index,
			   union ib_gid *gid, struct ib_gid_attr *attr);

int roce_gid_cache_find_gid(struct ib_device *ib_dev, union ib_gid *gid,
			    enum ib_gid_type gid_type, struct net *net,
			    int if_index, u8 *port, u16 *index);

int roce_gid_cache_find_gid_by_port(struct ib_device *ib_dev, union ib_gid *gid,
				    enum ib_gid_type gid_type, u8 port,
				    struct net *net, int if_index, u16 *index);

int roce_gid_cache_is_active(struct ib_device *ib_dev, u8 port);

int roce_gid_cache_setup(void);
void roce_gid_cache_cleanup(void);

int roce_add_gid(struct ib_device *ib_dev, u8 port,
		 union ib_gid *gid, struct ib_gid_attr *attr);

int roce_del_gid(struct ib_device *ib_dev, u8 port,
		 union ib_gid *gid, struct ib_gid_attr *attr);

int roce_del_all_netdev_gids(struct ib_device *ib_dev, u8 port,
			     struct net_device *ndev);

int roce_gid_mgmt_init(void);
void roce_gid_mgmt_cleanup(void);

int roce_rescan_device(struct ib_device *ib_dev);

#endif /* _CORE_PRIV_H */

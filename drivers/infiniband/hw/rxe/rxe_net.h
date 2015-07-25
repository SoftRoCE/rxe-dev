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

#ifndef RXE_NET_H
#define RXE_NET_H

#include <net/sock.h>
#include <net/if_inet6.h>
#include <linux/module.h>

struct rxe_net_info_list {
	int			ifindex;
	struct rxe_dev		*rxe;
	u8			port;
	struct net_device	*ndev;
	int			status;
	struct list_head	list;
};

struct rxe_addr_info {
	struct socket *sock4;
	struct socket *sock6;
};

extern struct rxe_addr_info addr_info;
extern struct list_head net_info_list;
extern spinlock_t net_info_lock;

struct rxe_net_info_list *net_info_list_add(int ifindex);
struct rxe_net_info_list *net_info_list_get(int ifindex, int add_if_missing);
void rxe_net_add(struct rxe_net_info_list *info_item);
void rxe_net_up(struct net_device *ndev, struct rxe_net_info_list *info_item);
void rxe_net_down(struct net_device *ndev, struct rxe_net_info_list *info_item);

int rxe_net_init(void);
void rxe_net_exit(void);

#endif /* RXE_NET_H */

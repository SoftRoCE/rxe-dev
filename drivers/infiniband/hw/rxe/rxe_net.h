/*
 * Copyright (c) 2016 Mellanox Technologies Ltd. All rights reserved.
 * Copyright (c) 2015 System Fabric Works, Inc. All rights reserved.
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

#define RXE_MAX_IF_INDEX	(384)

struct rxe_net_info {
	struct rxe_dev		*rxe;
	u8			port;
	struct net_device	*ndev;
	int			status;
};

struct rxe_recv_sockets {
	struct socket *sk4;
	struct socket *sk6;
};

extern struct rxe_recv_sockets recv_sockets;
extern struct rxe_net_info net_info[RXE_MAX_IF_INDEX];
extern spinlock_t net_info_lock;

/* caller must hold net_dev_lock */
static inline struct rxe_dev *net_to_rxe(struct net_device *ndev)
{
	return (ndev->ifindex >= RXE_MAX_IF_INDEX) ?
		NULL : net_info[ndev->ifindex].rxe;
}

static inline u8 net_to_port(struct net_device *ndev)
{
	return net_info[ndev->ifindex].port;
}

int rxe_net_add(struct net_device *ndev);
void rxe_net_up(struct net_device *ndev);
void rxe_net_down(struct net_device *ndev);

int rxe_net_init(void);
void rxe_net_exit(void);

#endif /* RXE_NET_H */

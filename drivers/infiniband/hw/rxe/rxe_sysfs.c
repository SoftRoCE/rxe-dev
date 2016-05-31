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

#include "rxe.h"
#include "rxe_net.h"

/* Copy argument and remove trailing CR. Return the new length. */
static int sanitize_arg(const char *val, char *intf, int intf_len)
{
	int len;

	if (!val)
		return 0;

	/* Remove newline. */
	for (len = 0; len < intf_len - 1 && val[len] && val[len] != '\n'; len++)
		intf[len] = val[len];
	intf[len] = 0;

	if (len == 0 || (val[len] != 0 && val[len] != '\n'))
		return 0;

	return len;
}

/* Caller must hold net_info_lock */
static void rxe_set_port_state(struct net_device *ndev)
{
	struct rxe_dev *rxe;

	rxe = net_to_rxe(ndev);
	if (!rxe)
		goto out;

	if (net_info[ndev->ifindex].status == IB_PORT_ACTIVE)
		rxe_net_up(ndev);
	else
		rxe_net_down(ndev); /* down for unknown state */
out:
	return;
}

static int rxe_param_set_add(const char *val, struct kernel_param *kp)
{
	int i, len, err;
	char intf[32];

	len = sanitize_arg(val, intf, sizeof(intf));
	if (!len) {
		pr_err("rxe: add: invalid interface name\n");
		return -EINVAL;
	}

	spin_lock_bh(&net_info_lock);
	for (i = 0; i < RXE_MAX_IF_INDEX; i++) {
		struct net_device *ndev = net_info[i].ndev;

		if (ndev && (!strncmp(intf, ndev->name, len))) {
			spin_unlock_bh(&net_info_lock);
			if (net_info[i].rxe)
				pr_info("rxe: already configured on %s\n",
					intf);
			else {
				err = rxe_net_add(ndev);
				if (!err && net_info[i].rxe) {
					rxe_set_port_state(ndev);
				} else {
					pr_err("rxe: add appears to have failed for %s (index %d)\n",
					       intf, i);
				}
			}
			return 0;
		}
	}
	spin_unlock_bh(&net_info_lock);

	pr_warn("interface %s not found\n", intf);

	return 0;
}

static int rxe_param_set_remove(const char *val, struct kernel_param *kp)
{
	int i, len;
	char intf[32];
	struct rxe_dev *rxe;

	len = sanitize_arg(val, intf, sizeof(intf));
	if (!len) {
		pr_err("rxe: remove: invalid interface name\n");
		return -EINVAL;
	}

	if (strncmp("all", intf, len) == 0) {
		pr_info("rxe_sys: remove all");
		rxe_remove_all();
		return 0;
	}

	spin_lock_bh(&net_info_lock);
	for (i = 0; i < RXE_MAX_IF_INDEX; i++) {
		if (!net_info[i].rxe || !net_info[i].ndev)
			continue;

		if (!strncmp(intf, net_info[i].rxe->ib_dev.name, len)) {
			rxe = net_info[i].rxe;
			net_info[i].rxe = NULL;
			spin_unlock_bh(&net_info_lock);

			rxe_remove(rxe);
			return 0;
		}
	}
	spin_unlock_bh(&net_info_lock);
	pr_warn("rxe_sys: instance %s not found\n", intf);

	return 0;
}

module_param_call(add, rxe_param_set_add, NULL, NULL, 0200);
module_param_call(remove, rxe_param_set_remove, NULL, NULL, 0200);

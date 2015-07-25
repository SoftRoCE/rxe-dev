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
static void rxe_set_port_state(struct rxe_net_info_list *info_item)
{
	if (info_item->status == IB_PORT_ACTIVE)
		rxe_net_up(info_item->ndev, info_item);
	else
		rxe_net_down(info_item->ndev, info_item); /* down for unknown state */
}

static int rxe_param_set_add(const char *val, const struct kernel_param *kp)
{
	int len;
	struct rxe_net_info_list *info_item;
	char intf[32];

	len = sanitize_arg(val, intf, sizeof(intf));
	if (!len) {
		pr_err("rxe: add: invalid interface name\n");
		return -EINVAL;
	}

	spin_lock_bh(&net_info_lock);
	list_for_each_entry(info_item, &net_info_list, list)
		if (info_item->ndev && (0 == strncmp(intf,
					info_item->ndev->name, len))) {
			spin_unlock_bh(&net_info_lock);
			if (info_item->rxe)
				pr_info("rxe: already configured on %s\n",
					intf);
			else {
				rxe_net_add(info_item);
				if (info_item->rxe)
					rxe_set_port_state(info_item);
				else
					pr_err("rxe: add appears to have failed"
					       " for %s (index %d)\n",
						intf, info_item->ndev->ifindex);
			}
			return 0;
		}
	spin_unlock_bh(&net_info_lock);

	pr_warn("interface %s not found\n", intf);

	return 0;
}

static void rxe_remove_all(void)
{
	struct rxe_dev *rxe;
	struct rxe_net_info_list *info_item;

	list_for_each_entry(info_item, &net_info_list, list)
		if (info_item->rxe) {
			spin_lock_bh(&net_info_lock);
			rxe = info_item->rxe;
			info_item->rxe = NULL;
			spin_unlock_bh(&net_info_lock);

			rxe_remove(rxe);
		}
}

static int rxe_param_set_remove(const char *val, const struct kernel_param *kp)
{
	int len;
	char intf[32];
	struct rxe_dev *rxe;
	struct rxe_net_info_list *info_item;

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
	list_for_each_entry(info_item, &net_info_list, list)
		if (!info_item->rxe || !info_item->ndev)
			continue;
		else if (0 == strncmp(intf, info_item->rxe->ib_dev.name, len)) {
			rxe = info_item->rxe;
			info_item->rxe = NULL;
			spin_unlock_bh(&net_info_lock);

			rxe_remove(rxe);

			return 0;
		}
	spin_unlock_bh(&net_info_lock);

	pr_warn("rxe_sys: instance %s not found\n", intf);

	return 0;
}

static struct kernel_param_ops param_ops_add = {
	.set = rxe_param_set_add,
	.get = NULL,
};
module_param_cb(add, &param_ops_add, NULL, 0200);

static struct kernel_param_ops param_ops_remove = {
	.set = rxe_param_set_remove,
	.get = NULL,
};
module_param_cb(remove, &param_ops_remove, NULL, 0200);

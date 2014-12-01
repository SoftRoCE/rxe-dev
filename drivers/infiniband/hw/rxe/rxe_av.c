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
 *	   Redistribution and use in source and binary forms, with or
 *	   without modification, are permitted provided that the following
 *	   conditions are met:
 *
 *		- Redistributions of source code must retain the above
 *		  copyright notice, this list of conditions and the following
 *		  disclaimer.
 *
 *		- Redistributions in binary form must reproduce the above
 *		  copyright notice, this list of conditions and the following
 *		  disclaimer in the documentation and/or other materials
 *		  provided with the distribution.
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

/* address handle implementation shared by ah and qp verbs */

#include "rxe.h"
#include "rxe_loc.h"

int rxe_av_chk_attr(struct rxe_dev *rxe, struct ib_ah_attr *attr)
{
	struct rxe_port *port;

	if (attr->port_num < 1 || attr->port_num > rxe->num_ports) {
		pr_info("rxe: invalid port_num = %d\n", attr->port_num);
		return -EINVAL;
	}

	port = &rxe->port[attr->port_num - 1];

	if (attr->ah_flags & IB_AH_GRH) {
		if (attr->grh.sgid_index > port->attr.gid_tbl_len) {
			pr_info("rxe: invalid sgid index = %d\n",
				attr->grh.sgid_index);
			return -EINVAL;
		}
	}

	return 0;
}

int rxe_av_from_attr(struct rxe_dev *rxe, u8 port_num,
		     struct rxe_av *av, struct ib_ah_attr *attr)
{
	memset(av, 0, sizeof(*av));
	av->attr = *attr;
	av->attr.port_num = port_num;
	return rxe->ifc_ops->init_av(rxe, attr, av);
}

int rxe_av_to_attr(struct rxe_dev *rxe, struct rxe_av *av,
		   struct ib_ah_attr *attr)
{
	*attr = av->attr;
	return 0;
}

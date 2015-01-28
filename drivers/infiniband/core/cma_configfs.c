/*
 * Copyright (c) 2015, Mellanox Technologies inc.  All rights reserved.
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

#include <linux/configfs.h>
#include <rdma/ib_verbs.h>
#include "core_priv.h"

struct cma_device;

struct cma_dev_group {
	struct config_item	item;
};

struct cma_configfs_attr {
	struct configfs_attribute	attr;
	ssize_t				(*show)(struct cma_device *cma_dev,
						struct cma_dev_group *group,
						char *buf);
	ssize_t				(*store)(struct cma_device *cma_dev,
						 struct cma_dev_group *group,
						 const char *buf, size_t count);
};

static struct cma_dev_group *to_dev_group(struct config_item *item)
{
	return item ?
		container_of(item, struct cma_dev_group, item) :
		NULL;
}

static ssize_t show_default_roce_mode(struct cma_device *cma_dev,
				      struct cma_dev_group *group,
				      char *buf)
{
	return sprintf(buf, "%s",
		       roce_gid_cache_type_str(cma_get_default_gid_type(cma_dev)));
}

static ssize_t store_default_roce_mode(struct cma_device *cma_dev,
				       struct cma_dev_group *group,
				       const char *buf, size_t count)
{
	int gid_type = roce_gid_cache_parse_gid_str(buf);

	if (gid_type < 0)
		return -EINVAL;

	cma_set_default_gid_type(cma_dev, gid_type);

	return strnlen(buf, count);
}

#define CMA_PARAM_ATTR_RW(_name)				\
static struct cma_configfs_attr cma_configfs_attr_##_name =	\
	__CONFIGFS_ATTR(_name, S_IRUGO | S_IWUSR, show_##_name, store_##_name)

CMA_PARAM_ATTR_RW(default_roce_mode);

static bool filter_by_name(struct ib_device *ib_dev, void *cookie)
{
	return !strcmp(ib_dev->name, cookie);
}

static ssize_t cma_configfs_attr_show(struct config_item *item,
				      struct configfs_attribute *attr,
				      char *buf)
{
	ssize_t ret = -EINVAL;
	struct cma_device *cma_dev =
		cma_enum_devices_by_ibdev(filter_by_name, config_item_name(item));
	struct cma_dev_group *group = to_dev_group(item);
	struct cma_configfs_attr *ca =
		container_of(attr, struct cma_configfs_attr, attr);

	if (!cma_dev)
		return -ENODEV;

	if (ca->show)
		ret = ca->show(cma_dev, group, buf);

	cma_deref_dev(cma_dev);
	return ret;
}

static ssize_t cma_configfs_attr_store(struct config_item *item,
				       struct configfs_attribute *attr,
				       const char *buf, size_t count)
{
	ssize_t ret = -EINVAL;
	struct cma_device *cma_dev =
		cma_enum_devices_by_ibdev(filter_by_name, config_item_name(item));
	struct cma_dev_group *group = to_dev_group(item);
	struct cma_configfs_attr *ca =
		container_of(attr, struct cma_configfs_attr, attr);

	if (!cma_dev)
		return -ENODEV;

	if (ca->store)
		ret = ca->store(cma_dev, group, buf, count);

	cma_deref_dev(cma_dev);
	return ret;
}

static struct configfs_attribute *cma_configfs_attributes[] = {
	&cma_configfs_attr_default_roce_mode.attr,
	NULL,
};

static void cma_configfs_attr_release(struct config_item *item)
{
	kfree(to_dev_group(item));
}

static struct configfs_item_operations cma_item_ops = {
	.show_attribute		= cma_configfs_attr_show,
	.store_attribute	= cma_configfs_attr_store,
	.release		= cma_configfs_attr_release,
};

static struct config_item_type cma_item_type = {
	.ct_attrs	= cma_configfs_attributes,
	.ct_item_ops	= &cma_item_ops,
	.ct_owner	= THIS_MODULE
};

static struct config_item *make_cma_dev(struct config_group *group,
					const char *name)
{
	int err = -EINVAL;
	struct cma_device *cma_dev = cma_enum_devices_by_ibdev(filter_by_name,
							       (void *)name);
	struct cma_dev_group *cma_dev_group = NULL;

	if (!cma_dev)
		goto fail;

	cma_dev_group = kzalloc(sizeof(*cma_dev_group), GFP_KERNEL);

	if (!cma_dev_group) {
		err = -ENOMEM;
		goto fail;
	}

	config_item_init_type_name(&cma_dev_group->item, name, &cma_item_type);

	cma_deref_dev(cma_dev);
	return &cma_dev_group->item;

fail:
	if (cma_dev)
		cma_deref_dev(cma_dev);
	kfree(cma_dev_group);
	return ERR_PTR(err);
}

static void drop_cma_dev(struct config_group *group,
			 struct config_item *item)
{
	config_item_put(item);
}

static struct configfs_group_operations cma_subsys_group_ops = {
	.make_item	= make_cma_dev,
	.drop_item	= drop_cma_dev,
};

static struct config_item_type cma_subsys_type = {
	.ct_group_ops	= &cma_subsys_group_ops,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem cma_subsys = {
	.su_group	= {
		.cg_item	= {
			.ci_namebuf	= "rdma_cm",
			.ci_type	= &cma_subsys_type,
		},
	},
};

int __init cma_configfs_init(void)
{
	config_group_init(&cma_subsys.su_group);
	mutex_init(&cma_subsys.su_mutex);
	return configfs_register_subsystem(&cma_subsys);
}

void __exit cma_configfs_exit(void)
{
	configfs_unregister_subsystem(&cma_subsys);
}

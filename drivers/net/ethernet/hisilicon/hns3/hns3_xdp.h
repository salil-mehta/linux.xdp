// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifndef __HNS3_XDP_H
#define __HNS3_XDP_H
#include "hns3_enet.h"
#include "hnae3.h"
#include <net/xdp.h>

#ifdef CONFIG_HNS3_XDP
static inline bool hns3_is_xdp_enabled(struct net_device *netdev)
{
	struct hns3_nic_priv * priv = netdev_priv(netdev);
	struct hnae3_handle *h = hns3_get_handle(netdev);

	/* we do not support XDP on VF yet */
	if (h->flags & HNAE3_SUPPORT_VF)
		return false;

	return !!priv->xdp_prog;
}

int hns3_xdp(struct net_device *netdev, struct netdev_bpf *xdp);
bool hns3_xdp_check_max_mtu(struct net_device *netdev);
u32 hns3_xdp_max_mtu(struct net_device *netdev) ;
#else /* CONFIG_HNS3_XDP */
static inline bool hns3_is_xdp_enabled(struct net_device *netdev) { return false; }
int hns3_xdp(struct net_device *netdev, struct netdev_bpf *xdp)  { return 0; }
bool hns3_xdp_check_max_mtu(struct net_device *netdev)  { return false; }
u32 hns3_xdp_max_mtu(struct net_device *netdev)  { return 0; }
#endif

#endif

// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifndef __HNS3_XDP_H
#define __HNS3_XDP_H
#include "hns3_enet.h"
#include "hnae3.h"
#include <net/xdp.h>

enum hns3_xdp_status {
	HNS3_XDP_PASS = 0,
	HNS3_XDP_TX = BIT(0),
	HNS3_XDP_REDIRECT = BIT(1),
	HNS3_XDP_DROP = BIT(2),
};

#define HNS_XDP_DEBUG

#ifdef HNS_XDP_DEBUG
struct hns3_dbg_info {
	struct net_device *ndev;
	void *page;
	u32 pgoff;
	u16 pgrus;
	u16 pgcnt;
	u16 pgcnb;
	u16 pgcub;
};

static inline void 
hns3_get_dbg_info(struct hns3_enet_ring *ring, struct hns3_dbg_info *di)
{
	struct hns3_desc_cb *cb = ring->desc_cb;

	di->ndev = ring->netdev;
	di->page = cb->priv;
	di->pgoff = cb->page_offset;
	di->pgrus = cb->reuse_flag;
	di->pgcnt = page_count(cb->priv);
	di->pgcnb = cb->pagecnt_bias;
	di->pgcub = page_count(cb->priv) - cb->pagecnt_bias;
}

#define hns3_dbg(__dev, format, args...)						\
	do {								\
		if (!strcmp(__dev->name, "enp125s0f0"))					\
			netdev_printk(KERN_ERR, __dev, "[%s][%d]" format, __func__, __LINE__ , ##args);\
	} while (0)

#define hns3_dbg_pgr(_ring)	\
	do {	\
		struct hns3_dbg_info di;	\
		hns3_get_dbg_info(_ring, &di);	\
		if (!di.pgcub)	\
			hns3_dbg(di.ndev, "Bingo! diff is zero\n");	\
		hns3_dbg(di.ndev, "pgrus[%u], pgoff[%u] pgcnt[%d] pgcnb[%u] pgubc[%u]\n",	\
			 di.pgrus, di.pgoff, di.pgcnt, di.pgcnb, di.pgcub);	\
	} while (0)

#endif /* HNS_XDP_DEBUG */

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

int hns3_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames, u32 flags);
int hns3_xdp(struct net_device *netdev, struct netdev_bpf *xdp);
bool hns3_xdp_check_max_mtu(struct net_device *netdev);
u32 hns3_xdp_max_mtu(struct net_device *netdev) ;
int hns3_xdp_handle_rx_bd(struct hns3_enet_ring *ring);
u32 hns3_rx_headroom(struct net_device *netdev);
void hns3_xdp_complete(struct hns3_enet_ring *ring);
#else /* CONFIG_HNS3_XDP */
static inline bool hns3_is_xdp_enabled(struct net_device *netdev) { return false; }
int hns3_xdp(struct net_device *netdev, struct netdev_bpf *xdp)  { return 0; }
int hns3_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames, u32 flags) { return 0; }
bool hns3_xdp_check_max_mtu(struct net_device *netdev)  { return false; }
u32 hns3_xdp_max_mtu(struct net_device *netdev)  { return 0; }
int hns3_xdp_handle_rx_bd(struct hns3_enet_ring *ring) { return 0; }
u32 hns3_rx_headroom(struct net_device *netdev) { return 0; }
void hns3_xdp_complete(struct hns3_enet_ring *ring) { return; }
#endif

#endif

// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include <linux/bpf_trace.h>
#include <net/xdp_sock_drv.h>
#include "hns3_xdp.h"
#include "hnae3.h"
#include "hns3_enet.h"

u32 hns3_rx_headroom(struct net_device *netdev)
{
	bool is_xdp = hns3_is_xdp_enabled(netdev);
	u32 headroom;

	headroom = NET_IP_ALIGN;
	headroom += is_xdp ? XDP_PACKET_HEADROOM : NET_SKB_PAD;

	return headroom;
}

u32 hns3_xdp_max_mtu(struct net_device *netdev)
{
	u32 max_xdp_mtu = SKB_MAX_HEAD(hns3_rx_headroom(netdev)) ;

	max_xdp_mtu -= HNS3_ETH_HDR_PAD;

	return max_xdp_mtu;
}

bool hns3_xdp_check_max_mtu(struct net_device *netdev)
{
	return netdev->mtu <= hns3_xdp_max_mtu(netdev) ;
}

static int hns3_xdp_check(struct net_device *netdev, struct bpf_prog *prog)
{
	struct hns3_nic_priv *priv = netdev_priv(netdev);

	if (test_bit(HNS3_NIC_STATE_RESETTING, &priv->state))
	{
		netdev_err(netdev, "can't set XDP while device is resetting\n");
		return -EAGAIN;
	}

	 /* TODO:  Enable GRO check for hns3 here */

	if (!hns3_xdp_check_max_mtu(netdev)) {
		netdev_warn(netdev,
			      "For now, XDP is not supported with MTU exceeding %d\n",
			       hns3_xdp_max_mtu(netdev));
		return -EINVAL;
	}

	return 0;
}

static struct sk_buff *hns3_build_skb(struct hns3_enet_ring *ring, struct xdp_buff *xdp)
{
	struct net_device *netdev = ring_to_netdev(ring);
	u32 truesize = hns3_buf_size(ring);
	struct sk_buff *skb;

	skb = ring->skb = build_skb(xdp->data_hard_start, truesize);
	if (unlikely(!skb)) {
		if (net_ratelimit())
			netdev_err(netdev, "failed to build skb from xdp buf\n");

		u64_stats_update_begin(&ring->syncp);
		ring->stats.sw_err_cnt++;
		u64_stats_update_end(&ring->syncp);

		return ERR_PTR(-ENOMEM);
	}

	ring->pending_buf = 1;

	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	skb_put(skb, xdp->data_end - xdp->data);

	u64_stats_update_begin(&ring->syncp);
	ring->stats.seg_pkt_cnt++;
	u64_stats_update_end(&ring->syncp);

	hns3_rx_ring_move_fw(ring);

	return skb;
}

static bool
hns3_xdp_run(struct hns3_enet_ring *rx_ring, struct xdp_buff *xdp)
{
	struct bpf_prog *xdp_prog;
	u32 act;

	/* RFC Question: should we? Any security risk in this action? */
	/* Pass the buffer to stack if we cannot get hold of xdp prog */
	xdp_prog = READ_ONCE(rx_ring->xdp_prog);
	if (!xdp_prog)
		return  false;

	act = bpf_prog_run_xdp(xdp_prog, xdp);
	switch (act) {
	case XDP_PASS:
		return false;
	case XDP_TX:
		/* transmit the buffer on the XDP TX queue */
		return true;
	case XDP_REDIRECT:
		/* redirect the buffer to other device TX queue */
		return true;
	default:
		bpf_warn_invalid_xdp_action(act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		u64_stats_update_begin(&rx_ring->syncp);
		rx_ring->stats.xdp_rx_drop++;
		u64_stats_update_end(&rx_ring->syncp);
		return true;
	}
}

int hns3_xdp_handle_rx_bd(struct hns3_enet_ring *ring)
{
	struct hns3_desc_cb *desc_cb;
	struct sk_buff *skb = ring->skb;
	void *data, *data_hard_start;
	struct hns3_desc *desc;
	struct xdp_buff xdp;
	u32 bd_base_info;
	bool consumed;
	u32 frag_size;
	int length, ret;

	desc = &ring->desc[ring->next_to_clean];
	desc_cb = &ring->desc_cb[ring->next_to_clean];

	/* prefetch the descriptor */
	prefetch(desc);

	bd_base_info = le32_to_cpu(desc->rx.bd_base_info);
	/* Check valid BD */
	if (unlikely(!(bd_base_info & BIT(HNS3_RXD_VLD_B))))
		return -ENXIO;

	dma_rmb();

	length = le16_to_cpu(desc->rx.size);
	ring->va = desc_cb->buf + desc_cb->page_offset;
	data_hard_start = ring->va;
	data = ring->va + desc_cb->rx_headroom;
	frag_size = hns3_buf_size(ring);

	dma_sync_single_for_cpu(ring_to_dev(ring),
			desc_cb->dma + desc_cb->page_offset,
			frag_size,
			DMA_FROM_DEVICE);

	/* Prefetch first two cache line of the xdp frame data */
	net_prefetch(data_hard_start);
	net_prefetch(data);

	/* initlialize xdp buffer */
	xdp_init_buff(&xdp, frag_size, &ring->xdp_rxq);
	xdp_prepare_buff(&xdp, data_hard_start, desc_cb->rx_headroom, length, false);
	xdp.frame_sz = frag_size;

	/* run xdp program */
	consumed = hns3_xdp_run(ring, &xdp);
	if (consumed) {
		ring->skb = 0;
		return 0;
	}

	/* build skb for passing to stack */
	skb = hns3_build_skb(ring, &xdp);
	if (IS_ERR(skb))
		return -ENOMEM;

	if (!(bd_base_info & BIT(HNS3_RXD_FE_B)))
		netdev_warn(ring_to_netdev(ring), "something is wrong! not a last xdp frag\n");

	ret = hns3_handle_bdinfo(ring, skb);
	if (unlikely(ret)) {
		dev_kfree_skb_any(skb);
		return ret;
	}

	skb_record_rx_queue(skb, ring->tqp->tqp_index);

	return 0;
}

static void hns3_attach_bpf_prog(struct net_device *ndev, struct bpf_prog *prog)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);
	struct hns3_nic_priv *priv = netdev_priv(ndev);
	struct hns3_enet_ring *ring;
	struct bpf_prog *old_prog;
	struct hnae3_queue *q;
	int tqp;

	/* attach xdp prog to nic and remove old */
	old_prog = xchg(&priv->xdp_prog, prog);

	if (old_prog && !priv->xdp_prog) {
		bpf_prog_put(old_prog);
		return;
	}

	if  (!old_prog && priv->xdp_prog)
		return;

	/* drop the old one and update ring prog */
	bpf_prog_put(old_prog);

	/* {de}attach XDP prog with each rxq */
	for (tqp = 0; tqp < h->kinfo.num_tqps; tqp++)  {
		q = h->kinfo.tqp[tqp];
		ring = &priv->ring[ q->tqp_index + h->kinfo.num_tqps];
		WRITE_ONCE(ring->xdp_prog, priv->xdp_prog);
	}
}

/**
 * hns3_xdp_setup_prog - attach or detach or replace XDP eBPF program
 * @ndev: net device to which XDP program is to be attached/detached/replaced
 * @prog: XDP program
 */
static int
hns3_xdp_setup_prog(struct net_device *ndev, struct bpf_prog *prog)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);
	struct hns3_nic_priv * priv = netdev_priv(ndev);
	bool ifup;
	int ret = 0;

	/* check if we are allowed to attach the XDP program */
	if (hns3_xdp_check(ndev, prog))
		return -EOPNOTSUPP;

	ifup = !test_bit(HNS3_NIC_STATE_DOWN, &priv->state);

	ret = hns3_reset_notify(h, HNAE3_DOWN_CLIENT);
	if (ret) {
		netdev_err(ndev, "Client down fail, this should'nt have happened!\n");
		return ret;
	}

	/* We do not need full reset when exchanging programs */
	if (hns3_is_xdp_enabled(ndev) && prog) {
		hns3_attach_bpf_prog(ndev, prog);
		goto exit_restore;
	}

	ret = hns3_reset_notify(h, HNAE3_UNINIT_CLIENT);
	if (ret) {
		netdev_err(ndev, "Client uninit fail, this should'nt have happened!\n");
		goto exit_restore;
	}

	/* let us attach or detach the xdp program */
	hns3_attach_bpf_prog(ndev, prog);

	/* TODO: check this error handling later */
	ret = hns3_reset_notify(h, HNAE3_INIT_CLIENT);
	if (ret) {
		netdev_err(ndev, "Unexpected failure in restoring client\n");
		goto err_restore;
	}

	if (h->ae_algo->ops->set_gro_en && hns3_is_xdp_enabled(ndev)) {
		netdev_warn(ndev,"Disable GRO when XDP is enabled\n");
		ret = h->ae_algo->ops->set_gro_en(h, false);
		if (ret)
			return ret;
	}
exit_restore:
	/* bring up the interface only if earlier it was up */
	if (ifup) {
		ret =  hns3_reset_notify(h, HNAE3_UP_CLIENT);
		if (ret)
			netdev_err(ndev, "Unexpectedly, could not bring up the interface!\n");
	}

	return ret;

err_restore:
	netdev_warn(ndev, "Device maybe insane. Reload driver/Reset required!\n");

	return ret;
}

/**
 * hns3_xdp: {un}sets XDP program, AF_XDP pools etc.
 * @netdev: netdevice corresponding to the XDP setup command
 * @xdp: XDP command
 */
int hns3_xdp(struct net_device *netdev, struct netdev_bpf *xdp)
{
	struct hnae3_handle *h = hns3_get_handle(netdev);

	if (!hns3_is_phys_func(h->pdev)) {
		NL_SET_ERR_MSG_MOD(xdp->extack,
				               "For now, XDP can only be loaded on PF\n");
		return -EINVAL;
	}

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return hns3_xdp_setup_prog(netdev, xdp->prog);
	case XDP_SETUP_XSK_POOL:
		/* TODO: coming soon */
	default:
		return -EINVAL;
	}
}

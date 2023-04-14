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
	struct hnae3_knic_private_info *kinfo;
	struct hnae3_handle *h;
	u32 max_xdp_mtu;

	h = hns3_get_handle(netdev);
	kinfo = &h->kinfo;

	max_xdp_mtu = kinfo->rx_buf_len;
	max_xdp_mtu -= hns3_rx_headroom(netdev) ;
	max_xdp_mtu -= HNS3_ETH_HDR_PAD;
	max_xdp_mtu -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	return max_xdp_mtu;
}

bool hns3_xdp_check_max_mtu(struct net_device *netdev, u32 mtu)
{
	return mtu <= hns3_xdp_max_mtu(netdev) ;
}

static u32 hns3_xdp_rx_frame_size(struct hns3_enet_ring *ring)
{
	unsigned int frame_size;

	/*
	 * TODO: Do we need different handling for pages >= 8K?
	 * Need to properly done during perfromance
	 */
	frame_size = hns3_page_size(ring) / 2;

	return frame_size;
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

	if (!hns3_xdp_check_max_mtu(netdev, netdev->mtu)) {
		netdev_warn(netdev,
			      "For now, XDP is not supported with MTU exceeding %d\n",
			       hns3_xdp_max_mtu(netdev));
		return -EINVAL;
	}

	return 0;
}

static void
hns3_xdp_adjust_page_offset(struct hns3_desc_cb *cb)
{
	unsigned int frame_size = hns3_xdp_rx_frame_size(cb->ring);

	/*
	 * TODO: Need to add proper page reuse handling for page size >= 8k
	 */
	/* flip to unused part of the page */
	cb->page_offset ^= frame_size;
}

static bool hns3_xdp_can_reuse_page(struct hns3_desc_cb *cb)
{
	struct page *page = (struct page *)cb->priv;
	u16 pagecnt_bias = cb->pagecnt_bias;

	/* distant node and pfmemalloc pages should not be reused */
	if (!dev_page_is_reusable(page))
		return false;

	/* check if stack is using the other part of the page */
	/*
	 * TODO: Later check race reported by 'Bjorn Topel' for ICE driver - it's buggy!
	 * i.e. need a fix better than that this for XDP in hns3 driver
	 * Link: https://lore.kernel.org/netdev/20200825172736.27318-4-bjorn.topel@gmail.com/
	 * Since we are not testing 'xdp_do_redirect/xdp_tx' therefore we are
	 * okay without above fix for now.
	 *
	 * Eventually we want to get over this and use page-pool frag reuse as
	 * that totally eliminates above race condition (I think)
	 */
	/*
	 * TODO: Need to add proper page reuse handling for page size >= 8k
	 */
	if ((unlikely(page_count(page) - pagecnt_bias) > 1))
		return false;

	if (unlikely(pagecnt_bias == 1)) {
		page_ref_add(page, USHRT_MAX - 1);
		cb->pagecnt_bias = USHRT_MAX;
	}

	return true;
}

static struct sk_buff *
hns3_build_skb(struct hns3_enet_ring *ring, struct xdp_buff *xdp)
{
	struct hns3_desc_cb *desc_cb = &ring->desc_cb[ring->next_to_clean];
	struct net_device *netdev = ring_to_netdev(ring);
	u8 metasize = xdp->data - xdp->data_meta;
	u32 truesize = hns3_xdp_rx_frame_size(ring);
	struct sk_buff *skb;

	net_prefetch(xdp->data_meta);

	skb = ring->skb = build_skb(xdp->data_hard_start, truesize);
	if (unlikely(!skb)) {
		hns3_rl_err(netdev, "failed to build skb from xdp buffer\n");

		u64_stats_update_begin(&ring->syncp);
		ring->stats.sw_err_cnt++;
		u64_stats_update_end(&ring->syncp);

		return ERR_PTR(-ENOMEM);
	}

	ring->pending_buf = 1;

	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	skb_put(skb, xdp->data_end - xdp->data);

	/* TODO: once we support XDP Hints this would be useful */
	if (metasize)
		skb_metadata_set(skb, metasize);

	skb_record_rx_queue(skb, ring->tqp->tqp_index);

	u64_stats_update_begin(&ring->syncp);
	ring->stats.seg_pkt_cnt++;
	u64_stats_update_end(&ring->syncp);

	hns3_xdp_adjust_page_offset(desc_cb);
	hns3_rx_ring_move_fw(ring);

	return skb;
}

void hns3_xdp_complete(struct hns3_enet_ring *ring)
{
	if (unlikely(test_bit(HNS3_XDP_REDIRECT, ring->xdp_flags))) {
		xdp_do_flush_map();
		__clear_bit(HNS3_XDP_REDIRECT, ring->xdp_flags);
	}

	if (unlikely(test_bit(HNS3_XDP_TX, ring->xdp_flags))) {
		hns3_tx_doorbell(ring->xdp_tx_ring, 1, true);
		__clear_bit(HNS3_XDP_TX, ring->xdp_flags);
	}
}

/**
 * hns3_xdp_tx - transmits a XDP frame on a tx ring/queue
 * @tx_ring: XDP TX queue on which frame has to be x'mited
 * @xdpf: XDP frame to be transmitted
 * @dma_addr: DMA mapped adress
 */
static int
hns3_xdp_xmit_frame(struct hns3_enet_ring *xdp_ring, struct xdp_frame *xdpf,
		     dma_addr_t dma_addr)
{
	struct hns3_desc_cb *desc_cb;
	struct hns3_desc *desc;

	if (!unlikely(hns3_desc_unused(xdp_ring)))
		return -ENOSPC;

	desc_cb = &xdp_ring->desc_cb[xdp_ring->next_to_use];
	desc_cb->priv = xdpf;
	desc_cb->length = xdpf->len;
	desc_cb->dma = dma_addr;
	desc_cb->type = DESC_TYPE_XDP_XMIT;

	desc = &xdp_ring->desc[xdp_ring->next_to_use];
	desc->addr = cpu_to_le64(dma_addr);
	desc->rx.bd_base_info = 0;

	smp_wmb();

	WRITE_ONCE(xdp_ring->last_to_use, xdp_ring->next_to_use);
	ring_ptr_move_fw(xdp_ring, next_to_use);

	return 0;
}

/**
 * hns3_xdp_tx - transmits a XDP buffer on a xdp tx queue
 * @tx_ring: xdp tx queue on which buffer is to be x'mited
 * @ring : rx queue from which recvd buff is being bounced
 * @xdp: XDP buffer to be transmitted
 */
static int
hns3_xdp_tx(struct hns3_enet_ring *tx_ring, struct hns3_enet_ring *ring,
	      struct xdp_buff *xdp)
{
	struct hns3_desc_cb *desc_cb = ring->desc_cb;
	dma_addr_t dma_addr = desc_cb->dma;
	struct xdp_frame *xdpf;
	int ret = 0;

	xdpf = xdp_convert_buff_to_frame(xdp);
	if (unlikely(!xdpf))
		return -ENOMEM;

	dma_sync_single_for_device(ring_to_dev(ring), dma_addr, xdpf->len,
				   DMA_BIDIRECTIONAL);

	ret = hns3_xdp_xmit_frame(tx_ring, xdpf, dma_addr);

	return ret;
}

/**
 * hns3_xdp_xmit - submit @n XDP packets for transmission
 * @netdev: net device on which frames need to be x'mted
 * @n: number of XDP frames to be transmitted
 * @frames: XDP frames to be transmitted
 * @flags: transmit flags
 *
 * Returns number of frames successfully transmited, frames that got
 * dropped are freed/returned via xdp_return_frame() etc.
 * For error cases, a negative errno code is returned and no-frames
 * are xmit'ed and caller must free the frames.
 */
int hns3_xdp_xmit(struct net_device *netdev, int n, struct xdp_frame **frames, u32 flags)
{
	struct hnae3_handle *h = hns3_get_handle(netdev);
	struct hns3_nic_priv * priv = netdev_priv(netdev);
	struct hns3_enet_ring *xdp_ring;
	unsigned int queue_index;
	dma_addr_t dma_addr;
	int drops = 0, i, ret;

	if (test_bit(HNS3_NIC_STATE_DOWN, &priv->state))
		return -ENETDOWN;

	if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
		return -EINVAL;

	/* TODO: Bad! This does not preserves QoS as of now. we need to do better
	 * than this later. will come back later.
	 */
	queue_index = smp_processor_id() % h->kinfo.num_tqps;
	xdp_ring = &priv->xdp_rings[queue_index];

	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = frames[i];

		dma_addr = dma_map_single(ring_to_dev(xdp_ring),  xdpf->data,
					xdpf->len, DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(ring_to_dev(xdp_ring), dma_addr))) {
			xdp_return_frame_rx_napi(xdpf);
			drops++;
			continue;
		}

		ret = hns3_xdp_xmit_frame(xdp_ring, xdpf, dma_addr);
		if (ret) {
			dma_unmap_single(ring_to_dev(xdp_ring), dma_addr,
					 xdpf->len, DMA_TO_DEVICE);
			xdp_return_frame_rx_napi(xdpf);
			drops++;
		}
	}

	if (flags & XDP_XMIT_FLUSH)
		hns3_tx_doorbell(xdp_ring->xdp_tx_ring, n - drops, true);

	return n - drops;
}

static int
hns3_xdp_run(struct hns3_enet_ring *rx_ring, struct xdp_buff *xdp)
{
	struct hns3_enet_ring *xdp_ring = rx_ring->xdp_tx_ring;
	struct bpf_prog *xdp_prog;
	int ret = HNS3_XDP_PASS;
	u32 act;

	/* RFC Question: should we? Any security risk in this action? */
	/* Pass the buffer to stack if we cannot get hold of xdp prog */
	rcu_read_lock();
	xdp_prog = READ_ONCE(rx_ring->xdp_prog);
	if (!xdp_prog)
		goto exit_unlock;

	act = bpf_prog_run_xdp(xdp_prog, xdp);
	switch (act) {
	case XDP_PASS:
		/* return and continue with normal SKB path */
		break;
	case XDP_TX:
		/* transmit the buffer on the XDP TX queue */
		ret = hns3_xdp_tx(xdp_ring, rx_ring, xdp);
		if (ret) {
			u64_stats_update_begin(&xdp_ring->syncp);
			xdp_ring->stats.xdp_rx_bounce_err++;
			u64_stats_update_end(&xdp_ring->syncp);
			break;
		}

		/*
		 * TODO: PERF: need to check the performance impact of these
		 * statistics later and then decide whether to keep them
		 */
		u64_stats_update_begin(&xdp_ring->syncp);
		xdp_ring->stats.xdp_rx_bounce++;
		u64_stats_update_end(&xdp_ring->syncp);

		__set_bit(HNS3_XDP_TX, rx_ring->xdp_flags);
		ret = HNS3_XDP_TX;
		break;
	case XDP_REDIRECT:
		/*
		 * TODO: do we need to unmap the buffer now? as it might go
		 * to different device so DMA mappings need to be destroyed
		 * and recreated for that target device during xmit there.
		 * Intel's ICE driver is buggy here!!
		 *
		 * Miles to go before I sleep..miles to go before I sleep!
		 */
		/* redirect the buffer to other device TX queue */
		ret = xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog);
		if (ret) {
			u64_stats_update_begin(&xdp_ring->syncp);
			xdp_ring->stats.xdp_rx_redir_err++;
			u64_stats_update_end(&xdp_ring->syncp);
			break;
		}

		/*
		 * TODO: PERF: need to check the performance impact of these
		 * statistics later and then decide whether to keep them
		 */
		u64_stats_update_begin(&xdp_ring->syncp);
		xdp_ring->stats.xdp_rx_redir++;
		u64_stats_update_end(&xdp_ring->syncp);

		__set_bit(HNS3_XDP_REDIRECT, rx_ring->xdp_flags);
		ret = HNS3_XDP_REDIRECT;
		break;
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

		ret = HNS3_XDP_DROP;
		break;
	}

exit_unlock:
	rcu_read_unlock();
	return ret;
}

/**
 * hns3_reuse_or_relinquish_page - check if the page can be reused by the driver
 * or it should unmap the page and relinquish. Later means updating the page count
 * with the unbiased page count(i.e. page count - page count bias) and let the
 * stack or the xdp redirect or the xdp tx do the work of free'ing the page
 * eventually which is akin to the unbiased approach (kind of fallback path).
 * (With this trick, we have deferred the atomic update of the page count as
 * long as possible and acheived the page reuse)
 *
 * @ring: ring to which the page belongs.
 * @cb: Buffer descriptor common block of the ring to which the page belongs.
 *
 */
static void
hns3_xdp_reuse_or_relinquish_page(struct hns3_enet_ring *ring,
				  struct hns3_desc_cb *cb)
{
	if (hns3_xdp_can_reuse_page(cb)) {
		/* mark it for reuse in the RX buffer allocation later */
		cb->reuse_flag = 1;
	} else {
		/*
		 * we are not reusing the page so unmap it. This should be done
		 * irrespective of the fact whether we are eventually free'ing
		 * the page or not.
		 */
		dma_unmap_page_attrs(ring->dev, cb->dma,
				     hns3_xdp_rx_frame_size(ring),
				     DMA_FROM_DEVICE,
				     DMA_ATTR_SKIP_CPU_SYNC);
		cb->dma = 0;

		/*
		 * update the page reference with the unbiased count. This
		 * might not result in free'ing of the page being relinquished.
		 * Driver is just falling back to the old unbiased page release
		 * mechanism.
		 */
		__page_frag_cache_drain(cb->priv, cb->pagecnt_bias);
	}
	hns3_dbg_pgr(ring);
}

int hns3_xdp_handle_rx_bd(struct hns3_enet_ring *ring)
{
	u32 frame_size, frag_size, bd_base_info;
	struct sk_buff *skb;
	struct hns3_desc_cb *desc_cb;
	void *data, *data_hard_start;
	struct hns3_desc *desc;
	struct xdp_buff xdp;
	int length, ret;

	ring->skb = NULL; /* TODO: we need to remove this later */

	desc = &ring->desc[ring->next_to_clean];
	desc_cb = &ring->desc_cb[ring->next_to_clean];

	/* prefetch the descriptor */
	prefetch(desc);

	bd_base_info = le32_to_cpu(desc->rx.bd_base_info);
	/* Check valid BD */
	if (unlikely(!(bd_base_info & BIT(HNS3_RXD_VLD_B))))
		return -ENXIO;
	hns3_dbg(ring->netdev, "\n++++ rx bd ++++\n");
	dma_rmb();

	length = le16_to_cpu(desc->rx.size);
	ring->va = desc_cb->buf + desc_cb->page_offset;
	data_hard_start = ring->va;
	data = ring->va + desc_cb->rx_headroom;
	frag_size = hns3_buf_size(ring); /* should we be more precise here? */
	frame_size = hns3_xdp_rx_frame_size(ring);

	dma_sync_single_for_cpu(ring_to_dev(ring),
			desc_cb->dma + desc_cb->page_offset,
			frag_size,
			DMA_FROM_DEVICE);

	desc_cb->pagecnt_bias--;
	hns3_dbg_pgr(ring);

	/* Prefetch first two cache line of the xdp frame data */
	net_prefetch(data_hard_start);
	net_prefetch(data);

	xdp_init_buff(&xdp, frame_size, &ring->xdp_rxq);
	xdp_prepare_buff(&xdp, data_hard_start, desc_cb->rx_headroom,
			 length, true);

	/* run xdp program */
	ret = hns3_xdp_run(ring, &xdp);
	/* handle XDP tx, redirect and drop verdicts */
	if (ret) {
		if (ret & (HNS3_XDP_TX | HNS3_XDP_REDIRECT)) {
			hns3_xdp_adjust_page_offset(desc_cb);
		} else {
			if (ret & HNS3_XDP_DROP)
				ret = 0;
			/* drop and error case of xdp run */
			desc_cb->pagecnt_bias++;
		}

		hns3_dbg_pgr(ring);
		hns3_xdp_reuse_or_relinquish_page(ring, desc_cb);
		hns3_rx_ring_move_fw(ring);

		return ret;
	}

	/* build skb and pass it to stack */
	/*
	 * TODO: We are not handling multi-buffer in XDP. We will enable it later
	 * Link: https://lore.kernel.org/bpf/cover.1642758637.git.lorenzo@kernel.org/
	 *
	 * Hence, 'HW GRO=disabled' and 'MTU <= 4k' is a requirement for now.
	 */
	skb = hns3_build_skb(ring, &xdp);
	if (IS_ERR(skb)) {
		/*
		 * page (offset, reuse} are still the old one. Do we have to
		 * release the page/buffer in this case (I think no?)
		 */
		desc_cb->pagecnt_bias++;
		hns3_dbg_pgr(ring);
		return -ENOMEM;
	}

	hns3_xdp_reuse_or_relinquish_page(ring, desc_cb);

	/*
	 * we dont support multi buffer xdp. This is pathological check.
	 */
	if (!(bd_base_info & BIT(HNS3_RXD_FE_B)))
		netdev_warn(ring_to_netdev(ring), "something is wrong! not a last xdp frag\n");

	ret = hns3_handle_bdinfo(ring, skb);
	if (unlikely(ret)) {
		dev_kfree_skb_any(skb);
		return ret;
	}
	hns3_dbg_pgr(ring);
	hns3_dbg(ring->netdev, "++++ End ++++\n");
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

	if (ifup) {
		ret = hns3_reset_notify(h, HNAE3_DOWN_CLIENT);
		if (ret) {
			netdev_err(ndev, "Client down fail, this should'nt have happened!\n");
			return ret;
		}
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

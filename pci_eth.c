#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/crc32.h>
#include <linux/spinlock.h>
#include <linux/bitops.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/uaccess.h>
#include <linux/phy.h>

#include <asm/processor.h>

#define PCI_VENDOR_ID_ETH 0xFF
#define PCI_DEVICE_ID_ETH 0xFF


#define DRV_NAME	"pci_eth"
#define DRV_VERSION	"1"
#define DRV_RELDATE	"01Nov2016"

/* Time in jiffies before concluding the transmitter is hung. */
#define TX_TIMEOUT	(6000 * HZ / 1000)

/* RDC MAC I/O Size */
#define R6040_IO_SIZE	256

/* MAX RDC MAC */
#define MAX_MAC		2

/* MAC registers */
#define MCR0		0x00	/* Control register 0 */
#define  MCR0_RCVEN	0x0002	/* Receive enable */
#define  MCR0_PROMISC	0x0020	/* Promiscuous mode */
#define  MCR0_HASH_EN	0x0100	/* Enable multicast hash table function */
#define  MCR0_XMTEN	0x1000	/* Transmission enable */
#define  MCR0_FD	0x8000	/* Full/Half duplex */
#define MCR1		0x04	/* Control register 1 */
#define  MAC_RST	0x0001	/* Reset the MAC */
#define MBCR		0x08	/* Bus control */
#define MT_ICR		0x0C	/* TX interrupt control */
#define MR_ICR		0x10	/* RX interrupt control */
#define MTPR		0x14	/* TX poll command register */
#define  TM2TX		0x0001	/* Trigger MAC to transmit */
#define MR_BSR		0x18	/* RX buffer size */
#define MR_DCR		0x1A	/* RX descriptor control */
#define MLSR		0x1C	/* Last status */
#define  TX_FIFO_UNDR	0x0200	/* TX FIFO under-run */
#define	 TX_EXCEEDC	0x2000	/* Transmit exceed collision */
#define  TX_LATEC	0x4000	/* Transmit late collision */
#define MMDIO		0x20	/* MDIO control register */
#define  MDIO_WRITE	0x4000	/* MDIO write */
#define  MDIO_READ	0x2000	/* MDIO read */
#define MMRD		0x24	/* MDIO read data register */
#define MMWD		0x28	/* MDIO write data register */
#define MTD_SA0		0x2C	/* TX descriptor start address 0 */
#define MTD_SA1		0x30	/* TX descriptor start address 1 */
#define MRD_SA0		0x34	/* RX descriptor start address 0 */
#define MRD_SA1		0x38	/* RX descriptor start address 1 */
#define MISR		0x3C	/* Status register */
#define MIER		0x40	/* INT enable register */
#define  MSK_INT	0x0000	/* Mask off interrupts */
#define  RX_FINISH	0x0001  /* RX finished */
#define  RX_NO_DESC	0x0002  /* No RX descriptor available */
#define  RX_FIFO_FULL	0x0004  /* RX FIFO full */
#define  RX_EARLY	0x0008  /* RX early */
#define  TX_FINISH	0x0010  /* TX finished */
#define  TX_EARLY	0x0080  /* TX early */
#define  EVENT_OVRFL	0x0100  /* Event counter overflow */
#define  LINK_CHANGED	0x0200  /* PHY link changed */
#define ME_CISR		0x44	/* Event counter INT status */
#define ME_CIER		0x48	/* Event counter INT enable  */
#define MR_CNT		0x50	/* Successfully received packet counter */
#define ME_CNT0		0x52	/* Event counter 0 */
#define ME_CNT1		0x54	/* Event counter 1 */
#define ME_CNT2		0x56	/* Event counter 2 */
#define ME_CNT3		0x58	/* Event counter 3 */
#define MT_CNT		0x5A	/* Successfully transmit packet counter */
#define ME_CNT4		0x5C	/* Event counter 4 */
#define MP_CNT		0x5E	/* Pause frame counter register */
#define MAR0		0x60	/* Hash table 0 */
#define MAR1		0x62	/* Hash table 1 */
#define MAR2		0x64	/* Hash table 2 */
#define MAR3		0x66	/* Hash table 3 */
#define MID_0L		0x68	/* Multicast address MID0 Low */
#define MID_0M		0x6A	/* Multicast address MID0 Medium */
#define MID_0H		0x6C	/* Multicast address MID0 High */
#define MID_1L		0x70	/* MID1 Low */
#define MID_1M		0x72	/* MID1 Medium */
#define MID_1H		0x74	/* MID1 High */
#define MID_2L		0x78	/* MID2 Low */
#define MID_2M		0x7A	/* MID2 Medium */
#define MID_2H		0x7C	/* MID2 High */
#define MID_3L		0x80	/* MID3 Low */
#define MID_3M		0x82	/* MID3 Medium */
#define MID_3H		0x84	/* MID3 High */
#define PHY_CC		0x88	/* PHY status change configuration register */
#define  SCEN		0x8000	/* PHY status change enable */
#define  PHYAD_SHIFT	8	/* PHY address shift */
#define  TMRDIV_SHIFT	0	/* Timer divider shift */
#define PHY_ST		0x8A	/* PHY status register */
#define MAC_SM		0xAC	/* MAC status machine */
#define  MAC_SM_RST	0x0002	/* MAC status machine reset */
#define MAC_ID		0xBE	/* Identifier register */

#define TX_DCNT		0x80	/* TX descriptor count */
#define RX_DCNT		0x80	/* RX descriptor count */
#define MAX_BUF_SIZE	0x600
#define RX_DESC_SIZE	(RX_DCNT * sizeof(struct pci_eth_descriptor))
#define TX_DESC_SIZE	(TX_DCNT * sizeof(struct pci_eth_descriptor))
#define MBCR_DEFAULT	0x012A	/* MAC Bus Control Register */
#define MCAST_MAX	3	/* Max number multicast addresses to filter */

#define MAC_DEF_TIMEOUT	2048	/* Default MAC read/write operation timeout */

/* Descriptor status */
#define DSC_OWNER_MAC	0x8000	/* MAC is the owner of this descriptor */
#define DSC_RX_OK	0x4000	/* RX was successful */
#define DSC_RX_ERR	0x0800	/* RX PHY error */
#define DSC_RX_ERR_DRI	0x0400	/* RX dribble packet */
#define DSC_RX_ERR_BUF	0x0200	/* RX length exceeds buffer size */
#define DSC_RX_ERR_LONG	0x0100	/* RX length > maximum packet length */
#define DSC_RX_ERR_RUNT	0x0080	/* RX packet length < 64 byte */
#define DSC_RX_ERR_CRC	0x0040	/* RX CRC error */
#define DSC_RX_BCAST	0x0020	/* RX broadcast (no error) */
#define DSC_RX_MCAST	0x0010	/* RX multicast (no error) */
#define DSC_RX_MCH_HIT	0x0008	/* RX multicast hit in hash table (no error) */
#define DSC_RX_MIDH_HIT	0x0004	/* RX MID table hit (no error) */
#define DSC_RX_IDX_MID_MASK 3	/* RX mask for the index of matched MIDx */

MODULE_AUTHOR("Sten Wang <sten.wang@rdc.com.tw>,"
	"Daniel Gimpelevich <daniel@gimpelevich.san-francisco.ca.us>,"
	"Florian Fainelli <florian@openwrt.org>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RDC R6040 NAPI PCI FastEthernet driver");
MODULE_VERSION(DRV_VERSION " " DRV_RELDATE);

/* RX and TX interrupts that we handle */
#define RX_INTS			(RX_FIFO_FULL | RX_NO_DESC | RX_FINISH)
#define TX_INTS			(TX_FINISH)
#define INT_MASK		(RX_INTS | TX_INTS)

struct pci_eth_descriptor {
	u16	status, len;		/* 0-3 */
	__le32	buf;			/* 4-7 */
	__le32	ndesc;			/* 8-B */
	u32	rev1;			/* C-F */
	char	*vbufp;			/* 10-13 */
	struct pci_eth_descriptor *vndescp;	/* 14-17 */
	struct sk_buff *skb_ptr;	/* 18-1B */
	u32	rev2;			/* 1C-1F */
} __aligned(32);

struct pci_eth_private {
	spinlock_t lock;		/* driver lock */
	struct pci_dev *pdev;
	struct pci_eth_descriptor *rx_insert_ptr;
	struct pci_eth_descriptor *rx_remove_ptr;
	struct pci_eth_descriptor *tx_insert_ptr;
	struct pci_eth_descriptor *tx_remove_ptr;
	struct pci_eth_descriptor *rx_ring;
	struct pci_eth_descriptor *tx_ring;
	dma_addr_t rx_ring_dma;
	dma_addr_t tx_ring_dma;
	u16	tx_free_desc;
	u16	mcr0;
	struct net_device *dev;
	struct mii_bus *mii_bus;
	struct napi_struct napi;
	void __iomem *base;
	struct phy_device *phydev;
	int old_link;
	int old_duplex;
};

static char version[] = DRV_NAME
	": PCI ETH NAPI net driver,"
	"version "DRV_VERSION " (" DRV_RELDATE ")";

/* Read a word data from PHY Chip */
static int pci_eth_phy_read(void __iomem *ioaddr, int phy_addr, int reg)
{
	int limit = MAC_DEF_TIMEOUT;
	u16 cmd;

	iowrite16(MDIO_READ + reg + (phy_addr << 8), ioaddr + MMDIO);
	/* Wait for the read bit to be cleared */
	while (limit--) {
		cmd = ioread16(ioaddr + MMDIO);
		if (!(cmd & MDIO_READ))
			break;
		udelay(1);
	}

	if (limit < 0)
		return -ETIMEDOUT;

	return ioread16(ioaddr + MMRD);
}

/* Write a word data from PHY Chip */
static int pci_eth_phy_write(void __iomem *ioaddr,
					int phy_addr, int reg, u16 val)
{
	int limit = MAC_DEF_TIMEOUT;
	u16 cmd;

	iowrite16(val, ioaddr + MMWD);
	/* Write the command to the MDIO bus */
	iowrite16(MDIO_WRITE + reg + (phy_addr << 8), ioaddr + MMDIO);
	/* Wait for the write bit to be cleared */
	while (limit--) {
		cmd = ioread16(ioaddr + MMDIO);
		if (!(cmd & MDIO_WRITE))
			break;
		udelay(1);
	}

	return (limit < 0) ? -ETIMEDOUT : 0;
}

static int pci_eth_mdiobus_read(struct mii_bus *bus, int phy_addr, int reg)
{
	struct net_device *dev = bus->priv;
	struct pci_eth_private *priv = netdev_priv(dev);
	void __iomem *ioaddr = priv->base;

	return pci_eth_phy_read(ioaddr, phy_addr, reg);
}

static int pci_eth_mdiobus_write(struct mii_bus *bus, int phy_addr,
						int reg, u16 value)
{
	struct net_device *dev = bus->priv;
	struct pci_eth_private *priv = netdev_priv(dev);
	void __iomem *ioaddr = priv->base;

	return pci_eth_phy_write(ioaddr, phy_addr, reg, value);
}

static void pci_eth_free_txbufs(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < TX_DCNT; i++) {
		if (priv->tx_insert_ptr->skb_ptr) {
			pci_unmap_single(priv->pdev,
				le32_to_cpu(priv->tx_insert_ptr->buf),
				MAX_BUF_SIZE, PCI_DMA_TODEVICE);
			dev_kfree_skb(priv->tx_insert_ptr->skb_ptr);
			priv->tx_insert_ptr->skb_ptr = NULL;
		}
		priv->tx_insert_ptr = priv->tx_insert_ptr->vndescp;
	}
}

static void pci_eth_free_rxbufs(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < RX_DCNT; i++) {
		if (priv->rx_insert_ptr->skb_ptr) {
			pci_unmap_single(priv->pdev,
				le32_to_cpu(priv->rx_insert_ptr->buf),
				MAX_BUF_SIZE, PCI_DMA_FROMDEVICE);
			dev_kfree_skb(priv->rx_insert_ptr->skb_ptr);
			priv->rx_insert_ptr->skb_ptr = NULL;
		}
		priv->rx_insert_ptr = priv->rx_insert_ptr->vndescp;
	}
}

static void pci_eth_init_ring_desc(struct pci_eth_descriptor *desc_ring,
				 dma_addr_t desc_dma, int size)
{
	struct pci_eth_descriptor *desc = desc_ring;
	dma_addr_t mapping = desc_dma;

	while (size-- > 0) {
		mapping += sizeof(*desc);
		desc->ndesc = cpu_to_le32(mapping);
		desc->vndescp = desc + 1;
		desc++;
	}
	desc--;
	desc->ndesc = cpu_to_le32(desc_dma);
	desc->vndescp = desc_ring;
}

static void pci_eth_init_txbufs(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);

	priv->tx_free_desc = TX_DCNT;

	priv->tx_remove_ptr = priv->tx_insert_ptr = priv->tx_ring;
	pci_eth_init_ring_desc(priv->tx_ring, priv->tx_ring_dma, TX_DCNT);
}

static int pci_eth_alloc_rxbufs(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	struct pci_eth_descriptor *desc;
	struct sk_buff *skb;
	int rc;

	priv->rx_remove_ptr = priv->rx_insert_ptr = priv->rx_ring;
	pci_eth_init_ring_desc(priv->rx_ring, priv->rx_ring_dma, RX_DCNT);

	/* Allocate skbs for the rx descriptors */
	desc = priv->rx_ring;
	do {
		skb = netdev_alloc_skb(dev, MAX_BUF_SIZE);
		if (!skb) {
			rc = -ENOMEM;
			goto err_exit;
		}
		desc->skb_ptr = skb;
		desc->buf = cpu_to_le32(pci_map_single(priv->pdev,
					desc->skb_ptr->data,
					MAX_BUF_SIZE, PCI_DMA_FROMDEVICE));
		desc->status = DSC_OWNER_MAC;
		desc = desc->vndescp;
	} while (desc != priv->rx_ring);

	return 0;

err_exit:
	/* Deallocate all previously allocated skbs */
	pci_eth_free_rxbufs(dev);
	return rc;
}

static void pci_eth_tx_timeout(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	void __iomem *ioaddr = dev->base_addr;

	dev->stats.tx_errors++;

	/* TODO: Reset MAC and re-init all registers */
}

static struct net_device_stats *pci_eth_get_stats(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	void __iomem *ioaddr = priv->base;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	dev->stats.rx_crc_errors += ioread8(ioaddr + ME_CNT1);
	dev->stats.multicast += ioread8(ioaddr + ME_CNT0);
	spin_unlock_irqrestore(&priv->lock, flags);

	return &dev->stats;
}

/* Stop RDC MAC and Free the allocated resource */
static void pci_eth_down(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	void __iomem *ioaddr = dev->base_addr;

	/* TODO: Stop MAC */

	/* TODO: Reset MAC */

	/* TODO: Restore MAC Address to MIDx */

	phy_stop(priv->phydev);
}

static int pci_eth_close(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	struct pci_dev *pdev = priv->pdev;

	spin_lock_irq(&priv->lock);
	napi_disable(&priv->napi);
	netif_stop_queue(dev);
	pci_eth_down(dev);

	/* Free IRQ */
	free_irq(dev->irq, dev);

	/* Free RX buffer */
	pci_eth_free_rxbufs(dev);

	/* Free TX buffer */
	pci_eth_free_txbufs(dev);

	spin_unlock_irq(&priv->lock);

	/* Free Descriptor memory */
	if (priv->rx_ring) {
		pci_free_consistent(pdev,
				RX_DESC_SIZE, priv->rx_ring, priv->rx_ring_dma);
		priv->rx_ring = NULL;
	}

	if (priv->tx_ring) {
		pci_free_consistent(pdev,
				TX_DESC_SIZE, priv->tx_ring, priv->tx_ring_dma);
		priv->tx_ring = NULL;
	}

	return 0;
}

static int pci_eth_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct pci_eth_private *priv = netdev_priv(dev);

	if (!priv->phydev)
		return -EINVAL;

	return phy_mii_ioctl(priv->phydev, rq, cmd);
}

static int pci_eth_rx(struct net_device *dev, int budget)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	struct pci_eth_descriptor *descptr = priv->rx_remove_ptr;
	struct sk_buff *skb_ptr, *new_skb;
	int count = 0;
	u16 err;

	/* Limit not reached and the descriptor belongs to the CPU */
	while (count < budget && !(descptr->status & DSC_OWNER_MAC)) {
		/* Read the descriptor status */
		err = descptr->status;
		/* Global error status set */
		if (err & DSC_RX_ERR) {
			/* RX dribble */
			if (err & DSC_RX_ERR_DRI)
				dev->stats.rx_frame_errors++;
			/* Buffer length exceeded */
			if (err & DSC_RX_ERR_BUF)
				dev->stats.rx_length_errors++;
			/* Packet too long */
			if (err & DSC_RX_ERR_LONG)
				dev->stats.rx_length_errors++;
			/* Packet < 64 bytes */
			if (err & DSC_RX_ERR_RUNT)
				dev->stats.rx_length_errors++;
			/* CRC error */
			if (err & DSC_RX_ERR_CRC) {
				spin_lock(&priv->lock);
				dev->stats.rx_crc_errors++;
				spin_unlock(&priv->lock);
			}
			goto next_descr;
		}

		/* Packet successfully received */
		new_skb = netdev_alloc_skb(dev, MAX_BUF_SIZE);
		if (!new_skb) {
			dev->stats.rx_dropped++;
			goto next_descr;
		}
		skb_ptr = descptr->skb_ptr;
		skb_ptr->dev = priv->dev;

		/* Do not count the CRC */
		skb_put(skb_ptr, descptr->len - 4);
		pci_unmap_single(priv->pdev, le32_to_cpu(descptr->buf),
					MAX_BUF_SIZE, PCI_DMA_FROMDEVICE);
		skb_ptr->protocol = eth_type_trans(skb_ptr, priv->dev);

		/* Send to upper layer */
		netif_receive_skb(skb_ptr);
		dev->stats.rx_packets++;
		dev->stats.rx_bytes += descptr->len - 4;

		/* put new skb into descriptor */
		descptr->skb_ptr = new_skb;
		descptr->buf = cpu_to_le32(pci_map_single(priv->pdev,
						descptr->skb_ptr->data,
					MAX_BUF_SIZE, PCI_DMA_FROMDEVICE));

next_descr:
		/* put the descriptor back to the MAC */
		descptr->status = DSC_OWNER_MAC;
		descptr = descptr->vndescp;
		count++;
	}
	priv->rx_remove_ptr = descptr;

	return count;
}

static void pci_eth_tx(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	struct pci_eth_descriptor *descptr;
	void __iomem *ioaddr = dev->base_addr;
	struct sk_buff *skb_ptr;
	u16 err;

	spin_lock(&priv->lock);
	descptr = priv->tx_remove_ptr;
	while (priv->tx_free_desc < TX_DCNT) {
		/* Check for errors */
		err = ioread16(ioaddr + MLSR);

		if (err & TX_FIFO_UNDR)
			dev->stats.tx_fifo_errors++;
		if (err & (TX_EXCEEDC | TX_LATEC))
			dev->stats.tx_carrier_errors++;

		if (descptr->status & DSC_OWNER_MAC)
			break; /* Not complete */
		skb_ptr = descptr->skb_ptr;
		pci_unmap_single(priv->pdev, le32_to_cpu(descptr->buf),
			skb_ptr->len, PCI_DMA_TODEVICE);
		/* Free buffer */
		dev_kfree_skb_irq(skb_ptr);
		descptr->skb_ptr = NULL;
		/* To next descriptor */
		descptr = descptr->vndescp;
		priv->tx_free_desc++;
	}
	priv->tx_remove_ptr = descptr;

	if (priv->tx_free_desc)
		netif_wake_queue(dev);
	spin_unlock(&priv->lock);
}

static int pci_eth_poll(struct napi_struct *napi, int budget)
{
	struct pci_eth_private *priv =
		container_of(napi, struct pci_eth_private, napi);
	struct net_device *dev = priv->dev;
	void __iomem *ioaddr = priv->base;
	int work_done;

	work_done = pci_eth_rx(dev, budget);

	if (work_done < budget) {
		napi_complete(napi);
		/* Enable RX interrupt */
		iowrite16(ioread16(ioaddr + MIER) | RX_INTS, ioaddr + MIER);
	}
	return work_done;
}

/* The RDC interrupt handler. */
static irqreturn_t pci_eth_interrupt(int irq, void *dev_id)
{
	struct net_device *dev = dev_id;
	struct pci_eth_private *priv = netdev_priv(dev);
	void __iomem *ioaddr = priv->base;
	u16 misr, status;

	/* TODO: Is it our interrupt? */
	/* TODO: Read status register and clear */
	status = ioread16(ioaddr + MISR);

	/* RX interrupt request */
	if (status & RX_INTS) {
		if (status & RX_NO_DESC) {
			/* RX descriptor unavailable */
			dev->stats.rx_dropped++;
			dev->stats.rx_missed_errors++;
		}
		if (status & RX_FIFO_FULL)
			dev->stats.rx_fifo_errors++;

		if (likely(napi_schedule_prep(&priv->napi))) {
			/* TODO: Mask off (disable) RX interrupt */
			__napi_schedule(&priv->napi);
		}
	}

	/* TX interrupt request */
	if (status & TX_INTS)
		pci_eth_tx(dev);

	return IRQ_HANDLED;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void pci_eth_poll_controller(struct net_device *dev)
{
	disable_irq(dev->irq);
	pci_eth_interrupt(dev->irq, dev);
	enable_irq(dev->irq);
}
#endif

/* Init RDC MAC */
static int pci_eth_up(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	void __iomem *ioaddr = dev->base_addr;
	int ret;

	/* TODO: Initialise and alloc RX/TX buffers */

	/* TODO: Initialize all MAC registers */

	phy_start(priv->phydev);

	return 0;
}


/* Read/set MAC address routines */
static void pci_eth_mac_address(struct net_device *dev)
{
	void __iomem *ioaddr = dev->base_addr;

	/* TODO: Reset MAC */

	/* TODO: Restore MAC Address */
}

static int pci_eth_open(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	int ret;

	/* Request IRQ and Register interrupt handler */
	ret = request_irq(dev->irq, pci_eth_interrupt,
		IRQF_SHARED, dev->name, dev);
	if (ret)
		goto out;

	/* Set MAC address */
	pci_eth_mac_address(dev);

	/* Allocate Descriptor memory */
	priv->rx_ring =
		pci_alloc_consistent(priv->pdev, RX_DESC_SIZE, &priv->rx_ring_dma);
	if (!priv->rx_ring) {
		ret = -ENOMEM;
		goto err_free_irq;
	}

	priv->tx_ring =
		pci_alloc_consistent(priv->pdev, TX_DESC_SIZE, &priv->tx_ring_dma);
	if (!priv->tx_ring) {
		ret = -ENOMEM;
		goto err_free_rx_ring;
	}

	ret = pci_eth_up(dev);
	if (ret)
		goto err_free_tx_ring;

	netif_start_queue(dev);

	return 0;

err_free_tx_ring:
	pci_free_consistent(priv->pdev, TX_DESC_SIZE, priv->tx_ring,
			priv->tx_ring_dma);
err_free_rx_ring:
	pci_free_consistent(priv->pdev, RX_DESC_SIZE, priv->rx_ring,
			priv->rx_ring_dma);
err_free_irq:
	free_irq(dev->irq, dev);
out:
	return ret;
}

static netdev_tx_t pci_eth_start_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	struct pci_eth_descriptor *descptr;
	void __iomem *ioaddr = dev->base_addr;
	unsigned long flags;

	/* Critical Section */
	spin_lock_irqsave(&priv->lock, flags);

	/* TX resource check */
	if (!priv->tx_free_desc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		netif_stop_queue(dev);
		netdev_err(dev, ": no tx descriptor\n");
		return NETDEV_TX_BUSY;
	}

	/* Statistic Counter */
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;

	/* Decrement free descriptors counter */
	priv->tx_free_desc--;

	/* Set TX descriptor & Transmit it */
	descptr = priv->tx_insert_ptr;
	if (skb->len < ETH_ZLEN)
		descptr->len = ETH_ZLEN;
	else
		descptr->len = skb->len;

	descptr->skb_ptr = skb;
	descptr->buf = cpu_to_le32(pci_map_single(priv->pdev,
		skb->data, skb->len, PCI_DMA_TODEVICE));
	descptr->status = DSC_OWNER_MAC;

	skb_tx_timestamp(skb);

	/* TODO: Trigger the MAC to check the TX descriptor - start DMA
	 * transaction.
	 */

	/* After DMA transaction perform the following check */
	/* If no tx resource, stop */
	if (!priv->tx_free_desc)
		netif_stop_queue(dev);

	spin_unlock_irqrestore(&priv->lock, flags);

	return NETDEV_TX_OK;
}


static const struct net_device_ops pci_eth_netdev_ops = {
	.ndo_open		= pci_eth_open,
	.ndo_stop		= pci_eth_close,
	.ndo_start_xmit		= pci_eth_start_xmit,
	.ndo_do_ioctl		= pci_eth_ioctl,
	.ndo_get_stats		= pci_eth_get_stats,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_tx_timeout		= pci_eth_tx_timeout,
};

static void pci_eth_adjust_link(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	struct phy_device *phydev = priv->phydev;
	int status_changed = 0;
	void __iomem *ioaddr = priv->base;

	BUG_ON(!phydev);

	if (priv->old_link != phydev->link) {
		status_changed = 1;
		priv->old_link = phydev->link;
	}

	/* reflect duplex change */
	if (phydev->link && (priv->old_duplex != phydev->duplex)) {
		priv->mcr0 |= (phydev->duplex == DUPLEX_FULL ? MCR0_FD : 0);
		iowrite16(priv->mcr0, ioaddr);

		status_changed = 1;
		priv->old_duplex = phydev->duplex;
	}

	if (status_changed) {
		pr_info("%s: link %s", dev->name, phydev->link ?
			"UP" : "DOWN");
		if (phydev->link)
			pr_cont(" - %d/%s", phydev->speed,
			DUPLEX_FULL == phydev->duplex ? "full" : "half");
		pr_cont("\n");
	}
}

static int pci_eth_mii_probe(struct net_device *dev)
{
	struct pci_eth_private *priv = netdev_priv(dev);
	struct phy_device *phydev = NULL;

	phydev = phy_find_first(priv->mii_bus);
	if (!phydev) {
		dev_err(&priv->pdev->dev, "no PHY found\n");
		return -ENODEV;
	}

	phydev = phy_connect(dev, phydev_name(phydev), &pci_eth_adjust_link,
			     PHY_INTERFACE_MODE_MII);

	if (IS_ERR(phydev)) {
		dev_err(&priv->pdev->dev, "could not attach to PHY\n");
		return PTR_ERR(phydev);
	}

	/* mask with MAC supported features */
	phydev->supported &= (SUPPORTED_10baseT_Half
				| SUPPORTED_10baseT_Full
				| SUPPORTED_100baseT_Half
				| SUPPORTED_100baseT_Full
				| SUPPORTED_Autoneg
				| SUPPORTED_MII
				| SUPPORTED_TP);

	phydev->advertising = phydev->supported;
	priv->phydev = phydev;
	priv->old_link = 0;
	priv->old_duplex = -1;

	phy_attached_info(phydev);

	return 0;
}

static int pci_eth_poll(struct napi_struct *napi, int budget)
{
	struct pci_eth_private *priv =
		container_of(napi, struct pci_eth_private, napi);
	struct net_device *dev = priv->dev;
	void __iomem *ioaddr = dev->base_addr;
	int work_done;

	work_done = pci_eth_rx(dev, budget);

	if (work_done < budget) {
		napi_complete(napi);
		/* TODO: Enable RX interrupt */
	}
	return work_done;
}


static int pci_eth_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct net_device *dev;
	struct pci_eth_private *priv;
	void __iomem *ioaddr;
	int err;
	static int card_idx = -1;
	int bar = 0; /* Base Adderess Register 0 */
	u16 *adrp;
	unsigned long iomem_size;

	pr_info("%s\n", version);

	/* Wake up PCI device */
	err = pci_enable_device(pdev);
	if (err)
		goto err_out;

	/* Does the device support 32-bit DMA address? */
	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
	if (err) {
		dev_err(&pdev->dev, "32-bit PCI DMA addresses"
				"not supported by the card\n");
		goto err_out_disable_dev;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
	if (err) {
		dev_err(&pdev->dev, "32-bit PCI DMA addresses"
				"not supported by the card\n");
		goto err_out_disable_dev;
	}

	/* Get IO Size */
	iomem_size = pci_resource_len(pdev, bar);
	pr_info("iomem_size = 0x%lx\n", iomem_size);

	/* Enable PCI bus mastering */
	pci_set_master(pdev);

	/* Reserve PCI I/O and memory resources */
	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(&pdev->dev, "Failed to request PCI regions\n");
		goto err_out_free_dev;
	}

	/* Map iomem_size bytes. After that ioaddr can be used via ioread*
	 * and iwrite* functions.
	 */
	ioaddr = pci_iomap(pdev, bar, iomem_size);
	if (!ioaddr) {
		dev_err(&pdev->dev, "ioremap failed for device\n");
		err = -EIO;
		goto err_out_free_res;
	}

	dev = alloc_etherdev(sizeof(struct pci_eth_private));
	if (!dev) {
		err = -ENOMEM;
		goto err_out_disable_dev;
	}
	SET_NETDEV_DEV(dev, &pdev->dev);
	priv = netdev_priv(dev);

	/* TODO: here we need to set PHY if it was not set by bootloader.
	 * (HW specific code)
	 */

	/* Set IRQ in struct net_device */
	dev->irq = pdev->irq;
	/* Set base address in struct net_device */
	dev->base_addr = ioaddr;

	/* Initialize spin lock */
	spin_lock_init(&priv->lock);

	/* Save struct net_device in the PCI private data */
	pci_set_drvdata(pdev, dev);

	/* TODO: Set MAC address (HW specific code) */

	/* Link new device into pci_eth_root_dev */
	priv->pdev = pdev;
	priv->dev = dev;

	/* TODO: Enable transmit and receive (HW specific code) */

	/* Fill struct net_device. */
	dev->netdev_ops = &pci_eth_netdev_ops;
	dev->watchdog_timeo = TX_TIMEOUT;

	netif_napi_add(dev, &priv->napi, pci_eth_poll, 64);

	priv->mii_bus = mdiobus_alloc();
	if (!priv->mii_bus) {
		dev_err(&pdev->dev, "mdiobus_alloc() failed\n");
		err = -ENOMEM;
		goto err_out_unmap;
	}

	/* Initialize MII if supported. */
	priv->mii_bus->priv = dev;
	priv->mii_bus->read = pci_eth_mdiobus_read;
	priv->mii_bus->write = pci_eth_mdiobus_write;
	priv->mii_bus->name = "pci_eth_mii";
	snprintf(priv->mii_bus->id, MII_BUS_ID_SIZE, "%s-%x",
		dev_name(&pdev->dev), card_idx);

	err = mdiobus_register(priv->mii_bus);
	if (err) {
		dev_err(&pdev->dev, "failed to register MII bus\n");
		goto err_out_mdio;
	}

	err = pci_eth_mii_probe(dev);
	if (err) {
		dev_err(&pdev->dev, "failed to probe MII bus\n");
		goto err_out_mdio_unregister;
	}

	/* Register net device. After this dev->name assign */
	err = register_netdev(dev);
	if (err) {
		dev_err(&pdev->dev, "Failed to register net device\n");
		goto err_out_mdio_unregister;
	}
	return 0;

err_out_mdio_unregister:
	mdiobus_unregister(priv->mii_bus);
err_out_mdio:
	mdiobus_free(priv->mii_bus);
err_out_unmap:
	netif_napi_del(&priv->napi);
	pci_iounmap(pdev, ioaddr);
err_out_free_res:
	pci_release_regions(pdev);
err_out_free_dev:
	free_netdev(dev);
err_out_disable_dev:
	pci_disable_device(pdev);
err_out:
	return err;
}

static void pci_eth_remove(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct pci_eth_private *priv = netdev_priv(dev);

	unregister_netdev(dev);
	mdiobus_unregister(priv->mii_bus);
	mdiobus_free(priv->mii_bus);
	netif_napi_del(&priv->napi);
	pci_iounmap(pdev, priv->base);
	pci_release_regions(pdev);
	free_netdev(dev);
	pci_disable_device(pdev);
}


static const struct pci_device_id pci_eth_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_ETH, PCI_DEVICE_ID_ETH) },
	{ 0 }
};
MODULE_DEVICE_TABLE(pci, pci_eth_id_table);

static struct pci_driver pci_eth_driver = {
	.name		= DRV_NAME,
	.id_table	= pci_eth_id_table,
	.probe		= pci_eth_probe,
	.remove		= pci_eth_remove,
};

module_pci_driver(pci_eth_driver);


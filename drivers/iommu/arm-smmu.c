/*
 * IOMMU API for ARM architected SMMU implementations.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2013 ARM Limited
 * Copyright (C) 2020 XiaoMi, Inc.
 *
 * Author: Will Deacon <will.deacon@arm.com>
 *
 * This driver currently supports:
 *	- SMMUv1 and v2 implementations
 *	- Stream-matching and stream-indexing
 *	- v7/v8 long-descriptor format
 *	- Non-secure access to the SMMU
 *	- Context fault reporting
 *	- Extended Stream ID (16 bit)
 */

#define pr_fmt(fmt) "arm-smmu: " fmt

#include <linux/acpi.h>
#include <linux/acpi_iort.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/io-64-nonatomic-hi-lo.h>
#include <linux/io-pgtable.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_iommu.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <linux/amba/bus.h>

#include "arm-smmu-regs.h"

/*
 * Apparently, some Qualcomm arm64 platforms which appear to expose their SMMU
 * global register space are still, in fact, using a hypervisor to mediate it
 * by trapping and emulating register accesses. Sadly, some deployed versions
 * of said trapping code have bugs wherein they go horribly wrong for stores
 * using r31 (i.e. XZR/WZR) as the source register.
 */
#define QCOM_DUMMY_VAL -1

#define ARM_MMU500_ACTLR_CPRE		(1 << 1)

#define ARM_MMU500_ACR_CACHE_LOCK	(1 << 26)
#define ARM_MMU500_ACR_S2CRB_TLBEN	(1 << 10)
#define ARM_MMU500_ACR_SMTNMB_TLBEN	(1 << 8)

#define TLB_LOOP_TIMEOUT		1000000	/* 1s! */
#define TLB_SPIN_COUNT			10

/* Maximum number of context banks per SMMU */
#define ARM_SMMU_MAX_CBS		128

/* SMMU global address space */
#define ARM_SMMU_GR0(smmu)		((smmu)->base)
#define ARM_SMMU_GR1(smmu)		((smmu)->base + (1 << (smmu)->pgshift))

/*
 * SMMU global address space with conditional offset to access secure
 * aliases of non-secure registers (e.g. nsCR0: 0x400, nsGFSR: 0x448,
 * nsGFSYNR0: 0x450)
 */
#define ARM_SMMU_GR0_NS(smmu)						\
	((smmu)->base +							\
		((smmu->options & ARM_SMMU_OPT_SECURE_CFG_ACCESS)	\
			? 0x400 : 0))

/*
 * Some 64-bit registers only make sense to write atomically, but in such
 * cases all the data relevant to AArch32 formats lies within the lower word,
 * therefore this actually makes more sense than it might first appear.
 */
#ifdef CONFIG_64BIT
#define smmu_write_atomic_lq		writeq_relaxed
#else
#define smmu_write_atomic_lq		writel_relaxed
#endif

/* Translation context bank */
#define ARM_SMMU_CB(smmu, n)	((smmu)->cb_base + ((n) << (smmu)->pgshift))

#define MSI_IOVA_BASE			0x8000000
#define MSI_IOVA_LENGTH			0x100000

static int force_stage;
module_param(force_stage, int, S_IRUGO);
MODULE_PARM_DESC(force_stage,
	"Force SMMU mappings to be installed at a particular stage of translation. A value of '1' or '2' forces the corresponding stage. All other values are ignored (i.e. no stage is forced). Note that selecting a specific stage will disable support for nested translation.");
static bool disable_bypass;
module_param(disable_bypass, bool, S_IRUGO);
MODULE_PARM_DESC(disable_bypass,
	"Disable bypass streams such that incoming transactions from devices that are not attached to an iommu domain will report an abort back to the device and will not be allowed to pass through the SMMU.");

enum arm_smmu_arch_version {
	ARM_SMMU_V1,
	ARM_SMMU_V1_64K,
	ARM_SMMU_V2,
};

enum arm_smmu_implementation {
	GENERIC_SMMU,
	ARM_MMU500,
	CAVIUM_SMMUV2,
	QCOM_SMMUV2,
};

struct arm_smmu_s2cr {
	struct iommu_group		*group;
	int				count;
	enum arm_smmu_s2cr_type		type;
	enum arm_smmu_s2cr_privcfg	privcfg;
	u8				cbndx;
};

#define s2cr_init_val (struct arm_smmu_s2cr){				\
	.type = disable_bypass ? S2CR_TYPE_FAULT : S2CR_TYPE_BYPASS,	\
}

struct arm_smmu_smr {
	u16				mask;
	u16				id;
	bool				valid;
};

struct arm_smmu_cb {
	u64				ttbr[2];
	u32				tcr[2];
	u32				mair[2];
	struct arm_smmu_cfg		*cfg;
};

struct arm_smmu_master_cfg {
	struct arm_smmu_device		*smmu;
	s16				smendx[];
};
#define INVALID_SMENDX			-1
#define __fwspec_cfg(fw) ((struct arm_smmu_master_cfg *)fw->iommu_priv)
#define fwspec_smmu(fw)  (__fwspec_cfg(fw)->smmu)
#define fwspec_smendx(fw, i) \
	(i >= fw->num_ids ? INVALID_SMENDX : __fwspec_cfg(fw)->smendx[i])
#define for_each_cfg_sme(fw, i, idx) \
	for (i = 0; idx = fwspec_smendx(fw, i), i < fw->num_ids; ++i)

struct arm_smmu_device {
	struct device			*dev;

	void __iomem			*base;
	void __iomem			*cb_base;
	unsigned long			pgshift;

#define ARM_SMMU_FEAT_COHERENT_WALK	(1 << 0)
#define ARM_SMMU_FEAT_STREAM_MATCH	(1 << 1)
#define ARM_SMMU_FEAT_TRANS_S1		(1 << 2)
#define ARM_SMMU_FEAT_TRANS_S2		(1 << 3)
#define ARM_SMMU_FEAT_TRANS_NESTED	(1 << 4)
#define ARM_SMMU_FEAT_TRANS_OPS		(1 << 5)
#define ARM_SMMU_FEAT_VMID16		(1 << 6)
#define ARM_SMMU_FEAT_FMT_AARCH64_4K	(1 << 7)
#define ARM_SMMU_FEAT_FMT_AARCH64_16K	(1 << 8)
#define ARM_SMMU_FEAT_FMT_AARCH64_64K	(1 << 9)
#define ARM_SMMU_FEAT_FMT_AARCH32_L	(1 << 10)
#define ARM_SMMU_FEAT_FMT_AARCH32_S	(1 << 11)
#define ARM_SMMU_FEAT_EXIDS		(1 << 12)
	u32				features;

#define ARM_SMMU_OPT_SECURE_CFG_ACCESS (1 << 0)
	u32				options;
	enum arm_smmu_arch_version	version;
	enum arm_smmu_implementation	model;

	u32				num_context_banks;
	u32				num_s2_context_banks;
	DECLARE_BITMAP(context_map, ARM_SMMU_MAX_CBS);
	struct arm_smmu_cb		*cbs;
	atomic_t			irptndx;

	u32				num_mapping_groups;
	u16				streamid_mask;
	u16				smr_mask_mask;
	struct arm_smmu_smr		*smrs;
	struct arm_smmu_s2cr		*s2crs;
	struct mutex			stream_map_mutex;

	unsigned long			va_size;
	unsigned long			ipa_size;
	unsigned long			pa_size;
	unsigned long			pgsize_bitmap;

	u32				num_global_irqs;
	u32				num_context_irqs;
	unsigned int			*irqs;

	u32				cavium_id_base; /* Specific to Cavium */

	spinlock_t			global_sync_lock;

	/* IOMMU core code handle */
	struct iommu_device		iommu;
};

enum arm_smmu_context_fmt {
	ARM_SMMU_CTX_FMT_NONE,
	ARM_SMMU_CTX_FMT_AARCH64,
	ARM_SMMU_CTX_FMT_AARCH32_L,
	ARM_SMMU_CTX_FMT_AARCH32_S,
};

struct arm_smmu_cfg {
	u8				cbndx;
	u8				irptndx;
	union {
		u16			asid;
		u16			vmid;
	};
	u32				cbar;
	enum arm_smmu_context_fmt	fmt;
};
#define INVALID_IRPTNDX			0xff

enum arm_smmu_domain_stage {
	ARM_SMMU_DOMAIN_S1 = 0,
	ARM_SMMU_DOMAIN_S2,
	ARM_SMMU_DOMAIN_NESTED,
	ARM_SMMU_DOMAIN_BYPASS,
};

struct arm_smmu_domain {
	struct arm_smmu_device		*smmu;
	struct io_pgtable_ops		*pgtbl_ops;
	const struct iommu_gather_ops	*tlb_ops;
	struct arm_smmu_cfg		cfg;
	enum arm_smmu_domain_stage	stage;
	struct mutex			init_mutex; /* Protects smmu pointer */
	spinlock_t			cb_lock; /* Serialises ATS1* ops and TLB syncs */
	struct iommu_domain		domain;
};

struct arm_smmu_option_prop {
	u32 opt;
	const char *prop;
};

static atomic_t cavium_smmu_context_count = ATOMIC_INIT(0);

static bool using_legacy_binding, using_generic_binding;

static struct arm_smmu_option_prop arm_smmu_options[] = {
	{ ARM_SMMU_OPT_SECURE_CFG_ACCESS, "calxeda,smmu-secure-config-access" },
	{ 0, NULL},
};

static struct arm_smmu_domain *to_smmu_domain(struct iommu_domain *dom)
{
	return container_of(dom, struct arm_smmu_domain, domain);
}

static void parse_driver_options(struct arm_smmu_device *smmu)
{
	int i = 0;

	do {
		if (of_property_read_bool(smmu->dev->of_node,
						arm_smmu_options[i].prop)) {
			smmu->options |= arm_smmu_options[i].opt;
			dev_notice(smmu->dev, "option %s\n",
				arm_smmu_options[i].prop);
		}
	} while (arm_smmu_options[++i].opt);
}

static struct device_node *dev_get_dev_node(struct device *dev)
{
	if (dev_is_pci(dev)) {
		struct pci_bus *bus = to_pci_dev(dev)->bus;

		while (!pci_is_root_bus(bus))
			bus = bus->parent;
		return of_node_get(bus->bridge->parent->of_node);
	}

	return of_node_get(dev->of_node);
}

static int __arm_smmu_get_pci_sid(struct pci_dev *pdev, u16 alias, void *data)
{
	*((__be32 *)data) = cpu_to_be32(alias);
	return 0; /* Continue walking */
}

static int __find_legacy_master_phandle(struct device *dev, void *data)
{
	struct of_phandle_iterator *it = *(void **)data;
	struct device_node *np = it->node;
	int err;

	of_for_each_phandle(it, err, dev->of_node, "mmu-masters",
			    "#stream-id-cells", 0)
		if (it->node == np) {
			*(void **)data = dev;
			return 1;
		}
	it->node = np;
	return err == -ENOENT ? 0 : err;
}

static struct platform_driver arm_smmu_driver;
static struct iommu_ops arm_smmu_ops;

static int arm_smmu_register_legacy_master(struct device *dev,
					   struct arm_smmu_device **smmu)
{
	struct device *smmu_dev;
	struct device_node *np;
	struct of_phandle_iterator it;
	void *data = &it;
	u32 *sids;
	__be32 pci_sid;
	int err;

	np = dev_get_dev_node(dev);
	if (!np || !of_find_property(np, "#stream-id-cells", NULL)) {
		of_node_put(np);
		return -ENODEV;
	}

	it.node = np;
	err = driver_for_each_device(&arm_smmu_driver.driver, NULL, &data,
				     __find_legacy_master_phandle);
	smmu_dev = data;
	of_node_put(np);
	if (err == 0)
		return -ENODEV;
	if (err < 0)
		return err;

	if (dev_is_pci(dev)) {
		/* "mmu-masters" assumes Stream ID == Requester ID */
		pci_for_each_dma_alias(to_pci_dev(dev), __arm_smmu_get_pci_sid,
				       &pci_sid);
		it.cur = &pci_sid;
		it.cur_count = 1;
	}

	err = iommu_fwspec_init(dev, &smmu_dev->of_node->fwnode,
				&arm_smmu_ops);
	if (err)
		return err;

	sids = kcalloc(it.cur_count, sizeof(*sids), GFP_KERNEL);
	if (!sids)
		return -ENOMEM;

	*smmu = dev_get_drvdata(smmu_dev);
	of_phandle_iterator_args(&it, sids, it.cur_count);
	err = iommu_fwspec_add_ids(dev, sids, it.cur_count);
	kfree(sids);
	return err;
}

static int __arm_smmu_alloc_bitmap(unsigned long *map, int start, int end)
{
	int idx;

	do {
		idx = find_next_zero_bit(map, end, start);
		if (idx == end)
			return -ENOSPC;
	} while (test_and_set_bit(idx, map));

	return idx;
}

static void __arm_smmu_free_bitmap(unsigned long *map, int idx)
{
	clear_bit(idx, map);
}

static int arm_smmu_prepare_clocks(struct arm_smmu_power_resources *pwr)
{
	int i, ret = 0;

	for (i = 0; i < pwr->num_clocks; ++i) {
		ret = clk_prepare(pwr->clocks[i]);
		if (ret) {
			dev_err(pwr->dev, "Couldn't prepare clock #%d\n", i);
			while (i--)
				clk_unprepare(pwr->clocks[i]);
			break;
		}
	}
	return ret;
}

static void arm_smmu_unprepare_clocks(struct arm_smmu_power_resources *pwr)
{
	int i;

	for (i = pwr->num_clocks; i; --i)
		clk_unprepare(pwr->clocks[i - 1]);
}

static int arm_smmu_enable_clocks(struct arm_smmu_power_resources *pwr)
{
	int i, ret = 0;

	for (i = 0; i < pwr->num_clocks; ++i) {
		ret = clk_enable(pwr->clocks[i]);
		if (ret) {
			dev_err(pwr->dev, "Couldn't enable clock #%d\n", i);
			while (i--)
				clk_disable(pwr->clocks[i]);
			break;
		}
	}

	return ret;
}

static void arm_smmu_disable_clocks(struct arm_smmu_power_resources *pwr)
{
	int i;

	for (i = pwr->num_clocks; i; --i)
		clk_disable(pwr->clocks[i - 1]);
}

static int arm_smmu_request_bus(struct arm_smmu_power_resources *pwr)
{
	if (!pwr->bus_client)
		return 0;
	return msm_bus_scale_client_update_request(pwr->bus_client, 1);
}

static void arm_smmu_unrequest_bus(struct arm_smmu_power_resources *pwr)
{
	if (!pwr->bus_client)
		return;
	WARN_ON(msm_bus_scale_client_update_request(pwr->bus_client, 0));
}

static int arm_smmu_enable_regulators(struct arm_smmu_power_resources *pwr)
{
	struct regulator_bulk_data *consumers;
	int num_consumers, ret;
	int i;

	num_consumers = pwr->num_gdscs;
	consumers = pwr->gdscs;
	for (i = 0; i < num_consumers; i++) {
		ret = regulator_enable(consumers[i].consumer);
		if (ret)
			goto out;
	}
	return 0;

out:
	i -= 1;
	for (; i >= 0; i--)
		regulator_disable(consumers[i].consumer);
	return ret;
}

static int arm_smmu_disable_regulators(struct arm_smmu_power_resources *pwr)
{
	struct regulator_bulk_data *consumers;
	int i;
	int num_consumers, ret, r;

	num_consumers = pwr->num_gdscs;
	consumers = pwr->gdscs;
	for (i = num_consumers - 1; i >= 0; --i) {
		ret = regulator_disable_deferred(consumers[i].consumer,
						 pwr->regulator_defer);
		if (ret != 0)
			goto err;
	}

	return 0;

err:
	pr_err("Failed to disable %s: %d\n", consumers[i].supply, ret);
	for (++i; i < num_consumers; ++i) {
		r = regulator_enable(consumers[i].consumer);
		if (r != 0)
			pr_err("Failed to rename %s: %d\n",
			       consumers[i].supply, r);
	}

	return ret;
}

/* Clocks must be prepared before this (arm_smmu_prepare_clocks) */
static int arm_smmu_power_on_atomic(struct arm_smmu_power_resources *pwr)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&pwr->clock_refs_lock, flags);
	if (pwr->clock_refs_count > 0) {
		pwr->clock_refs_count++;
		spin_unlock_irqrestore(&pwr->clock_refs_lock, flags);
		return 0;
	}

	ret = arm_smmu_enable_clocks(pwr);
	if (!ret)
		pwr->clock_refs_count = 1;

	spin_unlock_irqrestore(&pwr->clock_refs_lock, flags);
	return ret;
}

/* Clocks should be unprepared after this (arm_smmu_unprepare_clocks) */
static void arm_smmu_power_off_atomic(struct arm_smmu_power_resources *pwr)
{
	unsigned long flags;
	struct arm_smmu_device *smmu = pwr->dev->driver_data;

	arm_smmu_arch_write_sync(smmu);

	spin_lock_irqsave(&pwr->clock_refs_lock, flags);
	if (pwr->clock_refs_count == 0) {
		WARN(1, "%s: bad clock_ref_count\n", dev_name(pwr->dev));
		spin_unlock_irqrestore(&pwr->clock_refs_lock, flags);
		return;

	} else if (pwr->clock_refs_count > 1) {
		pwr->clock_refs_count--;
		spin_unlock_irqrestore(&pwr->clock_refs_lock, flags);
		return;
	}

	arm_smmu_disable_clocks(pwr);

	pwr->clock_refs_count = 0;
	spin_unlock_irqrestore(&pwr->clock_refs_lock, flags);
}

static int arm_smmu_power_on_slow(struct arm_smmu_power_resources *pwr)
{
	int ret;

	mutex_lock(&pwr->power_lock);
	if (pwr->power_count > 0) {
		pwr->power_count += 1;
		mutex_unlock(&pwr->power_lock);
		return 0;
	}

	ret = arm_smmu_request_bus(pwr);
	if (ret)
		goto out_unlock;

	ret = arm_smmu_enable_regulators(pwr);
	if (ret)
		goto out_disable_bus;

	ret = arm_smmu_prepare_clocks(pwr);
	if (ret)
		goto out_disable_regulators;

	pwr->power_count = 1;
	mutex_unlock(&pwr->power_lock);
	return 0;

out_disable_regulators:
	regulator_bulk_disable(pwr->num_gdscs, pwr->gdscs);
out_disable_bus:
	arm_smmu_unrequest_bus(pwr);
out_unlock:
	mutex_unlock(&pwr->power_lock);
	return ret;
}

static void arm_smmu_power_off_slow(struct arm_smmu_power_resources *pwr)
{
	mutex_lock(&pwr->power_lock);
	if (pwr->power_count == 0) {
		WARN(1, "%s: Bad power count\n", dev_name(pwr->dev));
		mutex_unlock(&pwr->power_lock);
		return;

	} else if (pwr->power_count > 1) {
		pwr->power_count--;
		mutex_unlock(&pwr->power_lock);
		return;
	}

	arm_smmu_unprepare_clocks(pwr);
	arm_smmu_disable_regulators(pwr);
	arm_smmu_unrequest_bus(pwr);
	pwr->power_count = 0;
	mutex_unlock(&pwr->power_lock);
}

static int arm_smmu_power_on(struct arm_smmu_power_resources *pwr)
{
	int ret;

	ret = arm_smmu_power_on_slow(pwr);
	if (ret)
		return ret;

	ret = arm_smmu_power_on_atomic(pwr);
	if (ret)
		goto out_disable;

	return 0;

out_disable:
	arm_smmu_power_off_slow(pwr);
	return ret;
}

static void arm_smmu_power_off(struct arm_smmu_power_resources *pwr)
{
	arm_smmu_power_off_atomic(pwr);
	arm_smmu_power_off_slow(pwr);
}

/*
 * Must be used instead of arm_smmu_power_on if it may be called from
 * atomic context
 */
static int arm_smmu_domain_power_on(struct iommu_domain *domain,
				struct arm_smmu_device *smmu)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	int atomic_domain = smmu_domain->attributes & (1 << DOMAIN_ATTR_ATOMIC);

	if (atomic_domain)
		return arm_smmu_power_on_atomic(smmu->pwr);

	return arm_smmu_power_on(smmu->pwr);
}

/*
 * Must be used instead of arm_smmu_power_on if it may be called from
 * atomic context
 */
static void arm_smmu_domain_power_off(struct iommu_domain *domain,
				struct arm_smmu_device *smmu)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	int atomic_domain = smmu_domain->attributes & (1 << DOMAIN_ATTR_ATOMIC);

	if (atomic_domain) {
		arm_smmu_power_off_atomic(smmu->pwr);
		return;
	}

	arm_smmu_power_off(smmu->pwr);
}

static struct qsmmuv500_tbu_device *qsmmuv500_find_tbu(
	struct arm_smmu_device *smmu, u32 sid)
{
	struct qsmmuv500_tbu_device *tbu = NULL;
	struct qsmmuv500_archdata *data = get_qsmmuv500_archdata(smmu);

	list_for_each_entry(tbu, &data->tbus, list) {
		if (tbu->sid_start <= sid &&
		    sid < tbu->sid_start + tbu->num_sids)
			return tbu;
	}
	return NULL;
}

static void arm_smmu_testbus_dump(struct arm_smmu_device *smmu, u16 sid)
{
	if (smmu->model == QCOM_SMMUV500 &&
	    IS_ENABLED(CONFIG_ARM_SMMU_TESTBUS_DUMP)) {
		struct qsmmuv500_archdata *data;
		struct qsmmuv500_tbu_device *tbu;

		data = smmu->archdata;
		tbu = qsmmuv500_find_tbu(smmu, sid);
		spin_lock(&testbus_lock);
		if (tbu)
			arm_smmu_debug_dump_tbu_testbus(tbu->dev,
							tbu->base,
							data->tcu_base,
							tbu_testbus_sel,
							data->testbus_version);
		else
			arm_smmu_debug_dump_tcu_testbus(smmu->dev,
							smmu->phys_addr,
							data->tcu_base,
							tcu_testbus_sel);
		spin_unlock(&testbus_lock);
	}
}

static void __arm_smmu_tlb_sync_timeout(struct arm_smmu_device *smmu)
{
	u32 sync_inv_ack, tbu_pwr_status, sync_inv_progress;
	u32 tbu_inv_pending = 0, tbu_sync_pending = 0;
	u32 tbu_inv_acked = 0, tbu_sync_acked = 0;
	u32 tcu_inv_pending = 0, tcu_sync_pending = 0;
	u32 tbu_ids = 0;
	phys_addr_t base_phys = smmu->phys_addr;


	static DEFINE_RATELIMIT_STATE(_rs,
				      DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);

	sync_inv_ack = scm_io_read(base_phys + ARM_SMMU_STATS_SYNC_INV_TBU_ACK);
	tbu_pwr_status = scm_io_read(base_phys + ARM_SMMU_TBU_PWR_STATUS);
	sync_inv_progress = scm_io_read(base_phys +
					ARM_SMMU_MMU2QSS_AND_SAFE_WAIT_CNTR);

	if (sync_inv_ack) {
		tbu_inv_pending = (sync_inv_ack >> TBU_INV_REQ_SHIFT) &
			TBU_INV_REQ_MASK;
		tbu_inv_acked = (sync_inv_ack >> TBU_INV_ACK_SHIFT) &
			TBU_INV_ACK_MASK;
		tbu_sync_pending = (sync_inv_ack >> TBU_SYNC_REQ_SHIFT) &
			TBU_SYNC_REQ_MASK;
		tbu_sync_acked = (sync_inv_ack >> TBU_SYNC_ACK_SHIFT) &
			TBU_SYNC_ACK_MASK;
	}

	if (tbu_pwr_status) {
		if (tbu_sync_pending)
			tbu_ids = tbu_pwr_status & ~tbu_sync_acked;
		else if (tbu_inv_pending)
			tbu_ids = tbu_pwr_status & ~tbu_inv_acked;
	}

	tcu_inv_pending = (sync_inv_progress >> TCU_INV_IN_PRGSS_SHIFT) &
		TCU_INV_IN_PRGSS_MASK;
	tcu_sync_pending = (sync_inv_progress >> TCU_SYNC_IN_PRGSS_SHIFT) &
		TCU_SYNC_IN_PRGSS_MASK;

	if (__ratelimit(&_rs)) {
		unsigned long tbu_id, tbus_t = tbu_ids;

		dev_err(smmu->dev,
			"TLB sync timed out -- SMMU may be deadlocked\n"
			"TBU ACK 0x%x TBU PWR 0x%x TCU sync_inv 0x%x\n",
			sync_inv_ack, tbu_pwr_status, sync_inv_progress);
		dev_err(smmu->dev,
			"TCU invalidation %s, TCU sync %s\n",
			tcu_inv_pending?"pending":"completed",
			tcu_sync_pending?"pending":"completed");

		dev_err(smmu->dev, "TBU PWR status 0x%x\n", tbu_pwr_status);

		while (tbus_t) {
			struct qsmmuv500_tbu_device *tbu;

			tbu_id = __ffs(tbus_t);
			tbus_t = tbus_t & ~(1 << tbu_id);
			tbu = qsmmuv500_find_tbu(smmu,
						 (u16)(tbu_id << TBUID_SHIFT));
			if (tbu) {
				dev_err(smmu->dev,
					"TBU %s ack pending for TBU %s, %s\n",
					tbu_sync_pending?"sync" : "inv",
					dev_name(tbu->dev),
					tbu_sync_pending ?
					"check pending transactions on TBU"
					: "check for TBU power status");
				arm_smmu_testbus_dump(smmu,
						(u16)(tbu_id << TBUID_SHIFT));
			}
		}

		/*dump TCU testbus*/
		arm_smmu_testbus_dump(smmu, U16_MAX);
	}

	BUG_ON(IS_ENABLED(CONFIG_IOMMU_TLBSYNC_DEBUG));
}

/* Wait for any pending TLB invalidations to complete */
static void __arm_smmu_tlb_sync(struct arm_smmu_device *smmu,
				void __iomem *sync, void __iomem *status)
{
	unsigned int spin_cnt, delay;

	writel_relaxed(QCOM_DUMMY_VAL, sync);
	for (delay = 1; delay < TLB_LOOP_TIMEOUT; delay *= 2) {
		for (spin_cnt = TLB_SPIN_COUNT; spin_cnt > 0; spin_cnt--) {
			if (!(readl_relaxed(status) & sTLBGSTATUS_GSACTIVE))
				return;
			cpu_relax();
		}
		udelay(delay);
	}
	dev_err_ratelimited(smmu->dev,
			    "TLB sync timed out -- SMMU may be deadlocked\n");
}

static void arm_smmu_tlb_sync_global(struct arm_smmu_device *smmu)
{
	void __iomem *base = ARM_SMMU_GR0(smmu);
	unsigned long flags;

	spin_lock_irqsave(&smmu->global_sync_lock, flags);
	__arm_smmu_tlb_sync(smmu, base + ARM_SMMU_GR0_sTLBGSYNC,
			    base + ARM_SMMU_GR0_sTLBGSTATUS);
	spin_unlock_irqrestore(&smmu->global_sync_lock, flags);
}

static void arm_smmu_tlb_sync_context(void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	void __iomem *base = ARM_SMMU_CB(smmu, smmu_domain->cfg.cbndx);
	unsigned long flags;

	spin_lock_irqsave(&smmu_domain->cb_lock, flags);
	__arm_smmu_tlb_sync(smmu, base + ARM_SMMU_CB_TLBSYNC,
			    base + ARM_SMMU_CB_TLBSTATUS);
	spin_unlock_irqrestore(&smmu_domain->cb_lock, flags);
}

static void arm_smmu_tlb_sync_vmid(void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;

	arm_smmu_tlb_sync_global(smmu_domain->smmu);
}

static void arm_smmu_tlb_inv_context_s1(void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	struct arm_smmu_cfg *cfg = &smmu_domain->cfg;
	void __iomem *base = ARM_SMMU_CB(smmu_domain->smmu, cfg->cbndx);

	writel_relaxed(cfg->asid, base + ARM_SMMU_CB_S1_TLBIASID);
	arm_smmu_tlb_sync_context(cookie);
}

static void arm_smmu_tlb_inv_context_s2(void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	void __iomem *base = ARM_SMMU_GR0(smmu);

	writel_relaxed(smmu_domain->cfg.vmid, base + ARM_SMMU_GR0_TLBIVMID);
	arm_smmu_tlb_sync_global(smmu);
}

static void arm_smmu_tlb_inv_range_nosync(unsigned long iova, size_t size,
					  size_t granule, bool leaf, void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	struct arm_smmu_cfg *cfg = &smmu_domain->cfg;
	bool stage1 = cfg->cbar != CBAR_TYPE_S2_TRANS;
	void __iomem *reg = ARM_SMMU_CB(smmu_domain->smmu, cfg->cbndx);

	if (smmu_domain->smmu->features & ARM_SMMU_FEAT_COHERENT_WALK)
		wmb();

	if (stage1) {
		reg += leaf ? ARM_SMMU_CB_S1_TLBIVAL : ARM_SMMU_CB_S1_TLBIVA;

		if (cfg->fmt != ARM_SMMU_CTX_FMT_AARCH64) {
			iova &= ~12UL;
			iova |= cfg->asid;
			do {
				writel_relaxed(iova, reg);
				iova += granule;
			} while (size -= granule);
		} else {
			iova >>= 12;
			iova |= (u64)cfg->asid << 48;
			do {
				writeq_relaxed(iova, reg);
				iova += granule >> 12;
			} while (size -= granule);
		}
	} else {
		reg += leaf ? ARM_SMMU_CB_S2_TLBIIPAS2L :
			      ARM_SMMU_CB_S2_TLBIIPAS2;
		iova >>= 12;
		do {
			smmu_write_atomic_lq(iova, reg);
			iova += granule >> 12;
		} while (size -= granule);
	}
}

/*
 * On MMU-401 at least, the cost of firing off multiple TLBIVMIDs appears
 * almost negligible, but the benefit of getting the first one in as far ahead
 * of the sync as possible is significant, hence we don't just make this a
 * no-op and set .tlb_sync to arm_smmu_inv_context_s2() as you might think.
 */
static void arm_smmu_tlb_inv_vmid_nosync(unsigned long iova, size_t size,
					 size_t granule, bool leaf, void *cookie)
{
	struct arm_smmu_domain *smmu_domain = cookie;
	void __iomem *base = ARM_SMMU_GR0(smmu_domain->smmu);

	if (smmu_domain->smmu->features & ARM_SMMU_FEAT_COHERENT_WALK)
		wmb();

	writel_relaxed(smmu_domain->cfg.vmid, base + ARM_SMMU_GR0_TLBIVMID);
}

static const struct iommu_gather_ops arm_smmu_s1_tlb_ops = {
	.tlb_flush_all	= arm_smmu_tlb_inv_context_s1,
	.tlb_add_flush	= arm_smmu_tlb_inv_range_nosync,
	.tlb_sync	= arm_smmu_tlb_sync_context,
};

static const struct iommu_gather_ops arm_smmu_s2_tlb_ops_v2 = {
	.tlb_flush_all	= arm_smmu_tlb_inv_context_s2,
	.tlb_add_flush	= arm_smmu_tlb_inv_range_nosync,
	.tlb_sync	= arm_smmu_tlb_sync_context,
};

static const struct iommu_gather_ops arm_smmu_s2_tlb_ops_v1 = {
	.tlb_flush_all	= arm_smmu_tlb_inv_context_s2,
	.tlb_add_flush	= arm_smmu_tlb_inv_vmid_nosync,
	.tlb_sync	= arm_smmu_tlb_sync_vmid,
};

static irqreturn_t arm_smmu_context_fault(int irq, void *dev)
{
	u32 fsr, fsynr;
	unsigned long iova;
	struct iommu_domain *domain = dev;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_cfg *cfg = &smmu_domain->cfg;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	void __iomem *cb_base;

	cb_base = ARM_SMMU_CB(smmu, cfg->cbndx);
	fsr = readl_relaxed(cb_base + ARM_SMMU_CB_FSR);

	if (!(fsr & FSR_FAULT))
		return IRQ_NONE;

	fsynr = readl_relaxed(cb_base + ARM_SMMU_CB_FSYNR0);
	iova = readq_relaxed(cb_base + ARM_SMMU_CB_FAR);

	dev_err_ratelimited(smmu->dev,
	"Unhandled context fault: fsr=0x%x, iova=0x%08lx, fsynr=0x%x, cb=%d\n",
			    fsr, iova, fsynr, cfg->cbndx);

	writel(fsr, cb_base + ARM_SMMU_CB_FSR);
	return IRQ_HANDLED;
}

static irqreturn_t arm_smmu_global_fault(int irq, void *dev)
{
	u32 gfsr, gfsynr0, gfsynr1, gfsynr2;
	struct arm_smmu_device *smmu = dev;
	void __iomem *gr0_base = ARM_SMMU_GR0_NS(smmu);

	gfsr = readl_relaxed(gr0_base + ARM_SMMU_GR0_sGFSR);
	gfsynr0 = readl_relaxed(gr0_base + ARM_SMMU_GR0_sGFSYNR0);
	gfsynr1 = readl_relaxed(gr0_base + ARM_SMMU_GR0_sGFSYNR1);
	gfsynr2 = readl_relaxed(gr0_base + ARM_SMMU_GR0_sGFSYNR2);

	if (!gfsr)
		return IRQ_NONE;

	dev_err_ratelimited(smmu->dev,
		"Unexpected global fault, this could be serious\n");
	dev_err_ratelimited(smmu->dev,
		"\tGFSR 0x%08x, GFSYNR0 0x%08x, GFSYNR1 0x%08x, GFSYNR2 0x%08x\n",
		gfsr, gfsynr0, gfsynr1, gfsynr2);

	writel(gfsr, gr0_base + ARM_SMMU_GR0_sGFSR);
	return IRQ_HANDLED;
}

static void arm_smmu_init_context_bank(struct arm_smmu_domain *smmu_domain,
				       struct io_pgtable_cfg *pgtbl_cfg)
{
	struct arm_smmu_cfg *cfg = &smmu_domain->cfg;
	struct arm_smmu_cb *cb = &smmu_domain->smmu->cbs[cfg->cbndx];
	bool stage1 = cfg->cbar != CBAR_TYPE_S2_TRANS;

	cb->cfg = cfg;

	/* TTBCR */
	if (stage1) {
		if (cfg->fmt == ARM_SMMU_CTX_FMT_AARCH32_S) {
			cb->tcr[0] = pgtbl_cfg->arm_v7s_cfg.tcr;
		} else {
			cb->tcr[0] = pgtbl_cfg->arm_lpae_s1_cfg.tcr;
			cb->tcr[1] = pgtbl_cfg->arm_lpae_s1_cfg.tcr >> 32;
			cb->tcr[1] |= TTBCR2_SEP_UPSTREAM;
			if (cfg->fmt == ARM_SMMU_CTX_FMT_AARCH64)
				cb->tcr[1] |= TTBCR2_AS;
		}
	} else {
		cb->tcr[0] = pgtbl_cfg->arm_lpae_s2_cfg.vtcr;
	}

	/* TTBRs */
	if (stage1) {
		if (cfg->fmt == ARM_SMMU_CTX_FMT_AARCH32_S) {
			cb->ttbr[0] = pgtbl_cfg->arm_v7s_cfg.ttbr[0];
			cb->ttbr[1] = pgtbl_cfg->arm_v7s_cfg.ttbr[1];
		} else {
			cb->ttbr[0] = pgtbl_cfg->arm_lpae_s1_cfg.ttbr[0];
			cb->ttbr[0] |= (u64)cfg->asid << TTBRn_ASID_SHIFT;
			cb->ttbr[1] = pgtbl_cfg->arm_lpae_s1_cfg.ttbr[1];
			cb->ttbr[1] |= (u64)cfg->asid << TTBRn_ASID_SHIFT;
		}
	} else {
		cb->ttbr[0] = pgtbl_cfg->arm_lpae_s2_cfg.vttbr;
	}

	/* MAIRs (stage-1 only) */
	if (stage1) {
		if (cfg->fmt == ARM_SMMU_CTX_FMT_AARCH32_S) {
			cb->mair[0] = pgtbl_cfg->arm_v7s_cfg.prrr;
			cb->mair[1] = pgtbl_cfg->arm_v7s_cfg.nmrr;
		} else {
			cb->mair[0] = pgtbl_cfg->arm_lpae_s1_cfg.mair[0];
			cb->mair[1] = pgtbl_cfg->arm_lpae_s1_cfg.mair[1];
		}
	}
}

static void arm_smmu_write_context_bank(struct arm_smmu_device *smmu, int idx)
{
	u32 reg;
	bool stage1;
	struct arm_smmu_cb *cb = &smmu->cbs[idx];
	struct arm_smmu_cfg *cfg = cb->cfg;
	void __iomem *cb_base, *gr1_base;

	cb_base = ARM_SMMU_CB(smmu, idx);

	/* Unassigned context banks only need disabling */
	if (!cfg) {
		writel_relaxed(0, cb_base + ARM_SMMU_CB_SCTLR);
		return;
	}

	gr1_base = ARM_SMMU_GR1(smmu);
	stage1 = cfg->cbar != CBAR_TYPE_S2_TRANS;

	/* CBA2R */
	if (smmu->version > ARM_SMMU_V1) {
		if (cfg->fmt == ARM_SMMU_CTX_FMT_AARCH64)
			reg = CBA2R_RW64_64BIT;
		else
			reg = CBA2R_RW64_32BIT;
		/* 16-bit VMIDs live in CBA2R */
		if (smmu->features & ARM_SMMU_FEAT_VMID16)
			reg |= cfg->vmid << CBA2R_VMID_SHIFT;

		writel_relaxed(reg, gr1_base + ARM_SMMU_GR1_CBA2R(idx));
	}

	/* CBAR */
	reg = cfg->cbar;
	if (smmu->version < ARM_SMMU_V2)
		reg |= cfg->irptndx << CBAR_IRPTNDX_SHIFT;

	/*
	 * Use the weakest shareability/memory types, so they are
	 * overridden by the ttbcr/pte.
	 */
	if (stage1) {
		reg |= (CBAR_S1_BPSHCFG_NSH << CBAR_S1_BPSHCFG_SHIFT) |
			(CBAR_S1_MEMATTR_WB << CBAR_S1_MEMATTR_SHIFT);
	} else if (!(smmu->features & ARM_SMMU_FEAT_VMID16)) {
		/* 8-bit VMIDs live in CBAR */
		reg |= cfg->vmid << CBAR_VMID_SHIFT;
	}
	writel_relaxed(reg, gr1_base + ARM_SMMU_GR1_CBAR(idx));

	/*
	 * TTBCR
	 * We must write this before the TTBRs, since it determines the
	 * access behaviour of some fields (in particular, ASID[15:8]).
	 */
	if (stage1 && smmu->version > ARM_SMMU_V1)
		writel_relaxed(cb->tcr[1], cb_base + ARM_SMMU_CB_TTBCR2);
	writel_relaxed(cb->tcr[0], cb_base + ARM_SMMU_CB_TTBCR);

	/* TTBRs */
	if (cfg->fmt == ARM_SMMU_CTX_FMT_AARCH32_S) {
		writel_relaxed(cfg->asid, cb_base + ARM_SMMU_CB_CONTEXTIDR);
		writel_relaxed(cb->ttbr[0], cb_base + ARM_SMMU_CB_TTBR0);
		writel_relaxed(cb->ttbr[1], cb_base + ARM_SMMU_CB_TTBR1);
	} else {
		writeq_relaxed(cb->ttbr[0], cb_base + ARM_SMMU_CB_TTBR0);
		if (stage1)
			writeq_relaxed(cb->ttbr[1], cb_base + ARM_SMMU_CB_TTBR1);
	}

	/* MAIRs (stage-1 only) */
	if (stage1) {
		writel_relaxed(cb->mair[0], cb_base + ARM_SMMU_CB_S1_MAIR0);
		writel_relaxed(cb->mair[1], cb_base + ARM_SMMU_CB_S1_MAIR1);
	}

	/* SCTLR */
	reg = SCTLR_CFIE | SCTLR_CFRE | SCTLR_AFE | SCTLR_TRE | SCTLR_M;
	if (stage1)
		reg |= SCTLR_S1_ASIDPNE;
	if (IS_ENABLED(CONFIG_CPU_BIG_ENDIAN))
		reg |= SCTLR_E;

	writel_relaxed(reg, cb_base + ARM_SMMU_CB_SCTLR);
}

static int arm_smmu_init_domain_context(struct iommu_domain *domain,
					struct arm_smmu_device *smmu)
{
	int irq, start, ret = 0;
	unsigned long ias, oas;
	struct io_pgtable_ops *pgtbl_ops;
	struct io_pgtable_cfg pgtbl_cfg;
	enum io_pgtable_fmt fmt;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_cfg *cfg = &smmu_domain->cfg;

	mutex_lock(&smmu_domain->init_mutex);
	if (smmu_domain->smmu)
		goto out_unlock;

	if (domain->type == IOMMU_DOMAIN_IDENTITY) {
		smmu_domain->stage = ARM_SMMU_DOMAIN_BYPASS;
		smmu_domain->smmu = smmu;
		goto out_unlock;
	}

	/*
	 * Mapping the requested stage onto what we support is surprisingly
	 * complicated, mainly because the spec allows S1+S2 SMMUs without
	 * support for nested translation. That means we end up with the
	 * following table:
	 *
	 * Requested        Supported        Actual
	 *     S1               N              S1
	 *     S1             S1+S2            S1
	 *     S1               S2             S2
	 *     S1               S1             S1
	 *     N                N              N
	 *     N              S1+S2            S2
	 *     N                S2             S2
	 *     N                S1             S1
	 *
	 * Note that you can't actually request stage-2 mappings.
	 */
	if (!(smmu->features & ARM_SMMU_FEAT_TRANS_S1))
		smmu_domain->stage = ARM_SMMU_DOMAIN_S2;
	if (!(smmu->features & ARM_SMMU_FEAT_TRANS_S2))
		smmu_domain->stage = ARM_SMMU_DOMAIN_S1;

	/*
	 * Choosing a suitable context format is even more fiddly. Until we
	 * grow some way for the caller to express a preference, and/or move
	 * the decision into the io-pgtable code where it arguably belongs,
	 * just aim for the closest thing to the rest of the system, and hope
	 * that the hardware isn't esoteric enough that we can't assume AArch64
	 * support to be a superset of AArch32 support...
	 */
	if (smmu->features & ARM_SMMU_FEAT_FMT_AARCH32_L)
		cfg->fmt = ARM_SMMU_CTX_FMT_AARCH32_L;
	if (IS_ENABLED(CONFIG_IOMMU_IO_PGTABLE_ARMV7S) &&
	    !IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_ARM_LPAE) &&
	    (smmu->features & ARM_SMMU_FEAT_FMT_AARCH32_S) &&
	    (smmu_domain->stage == ARM_SMMU_DOMAIN_S1))
		cfg->fmt = ARM_SMMU_CTX_FMT_AARCH32_S;
	if ((IS_ENABLED(CONFIG_64BIT) || cfg->fmt == ARM_SMMU_CTX_FMT_NONE) &&
	    (smmu->features & (ARM_SMMU_FEAT_FMT_AARCH64_64K |
			       ARM_SMMU_FEAT_FMT_AARCH64_16K |
			       ARM_SMMU_FEAT_FMT_AARCH64_4K)))
		cfg->fmt = ARM_SMMU_CTX_FMT_AARCH64;

	if (cfg->fmt == ARM_SMMU_CTX_FMT_NONE) {
		ret = -EINVAL;
		goto out_unlock;
	}

	switch (smmu_domain->stage) {
	case ARM_SMMU_DOMAIN_S1:
		cfg->cbar = CBAR_TYPE_S1_TRANS_S2_BYPASS;
		start = smmu->num_s2_context_banks;
		ias = smmu->va_size;
		oas = smmu->ipa_size;
		if (cfg->fmt == ARM_SMMU_CTX_FMT_AARCH64) {
			fmt = ARM_64_LPAE_S1;
		} else if (cfg->fmt == ARM_SMMU_CTX_FMT_AARCH32_L) {
			fmt = ARM_32_LPAE_S1;
			ias = min(ias, 32UL);
			oas = min(oas, 40UL);
		} else {
			fmt = ARM_V7S;
			ias = min(ias, 32UL);
			oas = min(oas, 32UL);
		}
		smmu_domain->tlb_ops = &arm_smmu_s1_tlb_ops;
		break;
	case ARM_SMMU_DOMAIN_NESTED:
		/*
		 * We will likely want to change this if/when KVM gets
		 * involved.
		 */
	case ARM_SMMU_DOMAIN_S2:
		cfg->cbar = CBAR_TYPE_S2_TRANS;
		start = 0;
		ias = smmu->ipa_size;
		oas = smmu->pa_size;
		if (cfg->fmt == ARM_SMMU_CTX_FMT_AARCH64) {
			fmt = ARM_64_LPAE_S2;
		} else {
			fmt = ARM_32_LPAE_S2;
			ias = min(ias, 40UL);
			oas = min(oas, 40UL);
		}
		if (smmu->version == ARM_SMMU_V2)
			smmu_domain->tlb_ops = &arm_smmu_s2_tlb_ops_v2;
		else
			smmu_domain->tlb_ops = &arm_smmu_s2_tlb_ops_v1;
		break;
	default:
		ret = -EINVAL;
		goto out_unlock;
	}
	ret = __arm_smmu_alloc_bitmap(smmu->context_map, start,
				      smmu->num_context_banks);
	if (ret < 0)
		goto out_unlock;

	cfg->cbndx = ret;
	if (smmu->version < ARM_SMMU_V2) {
		cfg->irptndx = atomic_inc_return(&smmu->irptndx);
		cfg->irptndx %= smmu->num_context_irqs;
	} else {
		cfg->irptndx = cfg->cbndx;
	}

	if (smmu_domain->stage == ARM_SMMU_DOMAIN_S2)
		cfg->vmid = cfg->cbndx + 1 + smmu->cavium_id_base;
	else
		cfg->asid = cfg->cbndx + smmu->cavium_id_base;

	pgtbl_cfg = (struct io_pgtable_cfg) {
		.pgsize_bitmap	= smmu->pgsize_bitmap,
		.ias		= ias,
		.oas		= oas,
		.tlb		= smmu_domain->tlb_ops,
		.iommu_dev	= smmu->dev,
	};

	if (smmu->features & ARM_SMMU_FEAT_COHERENT_WALK)
		pgtbl_cfg.quirks = IO_PGTABLE_QUIRK_NO_DMA;

	smmu_domain->smmu = smmu;
	pgtbl_ops = alloc_io_pgtable_ops(fmt, &pgtbl_cfg, smmu_domain);
	if (!pgtbl_ops) {
		ret = -ENOMEM;
		goto out_clear_smmu;
	}

	/* Update the domain's page sizes to reflect the page table format */
	domain->pgsize_bitmap = pgtbl_cfg.pgsize_bitmap;
	domain->geometry.aperture_end = (1UL << ias) - 1;
	domain->geometry.force_aperture = true;

	/* Initialise the context bank with our page table cfg */
	arm_smmu_init_context_bank(smmu_domain, &pgtbl_cfg);
	arm_smmu_write_context_bank(smmu, cfg->cbndx);

	/*
	 * Request context fault interrupt. Do this last to avoid the
	 * handler seeing a half-initialised domain state.
	 */
	irq = smmu->irqs[smmu->num_global_irqs + cfg->irptndx];
	ret = devm_request_irq(smmu->dev, irq, arm_smmu_context_fault,
			       IRQF_SHARED, "arm-smmu-context-fault", domain);
	if (ret < 0) {
		dev_err(smmu->dev, "failed to request context IRQ %d (%u)\n",
			cfg->irptndx, irq);
		cfg->irptndx = INVALID_IRPTNDX;
	}

	mutex_unlock(&smmu_domain->init_mutex);

	/* Publish page table ops for map/unmap */
	smmu_domain->pgtbl_ops = pgtbl_ops;
	return 0;

out_clear_smmu:
	smmu_domain->smmu = NULL;
out_unlock:
	mutex_unlock(&smmu_domain->init_mutex);
	return ret;
}

static void arm_smmu_destroy_domain_context(struct iommu_domain *domain)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_cfg *cfg = &smmu_domain->cfg;
	int irq;

	if (!smmu || domain->type == IOMMU_DOMAIN_IDENTITY)
		return;

	/*
	 * Disable the context bank and free the page tables before freeing
	 * it.
	 */
	smmu->cbs[cfg->cbndx].cfg = NULL;
	arm_smmu_write_context_bank(smmu, cfg->cbndx);

	if (cfg->irptndx != INVALID_IRPTNDX) {
		irq = smmu->irqs[smmu->num_global_irqs + cfg->irptndx];
		devm_free_irq(smmu->dev, irq, domain);
	}

	free_io_pgtable_ops(smmu_domain->pgtbl_ops);
	__arm_smmu_free_bitmap(smmu->context_map, cfg->cbndx);
}

static struct iommu_domain *arm_smmu_domain_alloc(unsigned type)
{
	struct arm_smmu_domain *smmu_domain;

	if (type != IOMMU_DOMAIN_UNMANAGED &&
	    type != IOMMU_DOMAIN_DMA &&
	    type != IOMMU_DOMAIN_IDENTITY)
		return NULL;
	/*
	 * Allocate the domain and initialise some of its data structures.
	 * We can't really do anything meaningful until we've added a
	 * master.
	 */
	smmu_domain = kzalloc(sizeof(*smmu_domain), GFP_KERNEL);
	if (!smmu_domain)
		return NULL;

	if (type == IOMMU_DOMAIN_DMA && (using_legacy_binding ||
	    iommu_get_dma_cookie(&smmu_domain->domain))) {
		kfree(smmu_domain);
		return NULL;
	}

	mutex_init(&smmu_domain->init_mutex);
	spin_lock_init(&smmu_domain->cb_lock);

	return &smmu_domain->domain;
}

static void arm_smmu_domain_free(struct iommu_domain *domain)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	/*
	 * Free the domain resources. We assume that all devices have
	 * already been detached.
	 */
	iommu_put_dma_cookie(domain);
	arm_smmu_destroy_domain_context(domain);
	kfree(smmu_domain);
}

static void arm_smmu_write_smr(struct arm_smmu_device *smmu, int idx)
{
	struct arm_smmu_smr *smr = smmu->smrs + idx;
	u32 reg = smr->id << SMR_ID_SHIFT | smr->mask << SMR_MASK_SHIFT;

	if (!(smmu->features & ARM_SMMU_FEAT_EXIDS) && smr->valid)
		reg |= SMR_VALID;
	writel_relaxed(reg, ARM_SMMU_GR0(smmu) + ARM_SMMU_GR0_SMR(idx));
}

static void arm_smmu_write_s2cr(struct arm_smmu_device *smmu, int idx)
{
	struct arm_smmu_s2cr *s2cr = smmu->s2crs + idx;
	u32 reg = (s2cr->type & S2CR_TYPE_MASK) << S2CR_TYPE_SHIFT |
		  (s2cr->cbndx & S2CR_CBNDX_MASK) << S2CR_CBNDX_SHIFT |
		  (s2cr->privcfg & S2CR_PRIVCFG_MASK) << S2CR_PRIVCFG_SHIFT;

	if (smmu->features & ARM_SMMU_FEAT_EXIDS && smmu->smrs &&
	    smmu->smrs[idx].valid)
		reg |= S2CR_EXIDVALID;
	writel_relaxed(reg, ARM_SMMU_GR0(smmu) + ARM_SMMU_GR0_S2CR(idx));
}

static void arm_smmu_write_sme(struct arm_smmu_device *smmu, int idx)
{
	arm_smmu_write_s2cr(smmu, idx);
	if (smmu->smrs)
		arm_smmu_write_smr(smmu, idx);
}

/*
 * The width of SMR's mask field depends on sCR0_EXIDENABLE, so this function
 * should be called after sCR0 is written.
 */
static void arm_smmu_test_smr_masks(struct arm_smmu_device *smmu)
{
	void __iomem *gr0_base = ARM_SMMU_GR0(smmu);
	u32 smr;

	if (!smmu->smrs)
		return;

	/*
	 * SMR.ID bits may not be preserved if the corresponding MASK
	 * bits are set, so check each one separately. We can reject
	 * masters later if they try to claim IDs outside these masks.
	 */
	smr = smmu->streamid_mask << SMR_ID_SHIFT;
	writel_relaxed(smr, gr0_base + ARM_SMMU_GR0_SMR(0));
	smr = readl_relaxed(gr0_base + ARM_SMMU_GR0_SMR(0));
	smmu->streamid_mask = smr >> SMR_ID_SHIFT;

	smr = smmu->streamid_mask << SMR_MASK_SHIFT;
	writel_relaxed(smr, gr0_base + ARM_SMMU_GR0_SMR(0));
	smr = readl_relaxed(gr0_base + ARM_SMMU_GR0_SMR(0));
	smmu->smr_mask_mask = smr >> SMR_MASK_SHIFT;
}

static int arm_smmu_find_sme(struct arm_smmu_device *smmu, u16 id, u16 mask)
{
	struct arm_smmu_smr *smrs = smmu->smrs;
	int i, free_idx = -ENOSPC;

	/* Stream indexing is blissfully easy */
	if (!smrs)
		return id;

	/* Validating SMRs is... less so */
	for (i = 0; i < smmu->num_mapping_groups; ++i) {
		if (!smrs[i].valid) {
			/*
			 * Note the first free entry we come across, which
			 * we'll claim in the end if nothing else matches.
			 */
			if (free_idx < 0)
				free_idx = i;
			continue;
		}
		/*
		 * If the new entry is _entirely_ matched by an existing entry,
		 * then reuse that, with the guarantee that there also cannot
		 * be any subsequent conflicting entries. In normal use we'd
		 * expect simply identical entries for this case, but there's
		 * no harm in accommodating the generalisation.
		 */
		if ((mask & smrs[i].mask) == mask &&
		    !((id ^ smrs[i].id) & ~smrs[i].mask))
			return i;
		/*
		 * If the new entry has any other overlap with an existing one,
		 * though, then there always exists at least one stream ID
		 * which would cause a conflict, and we can't allow that risk.
		 */
		if (!((id ^ smrs[i].id) & ~(smrs[i].mask | mask)))
			return -EINVAL;
	}

	return free_idx;
}

static bool arm_smmu_free_sme(struct arm_smmu_device *smmu, int idx)
{
	if (--smmu->s2crs[idx].count)
		return false;

	smmu->s2crs[idx] = s2cr_init_val;
	if (smmu->smrs)
		smmu->smrs[idx].valid = false;

	return true;
}

static int arm_smmu_master_alloc_smes(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct arm_smmu_master_cfg *cfg = fwspec->iommu_priv;
	struct arm_smmu_device *smmu = cfg->smmu;
	struct arm_smmu_smr *smrs = smmu->smrs;
	struct iommu_group *group;
	int i, idx, ret;

	mutex_lock(&smmu->stream_map_mutex);
	/* Figure out a viable stream map entry allocation */
	for_each_cfg_sme(fwspec, i, idx) {
		u16 sid = fwspec->ids[i];
		u16 mask = fwspec->ids[i] >> SMR_MASK_SHIFT;

		if (idx != INVALID_SMENDX) {
			ret = -EEXIST;
			goto out_err;
		}

		ret = arm_smmu_find_sme(smmu, sid, mask);
		if (ret < 0)
			goto out_err;

		idx = ret;
		if (smrs && smmu->s2crs[idx].count == 0) {
			smrs[idx].id = sid;
			smrs[idx].mask = mask;
			smrs[idx].valid = true;
		}
		smmu->s2crs[idx].count++;
		cfg->smendx[i] = (s16)idx;
	}

	group = iommu_group_get_for_dev(dev);
	if (!group)
		group = ERR_PTR(-ENOMEM);
	if (IS_ERR(group)) {
		ret = PTR_ERR(group);
		goto out_err;
	}
	iommu_group_put(group);

	/* It worked! Now, poke the actual hardware */
	for_each_cfg_sme(fwspec, i, idx) {
		arm_smmu_write_sme(smmu, idx);
		smmu->s2crs[idx].group = group;
	}

	mutex_unlock(&smmu->stream_map_mutex);
	return 0;

out_err:
	while (i--) {
		arm_smmu_free_sme(smmu, cfg->smendx[i]);
		cfg->smendx[i] = INVALID_SMENDX;
	}
	mutex_unlock(&smmu->stream_map_mutex);
	return ret;
}

static void arm_smmu_master_free_smes(struct iommu_fwspec *fwspec)
{
	struct arm_smmu_device *smmu = fwspec_smmu(fwspec);
	struct arm_smmu_master_cfg *cfg = fwspec->iommu_priv;
	int i, idx;

	mutex_lock(&smmu->stream_map_mutex);
	for_each_cfg_sme(fwspec, i, idx) {
		if (arm_smmu_free_sme(smmu, idx))
			arm_smmu_write_sme(smmu, idx);
		cfg->smendx[i] = INVALID_SMENDX;
	}
	mutex_unlock(&smmu->stream_map_mutex);
}

static int arm_smmu_domain_add_master(struct arm_smmu_domain *smmu_domain,
				      struct iommu_fwspec *fwspec)
{
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_s2cr *s2cr = smmu->s2crs;
	u8 cbndx = smmu_domain->cfg.cbndx;
	enum arm_smmu_s2cr_type type;
	int i, idx;

	if (smmu_domain->stage == ARM_SMMU_DOMAIN_BYPASS)
		type = S2CR_TYPE_BYPASS;
	else
		type = S2CR_TYPE_TRANS;

	for_each_cfg_sme(fwspec, i, idx) {
		if (type == s2cr[idx].type && cbndx == s2cr[idx].cbndx)
			continue;

		s2cr[idx].type = type;
		s2cr[idx].privcfg = S2CR_PRIVCFG_DEFAULT;
		s2cr[idx].cbndx = cbndx;
		arm_smmu_write_s2cr(smmu, idx);
	}
	return 0;
}

static int arm_smmu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	int ret;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct arm_smmu_device *smmu;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	if (!fwspec || fwspec->ops != &arm_smmu_ops) {
		dev_err(dev, "cannot attach to SMMU, is it on the same bus?\n");
		return -ENXIO;
	}

	/*
	 * FIXME: The arch/arm DMA API code tries to attach devices to its own
	 * domains between of_xlate() and add_device() - we have no way to cope
	 * with that, so until ARM gets converted to rely on groups and default
	 * domains, just say no (but more politely than by dereferencing NULL).
	 * This should be at least a WARN_ON once that's sorted.
	 */
	if (!fwspec->iommu_priv)
		return -ENODEV;

	smmu = fwspec_smmu(fwspec);
	/* Ensure that the domain is finalised */
	ret = arm_smmu_init_domain_context(domain, smmu);
	if (ret < 0)
		return ret;

	/*
	 * Sanity check the domain. We don't support domains across
	 * different SMMUs.
	 */
	if (smmu_domain->smmu != smmu) {
		dev_err(dev,
			"cannot attach to SMMU %s whilst already attached to domain on SMMU %s\n",
			dev_name(smmu_domain->smmu->dev), dev_name(smmu->dev));
		return -EINVAL;
	}

	/* Looks ok, so add the device to the domain */
	return arm_smmu_domain_add_master(smmu_domain, fwspec);
}

static int arm_smmu_map(struct iommu_domain *domain, unsigned long iova,
			phys_addr_t paddr, size_t size, int prot)
{
	struct io_pgtable_ops *ops = to_smmu_domain(domain)->pgtbl_ops;

	if (!ops)
		return -ENODEV;

	return ops->map(ops, iova, paddr, size, prot);
}

static size_t arm_smmu_unmap(struct iommu_domain *domain, unsigned long iova,
			     size_t size)
{
	struct io_pgtable_ops *ops = to_smmu_domain(domain)->pgtbl_ops;

	if (!ops)
		return 0;

	return ops->unmap(ops, iova, size);
}

static void arm_smmu_iotlb_sync(struct iommu_domain *domain)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	if (smmu_domain->tlb_ops)
		smmu_domain->tlb_ops->tlb_sync(smmu_domain);
}

static phys_addr_t arm_smmu_iova_to_phys_hard(struct iommu_domain *domain,
					      dma_addr_t iova)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_cfg *cfg = &smmu_domain->cfg;
	struct io_pgtable_ops *ops= smmu_domain->pgtbl_ops;
	struct device *dev = smmu->dev;
	void __iomem *cb_base;
	u32 tmp;
	u64 phys;
	unsigned long va, flags;

	cb_base = ARM_SMMU_CB(smmu, cfg->cbndx);

	spin_lock_irqsave(&smmu_domain->cb_lock, flags);
	/* ATS1 registers can only be written atomically */
	va = iova & ~0xfffUL;
	if (smmu->version == ARM_SMMU_V2)
		smmu_write_atomic_lq(va, cb_base + ARM_SMMU_CB_ATS1PR);
	else /* Register is only 32-bit in v1 */
		writel_relaxed(va, cb_base + ARM_SMMU_CB_ATS1PR);

	if (readl_poll_timeout_atomic(cb_base + ARM_SMMU_CB_ATSR, tmp,
				      !(tmp & ATSR_ACTIVE), 5, 50)) {
		spin_unlock_irqrestore(&smmu_domain->cb_lock, flags);
		dev_err(dev,
			"iova to phys timed out on %pad. Falling back to software table walk.\n",
			&iova);
		return ops->iova_to_phys(ops, iova);
	}

	phys = readq_relaxed(cb_base + ARM_SMMU_CB_PAR);
	spin_unlock_irqrestore(&smmu_domain->cb_lock, flags);
	if (phys & CB_PAR_F) {
		dev_err(dev, "translation fault!\n");
		dev_err(dev, "PAR = 0x%llx\n", phys);
		return 0;
	}

	return (phys & GENMASK_ULL(39, 12)) | (iova & 0xfff);
}

static phys_addr_t arm_smmu_iova_to_phys(struct iommu_domain *domain,
					dma_addr_t iova)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct io_pgtable_ops *ops = smmu_domain->pgtbl_ops;

	if (domain->type == IOMMU_DOMAIN_IDENTITY)
		return iova;

	if (!ops)
		return 0;

	if (smmu_domain->smmu->features & ARM_SMMU_FEAT_TRANS_OPS &&
			smmu_domain->stage == ARM_SMMU_DOMAIN_S1)
		return arm_smmu_iova_to_phys_hard(domain, iova);

	return ops->iova_to_phys(ops, iova);
}

static bool arm_smmu_capable(enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
		/*
		 * Return true here as the SMMU can always send out coherent
		 * requests.
		 */
		return true;
	case IOMMU_CAP_NOEXEC:
		return true;
	default:
		return false;
	}
}

static int arm_smmu_match_node(struct device *dev, void *data)
{
	return dev->fwnode == data;
}

static
struct arm_smmu_device *arm_smmu_get_by_fwnode(struct fwnode_handle *fwnode)
{
	struct device *dev = driver_find_device(&arm_smmu_driver.driver, NULL,
						fwnode, arm_smmu_match_node);
	put_device(dev);
	return dev ? dev_get_drvdata(dev) : NULL;
}

static int arm_smmu_add_device(struct device *dev)
{
	struct arm_smmu_device *smmu;
	struct arm_smmu_master_cfg *cfg;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	int i, ret;

	if (using_legacy_binding) {
		ret = arm_smmu_register_legacy_master(dev, &smmu);

		/*
		 * If dev->iommu_fwspec is initally NULL, arm_smmu_register_legacy_master()
		 * will allocate/initialise a new one. Thus we need to update fwspec for
		 * later use.
		 */
		fwspec = dev->iommu_fwspec;
		if (ret)
			goto out_free;
	} else if (fwspec && fwspec->ops == &arm_smmu_ops) {
		smmu = arm_smmu_get_by_fwnode(fwspec->iommu_fwnode);
	} else {
		return -ENODEV;
	}

	ret = -EINVAL;
	for (i = 0; i < fwspec->num_ids; i++) {
		u16 sid = fwspec->ids[i];
		u16 mask = fwspec->ids[i] >> SMR_MASK_SHIFT;

		if (sid & ~smmu->streamid_mask) {
			dev_err(dev, "stream ID 0x%x out of range for SMMU (0x%x)\n",
				sid, smmu->streamid_mask);
			goto out_free;
		}
		if (mask & ~smmu->smr_mask_mask) {
			dev_err(dev, "SMR mask 0x%x out of range for SMMU (0x%x)\n",
				mask, smmu->smr_mask_mask);
			goto out_free;
		}
	}

	ret = -ENOMEM;
	cfg = kzalloc(offsetof(struct arm_smmu_master_cfg, smendx[i]),
		      GFP_KERNEL);
	if (!cfg)
		goto out_free;

	cfg->smmu = smmu;
	fwspec->iommu_priv = cfg;
	while (i--)
		cfg->smendx[i] = INVALID_SMENDX;

	ret = arm_smmu_master_alloc_smes(dev);
	if (ret)
		goto out_cfg_free;

	iommu_device_link(&smmu->iommu, dev);

	return 0;

out_cfg_free:
	kfree(cfg);
out_free:
	iommu_fwspec_free(dev);
	return ret;
}

static void arm_smmu_remove_device(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct arm_smmu_master_cfg *cfg;
	struct arm_smmu_device *smmu;


	if (!fwspec || fwspec->ops != &arm_smmu_ops)
		return;

	cfg  = fwspec->iommu_priv;
	smmu = cfg->smmu;

	iommu_device_unlink(&smmu->iommu, dev);
	arm_smmu_master_free_smes(fwspec);
	iommu_group_remove_device(dev);
	kfree(fwspec->iommu_priv);
	iommu_fwspec_free(dev);
}

static struct iommu_group *arm_smmu_device_group(struct device *dev)
{
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct arm_smmu_device *smmu = fwspec_smmu(fwspec);
	struct iommu_group *group = NULL;
	int i, idx;

	for_each_cfg_sme(fwspec, i, idx) {
		if (group && smmu->s2crs[idx].group &&
		    group != smmu->s2crs[idx].group)
			return ERR_PTR(-EINVAL);

		group = smmu->s2crs[idx].group;
	}

	if (group)
		return iommu_group_ref_get(group);

	if (dev_is_pci(dev))
		group = pci_device_group(dev);
	else
		group = generic_device_group(dev);

	return group;
}

static int arm_smmu_domain_get_attr(struct iommu_domain *domain,
				    enum iommu_attr attr, void *data)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	if (domain->type != IOMMU_DOMAIN_UNMANAGED)
		return -EINVAL;

	switch (attr) {
	case DOMAIN_ATTR_NESTING:
		*(int *)data = (smmu_domain->stage == ARM_SMMU_DOMAIN_NESTED);
		return 0;
	default:
		return -ENODEV;
	}
}

static int arm_smmu_domain_set_attr(struct iommu_domain *domain,
				    enum iommu_attr attr, void *data)
{
	int ret = 0;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	if (domain->type != IOMMU_DOMAIN_UNMANAGED)
		return -EINVAL;

	mutex_lock(&smmu_domain->init_mutex);

	switch (attr) {
	case DOMAIN_ATTR_NESTING:
		if (smmu_domain->smmu) {
			ret = -EPERM;
			goto out_unlock;
		}

		if (*(int *)data)
			smmu_domain->stage = ARM_SMMU_DOMAIN_NESTED;
		else
			smmu_domain->stage = ARM_SMMU_DOMAIN_S1;

		break;
	default:
		ret = -ENODEV;
	}

out_unlock:
	mutex_unlock(&smmu_domain->init_mutex);
	return ret;
}

static int arm_smmu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	u32 mask, fwid = 0;

	if (args->args_count > 0)
		fwid |= (u16)args->args[0];

	if (args->args_count > 1)
		fwid |= (u16)args->args[1] << SMR_MASK_SHIFT;
	else if (!of_property_read_u32(args->np, "stream-match-mask", &mask))
		fwid |= (u16)mask << SMR_MASK_SHIFT;

	return iommu_fwspec_add_ids(dev, &fwid, 1);
}

static void arm_smmu_get_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *region;
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;

	region = iommu_alloc_resv_region(MSI_IOVA_BASE, MSI_IOVA_LENGTH,
					 prot, IOMMU_RESV_SW_MSI);
	if (!region)
		return;

	list_add_tail(&region->list, head);

	iommu_dma_get_resv_regions(dev, head);
}

static void arm_smmu_put_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *entry, *next;

	list_for_each_entry_safe(entry, next, head, list)
		kfree(entry);
}

static struct iommu_ops arm_smmu_ops = {
	.capable		= arm_smmu_capable,
	.domain_alloc		= arm_smmu_domain_alloc,
	.domain_free		= arm_smmu_domain_free,
	.attach_dev		= arm_smmu_attach_dev,
	.map			= arm_smmu_map,
	.unmap			= arm_smmu_unmap,
	.flush_iotlb_all	= arm_smmu_iotlb_sync,
	.iotlb_sync		= arm_smmu_iotlb_sync,
	.iova_to_phys		= arm_smmu_iova_to_phys,
	.add_device		= arm_smmu_add_device,
	.remove_device		= arm_smmu_remove_device,
	.device_group		= arm_smmu_device_group,
	.domain_get_attr	= arm_smmu_domain_get_attr,
	.domain_set_attr	= arm_smmu_domain_set_attr,
	.of_xlate		= arm_smmu_of_xlate,
	.get_resv_regions	= arm_smmu_get_resv_regions,
	.put_resv_regions	= arm_smmu_put_resv_regions,
	.pgsize_bitmap		= -1UL, /* Restricted during device attach */
};

static void arm_smmu_device_reset(struct arm_smmu_device *smmu)
{
	void __iomem *gr0_base = ARM_SMMU_GR0(smmu);
	int i;
	u32 reg, major;

	/* clear global FSR */
	reg = readl_relaxed(ARM_SMMU_GR0_NS(smmu) + ARM_SMMU_GR0_sGFSR);
	writel(reg, ARM_SMMU_GR0_NS(smmu) + ARM_SMMU_GR0_sGFSR);

	/*
	 * Reset stream mapping groups: Initial values mark all SMRn as
	 * invalid and all S2CRn as bypass unless overridden.
	 */
	for (i = 0; i < smmu->num_mapping_groups; ++i)
		arm_smmu_write_sme(smmu, i);

	if (smmu->model == ARM_MMU500) {
		/*
		 * Before clearing ARM_MMU500_ACTLR_CPRE, need to
		 * clear CACHE_LOCK bit of ACR first. And, CACHE_LOCK
		 * bit is only present in MMU-500r2 onwards.
		 */
		reg = readl_relaxed(gr0_base + ARM_SMMU_GR0_ID7);
		major = (reg >> ID7_MAJOR_SHIFT) & ID7_MAJOR_MASK;
		reg = readl_relaxed(gr0_base + ARM_SMMU_GR0_sACR);
		if (major >= 2)
			reg &= ~ARM_MMU500_ACR_CACHE_LOCK;
		/*
		 * Allow unmatched Stream IDs to allocate bypass
		 * TLB entries for reduced latency.
		 */
		reg |= ARM_MMU500_ACR_SMTNMB_TLBEN | ARM_MMU500_ACR_S2CRB_TLBEN;
		writel_relaxed(reg, gr0_base + ARM_SMMU_GR0_sACR);
	}

	/* Make sure all context banks are disabled and clear CB_FSR  */
	for (i = 0; i < smmu->num_context_banks; ++i) {
		void __iomem *cb_base = ARM_SMMU_CB(smmu, i);

		arm_smmu_write_context_bank(smmu, i);
		writel_relaxed(FSR_FAULT, cb_base + ARM_SMMU_CB_FSR);
		/*
		 * Disable MMU-500's not-particularly-beneficial next-page
		 * prefetcher for the sake of errata #841119 and #826419.
		 */
		if (smmu->model == ARM_MMU500) {
			reg = readl_relaxed(cb_base + ARM_SMMU_CB_ACTLR);
			reg &= ~ARM_MMU500_ACTLR_CPRE;
			writel_relaxed(reg, cb_base + ARM_SMMU_CB_ACTLR);
		}
	}

	/* Invalidate the TLB, just in case */
	writel_relaxed(QCOM_DUMMY_VAL, gr0_base + ARM_SMMU_GR0_TLBIALLH);
	writel_relaxed(QCOM_DUMMY_VAL, gr0_base + ARM_SMMU_GR0_TLBIALLNSNH);

	reg = readl_relaxed(ARM_SMMU_GR0_NS(smmu) + ARM_SMMU_GR0_sCR0);

	/* Enable fault reporting */
	reg |= (sCR0_GFRE | sCR0_GFIE | sCR0_GCFGFRE | sCR0_GCFGFIE);

	/* Disable TLB broadcasting. */
	reg |= (sCR0_VMIDPNE | sCR0_PTM);

	/* Enable client access, handling unmatched streams as appropriate */
	reg &= ~sCR0_CLIENTPD;
	if (disable_bypass)
		reg |= sCR0_USFCFG;
	else
		reg &= ~sCR0_USFCFG;

	/* Disable forced broadcasting */
	reg &= ~sCR0_FB;

	/* Don't upgrade barriers */
	reg &= ~(sCR0_BSU_MASK << sCR0_BSU_SHIFT);

	if (smmu->features & ARM_SMMU_FEAT_VMID16)
		reg |= sCR0_VMID16EN;

	if (smmu->features & ARM_SMMU_FEAT_EXIDS)
		reg |= sCR0_EXIDENABLE;

	/* Push the button */
	arm_smmu_tlb_sync_global(smmu);
	writel(reg, ARM_SMMU_GR0_NS(smmu) + ARM_SMMU_GR0_sCR0);
}

static int arm_smmu_id_size_to_bits(int size)
{
	switch (size) {
	case 0:
		return 32;
	case 1:
		return 36;
	case 2:
		return 40;
	case 3:
		return 42;
	case 4:
		return 44;
	case 5:
	default:
		return 48;
	}
}

static int arm_smmu_device_cfg_probe(struct arm_smmu_device *smmu)
{
	unsigned long size;
	void __iomem *gr0_base = ARM_SMMU_GR0(smmu);
	u32 id;
	bool cttw_reg, cttw_fw = smmu->features & ARM_SMMU_FEAT_COHERENT_WALK;
	int i;

	dev_notice(smmu->dev, "probing hardware configuration...\n");
	dev_notice(smmu->dev, "SMMUv%d with:\n",
			smmu->version == ARM_SMMU_V2 ? 2 : 1);

	/* ID0 */
	id = readl_relaxed(gr0_base + ARM_SMMU_GR0_ID0);

	/* Restrict available stages based on module parameter */
	if (force_stage == 1)
		id &= ~(ID0_S2TS | ID0_NTS);
	else if (force_stage == 2)
		id &= ~(ID0_S1TS | ID0_NTS);

	if (id & ID0_S1TS) {
		smmu->features |= ARM_SMMU_FEAT_TRANS_S1;
		dev_notice(smmu->dev, "\tstage 1 translation\n");
	}

	if (id & ID0_S2TS) {
		smmu->features |= ARM_SMMU_FEAT_TRANS_S2;
		dev_notice(smmu->dev, "\tstage 2 translation\n");
	}

	if (id & ID0_NTS) {
		smmu->features |= ARM_SMMU_FEAT_TRANS_NESTED;
		dev_notice(smmu->dev, "\tnested translation\n");
	}

	if (!(smmu->features &
		(ARM_SMMU_FEAT_TRANS_S1 | ARM_SMMU_FEAT_TRANS_S2))) {
		dev_err(smmu->dev, "\tno translation support!\n");
		return -ENODEV;
	}

	if ((id & ID0_S1TS) &&
		((smmu->version < ARM_SMMU_V2) || !(id & ID0_ATOSNS))) {
		smmu->features |= ARM_SMMU_FEAT_TRANS_OPS;
		dev_notice(smmu->dev, "\taddress translation ops\n");
	}

	/*
	 * In order for DMA API calls to work properly, we must defer to what
	 * the FW says about coherency, regardless of what the hardware claims.
	 * Fortunately, this also opens up a workaround for systems where the
	 * ID register value has ended up configured incorrectly.
	 */
	cttw_reg = !!(id & ID0_CTTW);
	if (cttw_fw || cttw_reg)
		dev_notice(smmu->dev, "\t%scoherent table walk\n",
			   cttw_fw ? "" : "non-");
	if (cttw_fw != cttw_reg)
		dev_notice(smmu->dev,
			   "\t(IDR0.CTTW overridden by FW configuration)\n");

	/* Max. number of entries we have for stream matching/indexing */
	if (smmu->version == ARM_SMMU_V2 && id & ID0_EXIDS) {
		smmu->features |= ARM_SMMU_FEAT_EXIDS;
		size = 1 << 16;
	} else {
		size = 1 << ((id >> ID0_NUMSIDB_SHIFT) & ID0_NUMSIDB_MASK);
	}
	smmu->streamid_mask = size - 1;
	if (id & ID0_SMS) {
		smmu->features |= ARM_SMMU_FEAT_STREAM_MATCH;
		size = (id >> ID0_NUMSMRG_SHIFT) & ID0_NUMSMRG_MASK;
		if (size == 0) {
			dev_err(smmu->dev,
				"stream-matching supported, but no SMRs present!\n");
			return -ENODEV;
		}

		/* Zero-initialised to mark as invalid */
		smmu->smrs = devm_kcalloc(smmu->dev, size, sizeof(*smmu->smrs),
					  GFP_KERNEL);
		if (!smmu->smrs)
			return -ENOMEM;

		dev_notice(smmu->dev,
			   "\tstream matching with %lu register groups", size);
	}
	/* s2cr->type == 0 means translation, so initialise explicitly */
	smmu->s2crs = devm_kmalloc_array(smmu->dev, size, sizeof(*smmu->s2crs),
					 GFP_KERNEL);
	if (!smmu->s2crs)
		return -ENOMEM;
	for (i = 0; i < size; i++)
		smmu->s2crs[i] = s2cr_init_val;

	smmu->num_mapping_groups = size;
	mutex_init(&smmu->stream_map_mutex);
	spin_lock_init(&smmu->global_sync_lock);

	if (smmu->version < ARM_SMMU_V2 || !(id & ID0_PTFS_NO_AARCH32)) {
		smmu->features |= ARM_SMMU_FEAT_FMT_AARCH32_L;
		if (!(id & ID0_PTFS_NO_AARCH32S))
			smmu->features |= ARM_SMMU_FEAT_FMT_AARCH32_S;
	}

	/* ID1 */
	id = readl_relaxed(gr0_base + ARM_SMMU_GR0_ID1);
	smmu->pgshift = (id & ID1_PAGESIZE) ? 16 : 12;

	/* Check for size mismatch of SMMU address space from mapped region */
	size = 1 << (((id >> ID1_NUMPAGENDXB_SHIFT) & ID1_NUMPAGENDXB_MASK) + 1);
	size <<= smmu->pgshift;
	if (smmu->cb_base != gr0_base + size)
		dev_warn(smmu->dev,
			"SMMU address space size (0x%lx) differs from mapped region size (0x%tx)!\n",
			size * 2, (smmu->cb_base - gr0_base) * 2);

	smmu->num_s2_context_banks = (id >> ID1_NUMS2CB_SHIFT) & ID1_NUMS2CB_MASK;
	smmu->num_context_banks = (id >> ID1_NUMCB_SHIFT) & ID1_NUMCB_MASK;
	if (smmu->num_s2_context_banks > smmu->num_context_banks) {
		dev_err(smmu->dev, "impossible number of S2 context banks!\n");
		return -ENODEV;
	}
	dev_notice(smmu->dev, "\t%u context banks (%u stage-2 only)\n",
		   smmu->num_context_banks, smmu->num_s2_context_banks);
	/*
	 * Cavium CN88xx erratum #27704.
	 * Ensure ASID and VMID allocation is unique across all SMMUs in
	 * the system.
	 */
	if (smmu->model == CAVIUM_SMMUV2) {
		smmu->cavium_id_base =
			atomic_add_return(smmu->num_context_banks,
					  &cavium_smmu_context_count);
		smmu->cavium_id_base -= smmu->num_context_banks;
		dev_notice(smmu->dev, "\tenabling workaround for Cavium erratum 27704\n");
	}
	smmu->cbs = devm_kcalloc(smmu->dev, smmu->num_context_banks,
				 sizeof(*smmu->cbs), GFP_KERNEL);
	if (!smmu->cbs)
		return -ENOMEM;

	/* ID2 */
	id = readl_relaxed(gr0_base + ARM_SMMU_GR0_ID2);
	size = arm_smmu_id_size_to_bits((id >> ID2_IAS_SHIFT) & ID2_IAS_MASK);
	smmu->ipa_size = size;

	/* The output mask is also applied for bypass */
	size = arm_smmu_id_size_to_bits((id >> ID2_OAS_SHIFT) & ID2_OAS_MASK);
	smmu->pa_size = size;

	if (id & ID2_VMID16)
		smmu->features |= ARM_SMMU_FEAT_VMID16;

	/*
	 * What the page table walker can address actually depends on which
	 * descriptor format is in use, but since a) we don't know that yet,
	 * and b) it can vary per context bank, this will have to do...
	 */
	if (dma_set_mask_and_coherent(smmu->dev, DMA_BIT_MASK(size)))
		dev_warn(smmu->dev,
			 "failed to set DMA mask for table walker\n");

	if (smmu->version < ARM_SMMU_V2) {
		smmu->va_size = smmu->ipa_size;
		if (smmu->version == ARM_SMMU_V1_64K)
			smmu->features |= ARM_SMMU_FEAT_FMT_AARCH64_64K;
	} else {
		size = (id >> ID2_UBS_SHIFT) & ID2_UBS_MASK;
		smmu->va_size = arm_smmu_id_size_to_bits(size);
		if (id & ID2_PTFS_4K)
			smmu->features |= ARM_SMMU_FEAT_FMT_AARCH64_4K;
		if (id & ID2_PTFS_16K)
			smmu->features |= ARM_SMMU_FEAT_FMT_AARCH64_16K;
		if (id & ID2_PTFS_64K)
			smmu->features |= ARM_SMMU_FEAT_FMT_AARCH64_64K;
	}

	/* Now we've corralled the various formats, what'll it do? */
	if (smmu->features & ARM_SMMU_FEAT_FMT_AARCH32_S)
		smmu->pgsize_bitmap |= SZ_4K | SZ_64K | SZ_1M | SZ_16M;
	if (smmu->features &
	    (ARM_SMMU_FEAT_FMT_AARCH32_L | ARM_SMMU_FEAT_FMT_AARCH64_4K))
		smmu->pgsize_bitmap |= SZ_4K | SZ_2M | SZ_1G;
	if (smmu->features & ARM_SMMU_FEAT_FMT_AARCH64_16K)
		smmu->pgsize_bitmap |= SZ_16K | SZ_32M;
	if (smmu->features & ARM_SMMU_FEAT_FMT_AARCH64_64K)
		smmu->pgsize_bitmap |= SZ_64K | SZ_512M;

	if (arm_smmu_ops.pgsize_bitmap == -1UL)
		arm_smmu_ops.pgsize_bitmap = smmu->pgsize_bitmap;
	else
		arm_smmu_ops.pgsize_bitmap |= smmu->pgsize_bitmap;
	dev_notice(smmu->dev, "\tSupported page sizes: 0x%08lx\n",
		   smmu->pgsize_bitmap);


	if (smmu->features & ARM_SMMU_FEAT_TRANS_S1)
		dev_notice(smmu->dev, "\tStage-1: %lu-bit VA -> %lu-bit IPA\n",
			   smmu->va_size, smmu->ipa_size);

	if (smmu->features & ARM_SMMU_FEAT_TRANS_S2)
		dev_notice(smmu->dev, "\tStage-2: %lu-bit IPA -> %lu-bit PA\n",
			   smmu->ipa_size, smmu->pa_size);

	return 0;
}

struct arm_smmu_match_data {
	enum arm_smmu_arch_version version;
	enum arm_smmu_implementation model;
};

#define ARM_SMMU_MATCH_DATA(name, ver, imp)	\
static struct arm_smmu_match_data name = { .version = ver, .model = imp }

ARM_SMMU_MATCH_DATA(smmu_generic_v1, ARM_SMMU_V1, GENERIC_SMMU);
ARM_SMMU_MATCH_DATA(smmu_generic_v2, ARM_SMMU_V2, GENERIC_SMMU);
ARM_SMMU_MATCH_DATA(arm_mmu401, ARM_SMMU_V1_64K, GENERIC_SMMU);
ARM_SMMU_MATCH_DATA(arm_mmu500, ARM_SMMU_V2, ARM_MMU500);
ARM_SMMU_MATCH_DATA(cavium_smmuv2, ARM_SMMU_V2, CAVIUM_SMMUV2);
ARM_SMMU_MATCH_DATA(qcom_smmuv2, ARM_SMMU_V2, QCOM_SMMUV2);

static const struct of_device_id arm_smmu_of_match[] = {
	{ .compatible = "arm,smmu-v1", .data = &smmu_generic_v1 },
	{ .compatible = "arm,smmu-v2", .data = &smmu_generic_v2 },
	{ .compatible = "arm,mmu-400", .data = &smmu_generic_v1 },
	{ .compatible = "arm,mmu-401", .data = &arm_mmu401 },
	{ .compatible = "arm,mmu-500", .data = &arm_mmu500 },
	{ .compatible = "cavium,smmu-v2", .data = &cavium_smmuv2 },
	{ .compatible = "qcom,smmu-v2", .data = &qcom_smmuv2 },
	{ },
};
MODULE_DEVICE_TABLE(of, arm_smmu_of_match);

#ifdef CONFIG_ACPI
static int acpi_smmu_get_data(u32 model, struct arm_smmu_device *smmu)
{
	int ret = 0;

	switch (model) {
	case ACPI_IORT_SMMU_V1:
	case ACPI_IORT_SMMU_CORELINK_MMU400:
		smmu->version = ARM_SMMU_V1;
		smmu->model = GENERIC_SMMU;
		break;
	case ACPI_IORT_SMMU_CORELINK_MMU401:
		smmu->version = ARM_SMMU_V1_64K;
		smmu->model = GENERIC_SMMU;
		break;
	case ACPI_IORT_SMMU_V2:
		smmu->version = ARM_SMMU_V2;
		smmu->model = GENERIC_SMMU;
		break;
	case ACPI_IORT_SMMU_CORELINK_MMU500:
		smmu->version = ARM_SMMU_V2;
		smmu->model = ARM_MMU500;
		break;
	case ACPI_IORT_SMMU_CAVIUM_THUNDERX:
		smmu->version = ARM_SMMU_V2;
		smmu->model = CAVIUM_SMMUV2;
		break;
	default:
		ret = -ENODEV;
	}

	return ret;
}

static int arm_smmu_device_acpi_probe(struct platform_device *pdev,
				      struct arm_smmu_device *smmu)
{
	struct device *dev = smmu->dev;
	struct acpi_iort_node *node =
		*(struct acpi_iort_node **)dev_get_platdata(dev);
	struct acpi_iort_smmu *iort_smmu;
	int ret;

	/* Retrieve SMMU1/2 specific data */
	iort_smmu = (struct acpi_iort_smmu *)node->node_data;

	ret = acpi_smmu_get_data(iort_smmu->model, smmu);
	if (ret < 0)
		return ret;

	/* Ignore the configuration access interrupt */
	smmu->num_global_irqs = 1;

	if (iort_smmu->flags & ACPI_IORT_SMMU_COHERENT_WALK)
		smmu->features |= ARM_SMMU_FEAT_COHERENT_WALK;

	return 0;
}
#else
static inline int arm_smmu_device_acpi_probe(struct platform_device *pdev,
					     struct arm_smmu_device *smmu)
{
	return -ENODEV;
}
#endif

static int arm_smmu_device_dt_probe(struct platform_device *pdev,
				    struct arm_smmu_device *smmu)
{
	const struct arm_smmu_match_data *data;
	struct device *dev = &pdev->dev;
	bool legacy_binding;

	if (of_property_read_u32(dev->of_node, "#global-interrupts",
				 &smmu->num_global_irqs)) {
		dev_err(dev, "missing #global-interrupts property\n");
		return -ENODEV;
	}

	data = of_device_get_match_data(dev);
	smmu->version = data->version;
	smmu->model = data->model;

	parse_driver_options(smmu);

	legacy_binding = of_find_property(dev->of_node, "mmu-masters", NULL);
	if (legacy_binding && !using_generic_binding) {
		if (!using_legacy_binding)
			pr_notice("deprecated \"mmu-masters\" DT property in use; DMA API support unavailable\n");
		using_legacy_binding = true;
	} else if (!legacy_binding && !using_legacy_binding) {
		using_generic_binding = true;
	} else {
		dev_err(dev, "not probing due to mismatched DT properties\n");
		return -ENODEV;
	}

	if (of_dma_is_coherent(dev->of_node))
		smmu->features |= ARM_SMMU_FEAT_COHERENT_WALK;

	return 0;
}

static void arm_smmu_bus_init(void)
{
	/* Oh, for a proper bus abstraction */
	if (!iommu_present(&platform_bus_type))
		bus_set_iommu(&platform_bus_type, &arm_smmu_ops);
#ifdef CONFIG_ARM_AMBA
	if (!iommu_present(&amba_bustype))
		bus_set_iommu(&amba_bustype, &arm_smmu_ops);
#endif
#ifdef CONFIG_PCI
	if (!iommu_present(&pci_bus_type)) {
		pci_request_acs();
		bus_set_iommu(&pci_bus_type, &arm_smmu_ops);
	}
#endif
}

static int arm_smmu_device_probe(struct platform_device *pdev)
{
	struct resource *res;
	resource_size_t ioaddr;
	struct arm_smmu_device *smmu;
	struct device *dev = &pdev->dev;
	int num_irqs, i, err;

	smmu = devm_kzalloc(dev, sizeof(*smmu), GFP_KERNEL);
	if (!smmu) {
		dev_err(dev, "failed to allocate arm_smmu_device\n");
		return -ENOMEM;
	}
	smmu->dev = dev;

	if (dev->of_node)
		err = arm_smmu_device_dt_probe(pdev, smmu);
	else
		err = arm_smmu_device_acpi_probe(pdev, smmu);

	if (err)
		return err;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ioaddr = res->start;
	smmu->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(smmu->base))
		return PTR_ERR(smmu->base);
	smmu->cb_base = smmu->base + resource_size(res) / 2;

	num_irqs = 0;
	while ((res = platform_get_resource(pdev, IORESOURCE_IRQ, num_irqs))) {
		num_irqs++;
		if (num_irqs > smmu->num_global_irqs)
			smmu->num_context_irqs++;
	}

	if (!smmu->num_context_irqs) {
		dev_err(dev, "found %d interrupts but expected at least %d\n",
			num_irqs, smmu->num_global_irqs + 1);
		return -ENODEV;
	}

	smmu->irqs = devm_kcalloc(dev, num_irqs, sizeof(*smmu->irqs),
				  GFP_KERNEL);
	if (!smmu->irqs) {
		dev_err(dev, "failed to allocate %d irqs\n", num_irqs);
		return -ENOMEM;
	}

	for (i = 0; i < num_irqs; ++i) {
		int irq = platform_get_irq(pdev, i);

		if (irq < 0) {
			dev_err(dev, "failed to get irq index %d\n", i);
			return -ENODEV;
		}
		smmu->irqs[i] = irq;
	}

	err = arm_smmu_device_cfg_probe(smmu);
	if (err)
		return err;

	if (smmu->version == ARM_SMMU_V2) {
		if (smmu->num_context_banks > smmu->num_context_irqs) {
			dev_err(dev,
			      "found only %d context irq(s) but %d required\n",
			      smmu->num_context_irqs, smmu->num_context_banks);
			return -ENODEV;
		}

		/* Ignore superfluous interrupts */
		smmu->num_context_irqs = smmu->num_context_banks;
	}

	for (i = 0; i < smmu->num_global_irqs; ++i) {
		err = devm_request_irq(smmu->dev, smmu->irqs[i],
				       arm_smmu_global_fault,
				       IRQF_SHARED,
				       "arm-smmu global fault",
				       smmu);
		if (err) {
			dev_err(dev, "failed to request global IRQ %d (%u)\n",
				i, smmu->irqs[i]);
			return err;
		}
	}

	err = iommu_device_sysfs_add(&smmu->iommu, smmu->dev, NULL,
				     "smmu.%pa", &ioaddr);
	if (err) {
		dev_err(dev, "Failed to register iommu in sysfs\n");
		return err;
	}

	iommu_device_set_ops(&smmu->iommu, &arm_smmu_ops);
	iommu_device_set_fwnode(&smmu->iommu, dev->fwnode);

	err = iommu_device_register(&smmu->iommu);
	if (err) {
		dev_err(dev, "Failed to register iommu\n");
		return err;
	}

	platform_set_drvdata(pdev, smmu);
	arm_smmu_device_reset(smmu);
	arm_smmu_test_smr_masks(smmu);

	/*
	 * For ACPI and generic DT bindings, an SMMU will be probed before
	 * any device which might need it, so we want the bus ops in place
	 * ready to handle default domain setup as soon as any SMMU exists.
	 */
	if (!using_legacy_binding)
		arm_smmu_bus_init();

	return 0;
}

/*
 * With the legacy DT binding in play, though, we have no guarantees about
 * probe order, but then we're also not doing default domains, so we can
 * delay setting bus ops until we're sure every possible SMMU is ready,
 * and that way ensure that no add_device() calls get missed.
 */
static int arm_smmu_legacy_bus_init(void)
{
	if (using_legacy_binding)
		arm_smmu_bus_init();
	return 0;
}
#ifndef MODULE
device_initcall_sync(arm_smmu_legacy_bus_init);
#endif

static int arm_smmu_device_remove(struct platform_device *pdev)
{
	struct arm_smmu_device *smmu = platform_get_drvdata(pdev);

	if (!smmu)
		return -ENODEV;

	if (!bitmap_empty(smmu->context_map, ARM_SMMU_MAX_CBS))
		dev_err(&pdev->dev, "removing device with active domains!\n");

	/* Turn the thing off */
	writel(sCR0_CLIENTPD, ARM_SMMU_GR0_NS(smmu) + ARM_SMMU_GR0_sCR0);
	return 0;
}

static void arm_smmu_device_shutdown(struct platform_device *pdev)
{
	arm_smmu_device_remove(pdev);
}

static int __maybe_unused arm_smmu_pm_resume(struct device *dev)
{
	struct arm_smmu_device *smmu = dev_get_drvdata(dev);

	arm_smmu_device_reset(smmu);
	return 0;
}

static SIMPLE_DEV_PM_OPS(arm_smmu_pm_ops, NULL, arm_smmu_pm_resume);

static struct platform_driver arm_smmu_driver = {
	.driver	= {
		.name		= "arm-smmu",
		.of_match_table	= of_match_ptr(arm_smmu_of_match),
		.pm		= &arm_smmu_pm_ops,
	},
	.probe	= arm_smmu_device_probe,
	.remove	= arm_smmu_device_remove,
	.shutdown = arm_smmu_device_shutdown,
};

static int __init arm_smmu_driver_init(void)
{
	int ret;

	ret = platform_driver_register(&arm_smmu_driver);
#ifdef MODULE
	if (!ret)
		arm_smmu_legacy_bus_init();
#endif
	return ret;
}

static void __exit arm_smmu_driver_exit(void)
{
	platform_driver_unregister(&arm_smmu_driver);
}

subsys_initcall(arm_smmu_init);
module_exit(arm_smmu_exit);

#define TCU_HW_VERSION_HLOS1		(0x18)

#define DEBUG_SID_HALT_REG		0x0
#define DEBUG_SID_HALT_VAL		(0x1 << 16)
#define DEBUG_SID_HALT_SID_MASK		0x3ff

#define DEBUG_VA_ADDR_REG		0x8

#define DEBUG_TXN_TRIGG_REG		0x18
#define DEBUG_TXN_AXPROT_SHIFT		6
#define DEBUG_TXN_AXPROT_PRIV	(0x1 << DEBUG_TXN_AXPROT_SHIFT)
#define DEBUG_TXN_AXPROT_UNPRIV	(0x0 << DEBUG_TXN_AXPROT_SHIFT)
#define DEBUG_TXN_AXPROT_NSEC	(0x2 << DEBUG_TXN_AXPROT_SHIFT)
#define DEBUG_TXN_AXPROT_SEC	(0x0 << DEBUG_TXN_AXPROT_SHIFT)
#define DEBUG_TXN_AXPROT_INST	(0x4 << DEBUG_TXN_AXPROT_SHIFT)
#define DEBUG_TXN_AXPROT_DATA	(0x0 << DEBUG_TXN_AXPROT_SHIFT)
#define DEBUG_TXN_AXCACHE_SHIFT		2
#define DEBUG_TXN_WRITE			(0x1 << 1)
#define DEBUG_TXN_READ			(0x0 << 1)
#define DEBUG_TXN_TRIGGER		0x1

#define DEBUG_SR_HALT_ACK_REG		0x20
#define DEBUG_SR_HALT_ACK_VAL		(0x1 << 1)
#define DEBUG_SR_ECATS_RUNNING_VAL	(0x1 << 0)

#define DEBUG_PAR_REG			0x28
#define DEBUG_PAR_PA_MASK		((0x1ULL << 36) - 1)
#define DEBUG_PAR_PA_SHIFT		12
#define DEBUG_PAR_FAULT_VAL		0x1

#define DEBUG_AXUSER_REG		0x30
#define DEBUG_AXUSER_CDMID_MASK         0xff
#define DEBUG_AXUSER_CDMID_SHIFT        36
#define DEBUG_AXUSER_CDMID_VAL          255

#define TBU_DBG_TIMEOUT_US		100

struct qsmmuv500_group_iommudata {
	bool has_actlr;
	u32 actlr;
};
#define to_qsmmuv500_group_iommudata(group)				\
	((struct qsmmuv500_group_iommudata *)				\
		(iommu_group_get_iommudata(group)))


static bool arm_smmu_fwspec_match_smr(struct iommu_fwspec *fwspec,
				      struct arm_smmu_smr *smr)
{
	struct arm_smmu_smr *smr2;
	struct arm_smmu_device *smmu = fwspec_smmu(fwspec);
	int i, idx;

	for_each_cfg_sme(fwspec, i, idx) {
		smr2 = &smmu->smrs[idx];
		/* Continue if table entry does not match */
		if ((smr->id ^ smr2->id) & ~(smr->mask | smr2->mask))
			continue;
		return true;
	}
	return false;
}

static int qsmmuv500_tbu_halt(struct qsmmuv500_tbu_device *tbu,
				struct arm_smmu_domain *smmu_domain)
{
	unsigned long flags;
	u32 halt, fsr, status;
	void __iomem *tbu_base, *cb_base;

	if (of_property_read_bool(tbu->dev->of_node,
						"qcom,opt-out-tbu-halting")) {
		dev_notice(tbu->dev, "TBU opted-out for halting!\n");
		return -EBUSY;
	}

	spin_lock_irqsave(&tbu->halt_lock, flags);
	if (tbu->halt_count) {
		tbu->halt_count++;
		spin_unlock_irqrestore(&tbu->halt_lock, flags);
		return 0;
	}

	cb_base = ARM_SMMU_CB(smmu_domain->smmu, smmu_domain->cfg.cbndx);
	tbu_base = tbu->base;
	halt = readl_relaxed(tbu_base + DEBUG_SID_HALT_REG);
	halt |= DEBUG_SID_HALT_VAL;
	writel_relaxed(halt, tbu_base + DEBUG_SID_HALT_REG);

	fsr = readl_relaxed(cb_base + ARM_SMMU_CB_FSR);
	if ((fsr & FSR_FAULT) && (fsr & FSR_SS)) {
		u32 sctlr_orig, sctlr;
		/*
		 * We are in a fault; Our request to halt the bus will not
		 * complete until transactions in front of us (such as the fault
		 * itself) have completed. Disable iommu faults and terminate
		 * any existing transactions.
		 */
		sctlr_orig = readl_relaxed(cb_base + ARM_SMMU_CB_SCTLR);
		sctlr = sctlr_orig & ~(SCTLR_CFCFG | SCTLR_CFIE);
		writel_relaxed(sctlr, cb_base + ARM_SMMU_CB_SCTLR);

		writel_relaxed(fsr, cb_base + ARM_SMMU_CB_FSR);
		/*
		 * Barrier required to ensure that the FSR is cleared
		 * before resuming SMMU operation
		 */
		wmb();
		writel_relaxed(RESUME_TERMINATE, cb_base +
			       ARM_SMMU_CB_RESUME);

		writel_relaxed(sctlr_orig, cb_base + ARM_SMMU_CB_SCTLR);
	}

	if (readl_poll_timeout_atomic(tbu_base + DEBUG_SR_HALT_ACK_REG, status,
					(status & DEBUG_SR_HALT_ACK_VAL),
					0, TBU_DBG_TIMEOUT_US)) {
		dev_err(tbu->dev, "Couldn't halt TBU!\n");

		halt = readl_relaxed(tbu_base + DEBUG_SID_HALT_REG);
		halt &= ~DEBUG_SID_HALT_VAL;
		writel_relaxed(halt, tbu_base + DEBUG_SID_HALT_REG);

		spin_unlock_irqrestore(&tbu->halt_lock, flags);
		return -ETIMEDOUT;
	}

	tbu->halt_count = 1;
	spin_unlock_irqrestore(&tbu->halt_lock, flags);
	return 0;
}

static void qsmmuv500_tbu_resume(struct qsmmuv500_tbu_device *tbu)
{
	unsigned long flags;
	u32 val;
	void __iomem *base;

	spin_lock_irqsave(&tbu->halt_lock, flags);
	if (!tbu->halt_count) {
		WARN(1, "%s: bad tbu->halt_count", dev_name(tbu->dev));
		spin_unlock_irqrestore(&tbu->halt_lock, flags);
		return;

	} else if (tbu->halt_count > 1) {
		tbu->halt_count--;
		spin_unlock_irqrestore(&tbu->halt_lock, flags);
		return;
	}

	base = tbu->base;
	val = readl_relaxed(base + DEBUG_SID_HALT_REG);
	val &= ~DEBUG_SID_HALT_VAL;
	writel_relaxed(val, base + DEBUG_SID_HALT_REG);

	tbu->halt_count = 0;
	spin_unlock_irqrestore(&tbu->halt_lock, flags);
}


static int qsmmuv500_ecats_lock(struct arm_smmu_domain *smmu_domain,
				struct qsmmuv500_tbu_device *tbu,
				unsigned long *flags)
{
	struct arm_smmu_device *smmu = tbu->smmu;
	struct qsmmuv500_archdata *data = get_qsmmuv500_archdata(smmu);
	u32 val;

	spin_lock_irqsave(&smmu->atos_lock, *flags);
	/* The status register is not accessible on version 1.0 */
	if (data->version == 0x01000000)
		return 0;

	if (readl_poll_timeout_atomic(tbu->status_reg,
					val, (val == 0x1), 0,
					TBU_DBG_TIMEOUT_US)) {
		dev_err(tbu->dev, "ECATS hw busy!\n");
		spin_unlock_irqrestore(&smmu->atos_lock, *flags);
		return  -ETIMEDOUT;
	}

	return 0;
}

static void qsmmuv500_ecats_unlock(struct arm_smmu_domain *smmu_domain,
					struct qsmmuv500_tbu_device *tbu,
					unsigned long *flags)
{
	struct arm_smmu_device *smmu = tbu->smmu;
	struct qsmmuv500_archdata *data = get_qsmmuv500_archdata(smmu);

	/* The status register is not accessible on version 1.0 */
	if (data->version != 0x01000000)
		writel_relaxed(0, tbu->status_reg);
	spin_unlock_irqrestore(&smmu->atos_lock, *flags);
}

/*
 * Zero means failure.
 */
static phys_addr_t qsmmuv500_iova_to_phys(
		struct iommu_domain *domain, dma_addr_t iova,
		u32 sid, unsigned long trans_flags)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct arm_smmu_cfg *cfg = &smmu_domain->cfg;
	struct qsmmuv500_tbu_device *tbu;
	int ret;
	phys_addr_t phys = 0;
	u64 val, fsr;
	unsigned long flags;
	void __iomem *cb_base;
	u32 sctlr_orig, sctlr;
	int needs_redo = 0;
	ktime_t timeout;

	/* only 36 bit iova is supported */
	if (iova >= (1ULL << 36)) {
		dev_err_ratelimited(smmu->dev, "ECATS: address too large: %pad\n",
					&iova);
		return 0;
	}

	cb_base = ARM_SMMU_CB(smmu, cfg->cbndx);
	tbu = qsmmuv500_find_tbu(smmu, sid);
	if (!tbu)
		return 0;

	ret = arm_smmu_power_on(tbu->pwr);
	if (ret)
		return 0;

	ret = qsmmuv500_tbu_halt(tbu, smmu_domain);
	if (ret)
		goto out_power_off;

	/*
	 * ECATS can trigger the fault interrupt, so disable it temporarily
	 * and check for an interrupt manually.
	 */
	sctlr_orig = readl_relaxed(cb_base + ARM_SMMU_CB_SCTLR);
	sctlr = sctlr_orig & ~(SCTLR_CFCFG | SCTLR_CFIE);
	writel_relaxed(sctlr, cb_base + ARM_SMMU_CB_SCTLR);

	fsr = readl_relaxed(cb_base + ARM_SMMU_CB_FSR);
	if (fsr & FSR_FAULT) {
		/* Clear pending interrupts */
		writel_relaxed(fsr, cb_base + ARM_SMMU_CB_FSR);
		/*
		 * Barrier required to ensure that the FSR is cleared
		 * before resuming SMMU operation.
		 */
		wmb();

		/*
		 * TBU halt takes care of resuming any stalled transcation.
		 * Kept it here for completeness sake.
		 */
		if (fsr & FSR_SS)
			writel_relaxed(RESUME_TERMINATE, cb_base +
				       ARM_SMMU_CB_RESUME);
	}

	/* Only one concurrent atos operation */
	ret = qsmmuv500_ecats_lock(smmu_domain, tbu, &flags);
	if (ret)
		goto out_resume;

redo:
	/* Set address and stream-id */
	val = readq_relaxed(tbu->base + DEBUG_SID_HALT_REG);
	val &= ~DEBUG_SID_HALT_SID_MASK;
	val |= sid & DEBUG_SID_HALT_SID_MASK;
	writeq_relaxed(val, tbu->base + DEBUG_SID_HALT_REG);
	writeq_relaxed(iova, tbu->base + DEBUG_VA_ADDR_REG);
	val = (u64)(DEBUG_AXUSER_CDMID_VAL & DEBUG_AXUSER_CDMID_MASK) <<
		DEBUG_AXUSER_CDMID_SHIFT;
	writeq_relaxed(val, tbu->base + DEBUG_AXUSER_REG);

	/* Write-back Read and Write-Allocate */
	val = 0xF << DEBUG_TXN_AXCACHE_SHIFT;

	/* Non-secure Access */
	val |= DEBUG_TXN_AXPROT_NSEC;

	/* Write or Read Access */
	if (trans_flags & IOMMU_TRANS_WRITE)
		val |= DEBUG_TXN_WRITE;

	/* Priviledged or Unpriviledged Access */
	if (trans_flags & IOMMU_TRANS_PRIV)
		val |= DEBUG_TXN_AXPROT_PRIV;

	/* Data or Instruction Access */
	if (trans_flags & IOMMU_TRANS_INST)
		val |= DEBUG_TXN_AXPROT_INST;

	val |= DEBUG_TXN_TRIGGER;
	writeq_relaxed(val, tbu->base + DEBUG_TXN_TRIGG_REG);

	ret = 0;
	timeout = ktime_add_us(ktime_get(), TBU_DBG_TIMEOUT_US);
	for (;;) {
		val = readl_relaxed(tbu->base + DEBUG_SR_HALT_ACK_REG);
		if (!(val & DEBUG_SR_ECATS_RUNNING_VAL))
			break;
		val = readl_relaxed(cb_base + ARM_SMMU_CB_FSR);
		if (val & FSR_FAULT)
			break;
		if (ktime_compare(ktime_get(), timeout) > 0) {
			dev_err(tbu->dev, "ECATS translation timed out!\n");
			ret = -ETIMEDOUT;
			break;
		}
	}

	val = readq_relaxed(tbu->base + DEBUG_PAR_REG);
	fsr = readl_relaxed(cb_base + ARM_SMMU_CB_FSR);
	if (val & DEBUG_PAR_FAULT_VAL) {
		dev_err(tbu->dev, "ECATS generated a fault interrupt! FSR = %llx, SID=0x%x\n",
			fsr, sid);

		dev_err(tbu->dev, "ECATS translation failed! PAR = %llx\n",
			val);
		/* Clear pending interrupts */
		writel_relaxed(fsr, cb_base + ARM_SMMU_CB_FSR);
		/*
		 * Barrier required to ensure that the FSR is cleared
		 * before resuming SMMU operation.
		 */
		wmb();

		if (fsr & FSR_SS)
			writel_relaxed(RESUME_TERMINATE, cb_base +
				       ARM_SMMU_CB_RESUME);

		ret = -EINVAL;
	}

	phys = (val >> DEBUG_PAR_PA_SHIFT) & DEBUG_PAR_PA_MASK;
	if (ret < 0)
		phys = 0;

	/* Reset hardware */
	writeq_relaxed(0, tbu->base + DEBUG_TXN_TRIGG_REG);
	writeq_relaxed(0, tbu->base + DEBUG_VA_ADDR_REG);
	val = readl_relaxed(tbu->base + DEBUG_SID_HALT_REG);
	val &= ~DEBUG_SID_HALT_SID_MASK;
	writel_relaxed(val, tbu->base + DEBUG_SID_HALT_REG);

	/*
	 * After a failed translation, the next successful translation will
	 * incorrectly be reported as a failure.
	 */
	if (!phys && needs_redo++ < 2)
		goto redo;

	writel_relaxed(sctlr_orig, cb_base + ARM_SMMU_CB_SCTLR);
	qsmmuv500_ecats_unlock(smmu_domain, tbu, &flags);

out_resume:
	qsmmuv500_tbu_resume(tbu);

out_power_off:
	/* Read to complete prior write transcations */
	val = readl_relaxed(tbu->base + DEBUG_SR_HALT_ACK_REG);

	/* Wait for read to complete before off */
	rmb();

	arm_smmu_power_off(tbu->pwr);

	return phys;
}

static phys_addr_t qsmmuv500_iova_to_phys_hard(
		struct iommu_domain *domain, dma_addr_t iova,
		unsigned long trans_flags)
{
	u16 sid;
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_cfg *cfg = &smmu_domain->cfg;
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct iommu_fwspec *fwspec;
	void __iomem *gr1_base;
	u32 frsynra;

	/* Check to see if the domain is associated with the test
	 * device. If the domain belongs to the test device, then
	 * pick the SID from fwspec.
	 */
	if (domain->is_debug_domain) {
		fwspec = smmu_domain->dev->iommu_fwspec;
		sid    = (u16)fwspec->ids[0];
	} else {

		/* If the domain belongs to an actual device, read
		 * SID from the corresponding frsynra register
		 */
		gr1_base = ARM_SMMU_GR1(smmu);
		frsynra  = readl_relaxed(gr1_base +
				ARM_SMMU_GR1_CBFRSYNRA(cfg->cbndx));
		frsynra &= CBFRSYNRA_SID_MASK;
		sid      = frsynra;
	}
	return qsmmuv500_iova_to_phys(domain, iova, sid, trans_flags);
}

static void qsmmuv500_release_group_iommudata(void *data)
{
	kfree(data);
}

/* If a device has a valid actlr, it must match */
static int qsmmuv500_device_group(struct device *dev,
				struct iommu_group *group)
{
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct arm_smmu_device *smmu = fwspec_smmu(fwspec);
	struct qsmmuv500_archdata *data = get_qsmmuv500_archdata(smmu);
	struct qsmmuv500_group_iommudata *iommudata;
	u32 actlr, i;
	struct arm_smmu_smr *smr;

	iommudata = to_qsmmuv500_group_iommudata(group);
	if (!iommudata) {
		iommudata = kzalloc(sizeof(*iommudata), GFP_KERNEL);
		if (!iommudata)
			return -ENOMEM;

		iommu_group_set_iommudata(group, iommudata,
				qsmmuv500_release_group_iommudata);
	}

	for (i = 0; i < data->actlr_tbl_size; i++) {
		smr = &data->actlrs[i].smr;
		actlr = data->actlrs[i].actlr;

		if (!arm_smmu_fwspec_match_smr(fwspec, smr))
			continue;

		if (!iommudata->has_actlr) {
			iommudata->actlr = actlr;
			iommudata->has_actlr = true;
		} else if (iommudata->actlr != actlr) {
			return -EINVAL;
		}
	}

	return 0;
}

static void qsmmuv500_init_cb(struct arm_smmu_domain *smmu_domain,
				struct device *dev)
{
	struct arm_smmu_device *smmu = smmu_domain->smmu;
	struct qsmmuv500_group_iommudata *iommudata =
		to_qsmmuv500_group_iommudata(dev->iommu_group);
	void __iomem *cb_base;
	const struct iommu_gather_ops *tlb;

	if (!iommudata->has_actlr)
		return;

	tlb = smmu_domain->pgtbl_cfg.tlb;
	cb_base = ARM_SMMU_CB(smmu, smmu_domain->cfg.cbndx);

	writel_relaxed(iommudata->actlr, cb_base + ARM_SMMU_CB_ACTLR);

	/*
	 * Flush the context bank after modifying ACTLR to ensure there
	 * are no cache entries with stale state
	 */
	tlb->tlb_flush_all(smmu_domain);
}

static int qsmmuv500_tbu_register(struct device *dev, void *cookie)
{
	struct arm_smmu_device *smmu = cookie;
	struct qsmmuv500_tbu_device *tbu;
	struct qsmmuv500_archdata *data = get_qsmmuv500_archdata(smmu);

	if (!dev->driver) {
		dev_err(dev, "TBU failed probe, QSMMUV500 cannot continue!\n");
		return -EINVAL;
	}

	tbu = dev_get_drvdata(dev);

	INIT_LIST_HEAD(&tbu->list);
	tbu->smmu = smmu;
	list_add(&tbu->list, &data->tbus);
	return 0;
}

static int qsmmuv500_read_actlr_tbl(struct arm_smmu_device *smmu)
{
	int len, i;
	struct device *dev = smmu->dev;
	struct qsmmuv500_archdata *data = get_qsmmuv500_archdata(smmu);
	struct actlr_setting *actlrs;
	const __be32 *cell;

	cell = of_get_property(dev->of_node, "qcom,actlr", NULL);
	if (!cell)
		return 0;

	len = of_property_count_elems_of_size(dev->of_node, "qcom,actlr",
						sizeof(u32) * 3);
	if (len < 0)
		return 0;

	actlrs = devm_kzalloc(dev, sizeof(*actlrs) * len, GFP_KERNEL);
	if (!actlrs)
		return -ENOMEM;

	for (i = 0; i < len; i++) {
		actlrs[i].smr.id = of_read_number(cell++, 1);
		actlrs[i].smr.mask = of_read_number(cell++, 1);
		actlrs[i].actlr = of_read_number(cell++, 1);
	}

	data->actlrs = actlrs;
	data->actlr_tbl_size = len;
	return 0;
}

static int qsmmuv500_get_testbus_version(struct arm_smmu_device *smmu)
{
	struct device *dev = smmu->dev;
	struct qsmmuv500_archdata *data = get_qsmmuv500_archdata(smmu);
	u32 testbus_version;
	const __be32 *cell;

	cell = of_get_property(dev->of_node, "qcom,testbus-version", NULL);
	if (!cell)
		return 0;

	testbus_version = of_read_number(cell, 1);

	data->testbus_version = testbus_version;
	return 0;
}
static ssize_t arm_smmu_debug_testbus_read(struct file *file,
		char __user *ubuf, size_t count, loff_t *offset,
		enum testbus_sel tbu, enum testbus_ops ops)

{
	char buf[100];
	ssize_t retval;
	size_t buflen;
	int buf_len = sizeof(buf);

	if (*offset)
		return 0;

	memset(buf, 0, buf_len);

	if (tbu == SEL_TBU) {
		struct qsmmuv500_tbu_device *tbu = file->private_data;
		struct arm_smmu_device *smmu = tbu->smmu;
		void __iomem *tbu_base = tbu->base;
		struct qsmmuv500_archdata *data = smmu->archdata;
		void __iomem *tcu_base = data->tcu_base;
		u32 testbus_version = data->testbus_version;
		struct arm_smmu_power_resources *pwr;
		long val;

		if (testbus_version == 1)
			pwr = smmu->pwr;
		else
			pwr = tbu->pwr;

		arm_smmu_power_on(pwr);

		if (ops == TESTBUS_SELECT)
			val = arm_smmu_debug_tbu_testbus_select(tbu_base,
					tcu_base, testbus_version, READ, 0);
		else
			val = arm_smmu_debug_tbu_testbus_output(tbu_base,
							testbus_version);
		arm_smmu_power_off(pwr);

		snprintf(buf, buf_len, "0x%0x\n", val);
	} else {

		struct arm_smmu_device *smmu = file->private_data;
		struct qsmmuv500_archdata *data = smmu->archdata;
		phys_addr_t phys_addr = smmu->phys_addr;
		void __iomem *tcu_base = data->tcu_base;

		arm_smmu_power_on(smmu->pwr);

		if (ops == TESTBUS_SELECT) {
			snprintf(buf, buf_len, "TCU clk testbus sel: 0x%0x\n",
				arm_smmu_debug_tcu_testbus_select(phys_addr,
					tcu_base, CLK_TESTBUS, READ, 0));
			snprintf(buf + strlen(buf), buf_len - strlen(buf),
				 "TCU testbus sel : 0x%0x\n",
				 arm_smmu_debug_tcu_testbus_select(phys_addr,
					 tcu_base, PTW_AND_CACHE_TESTBUS,
					 READ, 0));
		} else {
			snprintf(buf, buf_len, "0x%0x\n",
				 arm_smmu_debug_tcu_testbus_output(phys_addr));
		}

		arm_smmu_power_off(smmu->pwr);
	}
	buflen = min(count, strlen(buf));
	if (copy_to_user(ubuf, buf, buflen)) {
		pr_err_ratelimited("Couldn't copy_to_user\n");
		retval = -EFAULT;
	} else {
		*offset = 1;
		retval = buflen;
	}

	return retval;
}
static ssize_t arm_smmu_debug_tcu_testbus_sel_write(struct file *file,
		const char __user *ubuf, size_t count, loff_t *offset)
{
	struct arm_smmu_device *smmu = file->private_data;
	struct qsmmuv500_archdata *data = smmu->archdata;
	void __iomem *tcu_base = data->tcu_base;
	phys_addr_t phys_addr = smmu->phys_addr;
	char *comma;
	char buf[100];
	u64 sel, val;

	if (count >= 100) {
		pr_err_ratelimited("Value too large\n");
		return -EINVAL;
	}

	memset(buf, 0, 100);

	if (copy_from_user(buf, ubuf, count)) {
		pr_err_ratelimited("Couldn't copy from user\n");
		return -EFAULT;
	}

	comma = strnchr(buf, count, ',');
	if (!comma)
		goto invalid_format;

	/* split up the words */
	*comma = '\0';

	if (kstrtou64(buf, 0, &sel))
		goto invalid_format;

	if (sel != 1 && sel != 2)
		goto invalid_format;

	if (kstrtou64(comma + 1, 0, &val))
		goto invalid_format;

	arm_smmu_power_on(smmu->pwr);

	if (sel == 1)
		arm_smmu_debug_tcu_testbus_select(phys_addr,
				tcu_base, CLK_TESTBUS, WRITE, val);
	else if (sel == 2)
		arm_smmu_debug_tcu_testbus_select(phys_addr,
				tcu_base, PTW_AND_CACHE_TESTBUS,
				WRITE, val);

	arm_smmu_power_off(smmu->pwr);

	return count;

invalid_format:
	pr_err_ratelimited("Invalid format. Expected: <1, testbus select> for tcu CLK testbus (or) <2, testbus select> for tcu PTW/CACHE testbuses\n");
	return -EINVAL;
}

static ssize_t arm_smmu_debug_tcu_testbus_sel_read(struct file *file,
		char __user *ubuf, size_t count, loff_t *offset)
{
	return arm_smmu_debug_testbus_read(file, ubuf,
			count, offset, SEL_TCU, TESTBUS_SELECT);
}

static const struct file_operations arm_smmu_debug_tcu_testbus_sel_fops = {
	.open	= simple_open,
	.write	= arm_smmu_debug_tcu_testbus_sel_write,
	.read	= arm_smmu_debug_tcu_testbus_sel_read,
};

static ssize_t arm_smmu_debug_tcu_testbus_read(struct file *file,
		char __user *ubuf, size_t count, loff_t *offset)
{
	return arm_smmu_debug_testbus_read(file, ubuf,
			count, offset, SEL_TCU, TESTBUS_OUTPUT);
}

static const struct file_operations arm_smmu_debug_tcu_testbus_fops = {
	.open	= simple_open,
	.read	= arm_smmu_debug_tcu_testbus_read,
};

static int qsmmuv500_tcu_testbus_init(struct arm_smmu_device *smmu)
{
	struct dentry *testbus_dir;

	if (!iommu_debugfs_top)
		return 0;

	if (!debugfs_testbus_dir) {
		debugfs_testbus_dir = debugfs_create_dir("testbus",
						       iommu_debugfs_top);
		if (!debugfs_testbus_dir) {
			pr_err_ratelimited("Couldn't create iommu/testbus debugfs directory\n");
			return -ENODEV;
		}
	}

	testbus_dir = debugfs_create_dir(dev_name(smmu->dev),
				debugfs_testbus_dir);

	if (!testbus_dir) {
		pr_err_ratelimited("Couldn't create iommu/testbus/%s debugfs directory\n",
		       dev_name(smmu->dev));
		goto err;
	}

	if (!debugfs_create_file("tcu_testbus_sel", 0400, testbus_dir, smmu,
			&arm_smmu_debug_tcu_testbus_sel_fops)) {
		pr_err_ratelimited("Couldn't create iommu/testbus/%s/tcu_testbus_sel debugfs file\n",
		       dev_name(smmu->dev));
		goto err_rmdir;
	}

	if (!debugfs_create_file("tcu_testbus_output", 0400, testbus_dir, smmu,
			&arm_smmu_debug_tcu_testbus_fops)) {
		pr_err_ratelimited("Couldn't create iommu/testbus/%s/tcu_testbus_output debugfs file\n",
		       dev_name(smmu->dev));
		goto err_rmdir;
	}

	return 0;
err_rmdir:
	debugfs_remove_recursive(testbus_dir);
err:
	return 0;
}

static ssize_t arm_smmu_debug_tbu_testbus_sel_write(struct file *file,
		const char __user *ubuf, size_t count, loff_t *offset)
{
	struct qsmmuv500_tbu_device *tbu = file->private_data;
	void __iomem *tbu_base = tbu->base;
	struct arm_smmu_device *smmu = tbu->smmu;
	struct arm_smmu_power_resources *pwr;
	struct qsmmuv500_archdata *data = smmu->archdata;
	void __iomem *tcu_base = data->tcu_base;
	u32 testbus_version = data->testbus_version;
	u64 val;

	if (kstrtoull_from_user(ubuf, count, 0, &val)) {
		pr_err_ratelimited("Invalid format for tbu testbus select\n");
		return -EINVAL;
	}

	if (testbus_version == 1)
		pwr = smmu->pwr;
	else
		pwr = tbu->pwr;

	arm_smmu_power_on(pwr);
	arm_smmu_debug_tbu_testbus_select(tbu_base, tcu_base,
			testbus_version, WRITE, val);
	arm_smmu_power_off(pwr);

	return count;
}

static ssize_t arm_smmu_debug_tbu_testbus_sel_read(struct file *file,
		char __user *ubuf, size_t count, loff_t *offset)
{
	return arm_smmu_debug_testbus_read(file, ubuf,
			count, offset, SEL_TBU, TESTBUS_SELECT);
}

static const struct file_operations arm_smmu_debug_tbu_testbus_sel_fops = {
	.open	= simple_open,
	.write	= arm_smmu_debug_tbu_testbus_sel_write,
	.read	= arm_smmu_debug_tbu_testbus_sel_read,
};

static ssize_t arm_smmu_debug_tbu_testbus_read(struct file *file,
		char __user *ubuf, size_t count, loff_t *offset)
{
	return arm_smmu_debug_testbus_read(file, ubuf,
			count, offset, SEL_TBU, TESTBUS_OUTPUT);
}

static const struct file_operations arm_smmu_debug_tbu_testbus_fops = {
	.open	= simple_open,
	.read	= arm_smmu_debug_tbu_testbus_read,
};

static int qsmmuv500_tbu_testbus_init(struct qsmmuv500_tbu_device *tbu)
{
	struct dentry *testbus_dir;

	if (!iommu_debugfs_top)
		return 0;

	if (!debugfs_testbus_dir) {
		debugfs_testbus_dir = debugfs_create_dir("testbus",
						       iommu_debugfs_top);
		if (!debugfs_testbus_dir) {
			pr_err_ratelimited("Couldn't create iommu/testbus debugfs directory\n");
			return -ENODEV;
		}
	}

	testbus_dir = debugfs_create_dir(dev_name(tbu->dev),
				debugfs_testbus_dir);

	if (!testbus_dir) {
		pr_err_ratelimited("Couldn't create iommu/testbus/%s debugfs directory\n",
				dev_name(tbu->dev));
		goto err;
	}

	if (!debugfs_create_file("tbu_testbus_sel", 0400, testbus_dir, tbu,
			&arm_smmu_debug_tbu_testbus_sel_fops)) {
		pr_err_ratelimited("Couldn't create iommu/testbus/%s/tbu_testbus_sel debugfs file\n",
				dev_name(tbu->dev));
		goto err_rmdir;
	}

	if (!debugfs_create_file("tbu_testbus_output", 0400, testbus_dir, tbu,
			&arm_smmu_debug_tbu_testbus_fops)) {
		pr_err_ratelimited("Couldn't create iommu/testbus/%s/tbu_testbus_output debugfs file\n",
				dev_name(tbu->dev));
		goto err_rmdir;
	}

	return 0;
err_rmdir:
	debugfs_remove_recursive(testbus_dir);
err:
	return 0;
}

static ssize_t arm_smmu_debug_capturebus_snapshot_read(struct file *file,
		char __user *ubuf, size_t count, loff_t *offset)
{
	struct qsmmuv500_tbu_device *tbu = file->private_data;
	struct arm_smmu_device *smmu = tbu->smmu;
	void __iomem *tbu_base = tbu->base;
	u64 snapshot[NO_OF_CAPTURE_POINTS][REGS_PER_CAPTURE_POINT];
	char buf[400];
	ssize_t retval;
	size_t buflen;
	int buf_len = sizeof(buf);
	int i, j;

	if (*offset)
		return 0;

	memset(buf, 0, buf_len);

	arm_smmu_power_on(smmu->pwr);
	arm_smmu_power_on(tbu->pwr);

	arm_smmu_debug_get_capture_snapshot(tbu_base, snapshot);

	arm_smmu_power_off(tbu->pwr);
	arm_smmu_power_off(smmu->pwr);

	for (i = 0; i < NO_OF_CAPTURE_POINTS ; ++i) {
		for (j = 0; j < REGS_PER_CAPTURE_POINT; ++j) {
			snprintf(buf + strlen(buf), buf_len - strlen(buf),
				 "Capture_%d_Snapshot_%d : 0x%0llx\n",
				  i+1, j+1, snapshot[i][j]);
		}
	}

	buflen = min(count, strlen(buf));
	if (copy_to_user(ubuf, buf, buflen)) {
		pr_err_ratelimited("Couldn't copy_to_user\n");
		retval = -EFAULT;
	} else {
		*offset = 1;
		retval = buflen;
	}

	return retval;
}
static const struct file_operations arm_smmu_debug_capturebus_snapshot_fops = {
	.open	= simple_open,
	.read	= arm_smmu_debug_capturebus_snapshot_read,
};

static ssize_t arm_smmu_debug_capturebus_config_write(struct file *file,
		const char __user *ubuf, size_t count, loff_t *offset)
{
	struct qsmmuv500_tbu_device *tbu = file->private_data;
	struct arm_smmu_device *smmu = tbu->smmu;
	void __iomem *tbu_base = tbu->base;
	char *comma1, *comma2;
	char buf[100];
	u64 sel, mask, match, val;

	if (count >= 100) {
		pr_err_ratelimited("Input too large\n");
		goto invalid_format;
	}

	memset(buf, 0, 100);

	if (copy_from_user(buf, ubuf, count)) {
		pr_err_ratelimited("Couldn't copy from user\n");
		return -EFAULT;
	}

	comma1 = strnchr(buf, count, ',');
	if (!comma1)
		goto invalid_format;

	*comma1  = '\0';

	if (kstrtou64(buf, 0, &sel))
		goto invalid_format;

	if (sel > 4) {
		goto invalid_format;
	} else if (sel == 4) {
		if (kstrtou64(comma1 + 1, 0, &val))
			goto invalid_format;
		goto program_capturebus;
	}

	comma2 = strnchr(comma1 + 1, count, ',');
	if (!comma2)
		goto invalid_format;

	/* split up the words */
	*comma2 = '\0';

	if (kstrtou64(comma1 + 1, 0, &mask))
		goto invalid_format;

	if (kstrtou64(comma2 + 1, 0, &match))
		goto invalid_format;

program_capturebus:
	arm_smmu_power_on(smmu->pwr);
	arm_smmu_power_on(tbu->pwr);

	if (sel == 4)
		arm_smmu_debug_set_tnx_tcr_cntl(tbu_base, val);
	else
		arm_smmu_debug_set_mask_and_match(tbu_base, sel, mask, match);

	arm_smmu_power_off(tbu->pwr);
	arm_smmu_power_off(smmu->pwr);
	return count;

invalid_format:
	pr_err_ratelimited("Invalid format. Expected: <1/2/3,Mask,Match> (or) <4,TNX_TCR_CNTL>>\n");
	return -EINVAL;
}
static ssize_t arm_smmu_debug_capturebus_config_read(struct file *file,
		char __user *ubuf, size_t count, loff_t *offset)
{
	struct qsmmuv500_tbu_device *tbu = file->private_data;
	struct arm_smmu_device *smmu = tbu->smmu;
	void __iomem *tbu_base = tbu->base;
	unsigned long val;
	u64 mask[NO_OF_MASK_AND_MATCH], match[NO_OF_MASK_AND_MATCH];
	char buf[400];
	ssize_t retval;
	size_t buflen;
	int buf_len = sizeof(buf);
	int i;

	if (*offset)
		return 0;

	memset(buf, 0, buf_len);

	arm_smmu_power_on(smmu->pwr);
	arm_smmu_power_on(tbu->pwr);

	arm_smmu_debug_get_mask_and_match(tbu_base,
					mask, match);
	val = arm_smmu_debug_get_tnx_tcr_cntl(tbu_base);

	arm_smmu_power_off(tbu->pwr);
	arm_smmu_power_off(smmu->pwr);

	for (i = 0; i < NO_OF_MASK_AND_MATCH; ++i) {
		snprintf(buf + strlen(buf), buf_len - strlen(buf),
				"Mask_%d : 0x%0llx\t", i+1, mask[i]);
		snprintf(buf + strlen(buf), buf_len - strlen(buf),
				"Match_%d : 0x%0llx\n", i+1, match[i]);
	}
	snprintf(buf + strlen(buf), buf_len - strlen(buf), "0x%0x\n", val);

	buflen = min(count, strlen(buf));
	if (copy_to_user(ubuf, buf, buflen)) {
		pr_err_ratelimited("Couldn't copy_to_user\n");
		retval = -EFAULT;
	} else {
		*offset = 1;
		retval = buflen;
	}

	return retval;
}

static const struct file_operations arm_smmu_debug_capturebus_config_fops = {
	.open	= simple_open,
	.write	= arm_smmu_debug_capturebus_config_write,
	.read	= arm_smmu_debug_capturebus_config_read,
};

static int qsmmuv500_capturebus_init(struct qsmmuv500_tbu_device *tbu)
{
	struct dentry *capturebus_dir;

	if (!iommu_debugfs_top)
		return 0;

	if (!debugfs_capturebus_dir) {
		debugfs_capturebus_dir = debugfs_create_dir(
					 "capturebus", iommu_debugfs_top);
		if (!debugfs_capturebus_dir) {
			pr_err_ratelimited("Couldn't create iommu/capturebus debugfs directory\n");
			return -ENODEV;
		}
	}
	capturebus_dir = debugfs_create_dir(dev_name(tbu->dev),
				debugfs_capturebus_dir);
	if (!capturebus_dir) {
		pr_err_ratelimited("Couldn't create iommu/capturebus/%s debugfs directory\n",
				dev_name(tbu->dev));
		goto err;
	}

	if (!debugfs_create_file("config", 0400, capturebus_dir, tbu,
			&arm_smmu_debug_capturebus_config_fops)) {
		pr_err_ratelimited("Couldn't create iommu/capturebus/%s/config debugfs file\n",
				dev_name(tbu->dev));
		goto err_rmdir;
	}

	if (!debugfs_create_file("snapshot", 0400, capturebus_dir, tbu,
			&arm_smmu_debug_capturebus_snapshot_fops)) {
		pr_err_ratelimited("Couldn't create iommu/capturebus/%s/snapshot debugfs file\n",
				dev_name(tbu->dev));
		goto err_rmdir;
	}
	return 0;
err_rmdir:
	debugfs_remove_recursive(capturebus_dir);
err:
	return 0;
}

static irqreturn_t arm_smmu_debug_capture_bus_match(int irq, void *dev)
{
	struct qsmmuv500_tbu_device *tbu = dev;
	struct arm_smmu_device *smmu = tbu->smmu;
	void __iomem *tbu_base = tbu->base;
	u64 mask[NO_OF_MASK_AND_MATCH], match[NO_OF_MASK_AND_MATCH];
	u64 snapshot[NO_OF_CAPTURE_POINTS][REGS_PER_CAPTURE_POINT];
	int i, j, val;

	if (arm_smmu_power_on(smmu->pwr) || arm_smmu_power_on(tbu->pwr))
		return IRQ_NONE;

	val = arm_smmu_debug_get_tnx_tcr_cntl(tbu_base);
	arm_smmu_debug_get_mask_and_match(tbu_base, mask, match);
	arm_smmu_debug_get_capture_snapshot(tbu_base, snapshot);
	arm_smmu_debug_clear_intr_and_validbits(tbu_base);

	arm_smmu_power_off(tbu->pwr);
	arm_smmu_power_off(smmu->pwr);

	dev_info(tbu->dev, "TNX_TCR_CNTL : 0x%0llx\n", val);

	for (i = 0; i < NO_OF_MASK_AND_MATCH; ++i) {
		dev_info(tbu->dev,
				"Mask_%d : 0x%0llx\n", i+1, mask[i]);
		dev_info(tbu->dev,
				"Match_%d : 0x%0llx\n", i+1, match[i]);
	}

	for (i = 0; i < NO_OF_CAPTURE_POINTS ; ++i) {
		for (j = 0; j < REGS_PER_CAPTURE_POINT; ++j) {
			dev_info(tbu->dev,
					"Capture_%d_Snapshot_%d : 0x%0llx\n",
					i+1, j+1, snapshot[i][j]);
		}
	}

	return IRQ_HANDLED;
}

static int qsmmuv500_arch_init(struct arm_smmu_device *smmu)
{
	struct resource *res;
	struct device *dev = smmu->dev;
	struct qsmmuv500_archdata *data;
	struct platform_device *pdev;
	int ret;
	u32 val;
	void __iomem *reg;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	INIT_LIST_HEAD(&data->tbus);

	pdev = container_of(dev, struct platform_device, dev);
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "tcu-base");
	if (!res) {
		dev_err(dev, "Unable to get the tcu-base\n");
		return -EINVAL;
	}
	data->tcu_base = devm_ioremap(dev, res->start, resource_size(res));
	if (IS_ERR(data->tcu_base))
		return PTR_ERR(data->tcu_base);

	data->version = readl_relaxed(data->tcu_base + TCU_HW_VERSION_HLOS1);
	smmu->archdata = data;

	ret = qsmmuv500_get_testbus_version(smmu);
	if (ret)
		return ret;

	qsmmuv500_tcu_testbus_init(smmu);

	if (arm_smmu_is_static_cb(smmu))
		return 0;

	ret = qsmmuv500_read_actlr_tbl(smmu);
	if (ret)
		return ret;

	reg = ARM_SMMU_GR0(smmu);
	val = readl_relaxed(reg + ARM_SMMU_GR0_sACR);
	val &= ~ARM_MMU500_ACR_CACHE_LOCK;
	writel_relaxed(val, reg + ARM_SMMU_GR0_sACR);
	val = readl_relaxed(reg + ARM_SMMU_GR0_sACR);
	/*
	 * Modifiying the nonsecure copy of the sACR register is only
	 * allowed if permission is given in the secure sACR register.
	 * Attempt to detect if we were able to update the value.
	 */
	WARN_ON(val & ARM_MMU500_ACR_CACHE_LOCK);

	ret = of_platform_populate(dev->of_node, NULL, NULL, dev);
	if (ret)
		return ret;

	/* Attempt to register child devices */
	ret = device_for_each_child(dev, smmu, qsmmuv500_tbu_register);
	if (ret)
		return -EPROBE_DEFER;

	return 0;
}

struct arm_smmu_arch_ops qsmmuv500_arch_ops = {
	.init = qsmmuv500_arch_init,
	.iova_to_phys_hard = qsmmuv500_iova_to_phys_hard,
	.init_context_bank = qsmmuv500_init_cb,
	.device_group = qsmmuv500_device_group,
};

static const struct of_device_id qsmmuv500_tbu_of_match[] = {
	{.compatible = "qcom,qsmmuv500-tbu"},
	{}
};

static int qsmmuv500_tbu_probe(struct platform_device *pdev)
{
	struct resource *res;
	struct device *dev = &pdev->dev;
	struct qsmmuv500_tbu_device *tbu;
	const __be32 *cell;
	int len, i, err, num_irqs = 0;

	tbu = devm_kzalloc(dev, sizeof(*tbu), GFP_KERNEL);
	if (!tbu)
		return -ENOMEM;

	INIT_LIST_HEAD(&tbu->list);
	tbu->dev = dev;
	spin_lock_init(&tbu->halt_lock);

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "base");
	tbu->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(tbu->base))
		return PTR_ERR(tbu->base);

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "status-reg");
	tbu->status_reg = devm_ioremap_resource(dev, res);
	if (IS_ERR(tbu->status_reg))
		return PTR_ERR(tbu->status_reg);

	cell = of_get_property(dev->of_node, "qcom,stream-id-range", &len);
	if (!cell || len < 8)
		return -EINVAL;

	tbu->sid_start = of_read_number(cell, 1);
	tbu->num_sids = of_read_number(cell + 1, 1);

	while ((res = platform_get_resource(pdev, IORESOURCE_IRQ, num_irqs)))
		num_irqs++;

	tbu->irqs = devm_kzalloc(dev, sizeof(*tbu->irqs) * num_irqs,
				  GFP_KERNEL);
	if (!tbu->irqs)
		return -ENOMEM;

	for (i = 0; i < num_irqs; ++i) {
		int irq = platform_get_irq(pdev, i);

		if (irq < 0) {
			dev_err(dev, "failed to get irq index %d\n", i);
			return -ENODEV;
		}
		tbu->irqs[i] = irq;

		err = devm_request_threaded_irq(tbu->dev, tbu->irqs[i],
					NULL, arm_smmu_debug_capture_bus_match,
					IRQF_ONESHOT | IRQF_SHARED,
					"capture bus", tbu);
		if (err) {
			dev_err(dev, "failed to request capture bus irq%d (%u)\n",
				i, tbu->irqs[i]);
			return err;
		}
	}

	tbu->pwr = arm_smmu_init_power_resources(pdev);
	if (IS_ERR(tbu->pwr))
		return PTR_ERR(tbu->pwr);

	dev_set_drvdata(dev, tbu);

	qsmmuv500_tbu_testbus_init(tbu);
	qsmmuv500_capturebus_init(tbu);

	return 0;
}

static struct platform_driver qsmmuv500_tbu_driver = {
	.driver	= {
		.name		= "qsmmuv500-tbu",
		.of_match_table	= of_match_ptr(qsmmuv500_tbu_of_match),
	},
	.probe	= qsmmuv500_tbu_probe,
};

MODULE_DESCRIPTION("IOMMU API for ARM architected SMMU implementations");
MODULE_AUTHOR("Will Deacon <will.deacon@arm.com>");
MODULE_LICENSE("GPL v2");

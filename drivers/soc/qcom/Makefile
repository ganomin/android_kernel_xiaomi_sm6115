# SPDX-License-Identifier: GPL-2.0
CFLAGS_rpmh-rsc.o := -I$(src)
obj-$(CONFIG_QCOM_GENI_SE) +=	qcom-geni-se.o
obj-$(CONFIG_QCOM_COMMAND_DB) += cmd-db.o
obj-$(CONFIG_QCOM_GLINK_SSR) +=	glink_ssr.o
obj-$(CONFIG_QCOM_GSBI)	+=	qcom_gsbi.o
obj-$(CONFIG_QCOM_MDT_LOADER)	+= mdt_loader.o
obj-$(CONFIG_QCOM_PM)	+=	spm.o
obj-$(CONFIG_QCOM_QMI_HELPERS)	+= qmi_helpers.o
qmi_helpers-y	+= qmi_encdec.o qmi_interface.o
obj-$(CONFIG_QCOM_RMTFS_MEM)	+= rmtfs_mem.o
obj-$(CONFIG_QCOM_RPMH)		+= qcom_rpmh.o
qcom_rpmh-y			+= rpmh-rsc.o
qcom_rpmh-y			+= rpmh.o
obj-$(CONFIG_QCOM_SMD_RPM)	+= smd-rpm.o
obj-$(CONFIG_QCOM_SMEM) +=	smem.o
obj-$(CONFIG_QCOM_SMEM_STATE) += smem_state.o
obj-$(CONFIG_QCOM_SMP2P)	+= smp2p.o
obj-$(CONFIG_QCOM_SMSM)	+= smsm.o
obj-$(CONFIG_QCOM_WCNSS_CTRL) += wcnss_ctrl.o
obj-$(CONFIG_QCOM_APR) += apr.o
obj-$(CONFIG_QCOM_LLCC) += llcc-slice.o
obj-$(CONFIG_QCOM_SDM845_LLCC) += llcc-sdm845.o
CFLAGS_rpmh-rsc.o := -I$(src)
obj-$(CONFIG_QCOM_BUS_SCALING) += msm_bus/
obj-$(CONFIG_QCOM_FSA4480_I2C) += fsa4480-i2c.o
obj-$(CONFIG_QCOM_GLINK) += glink_probe.o
obj-$(CONFIG_QCOM_GLINK_PKT) += glink_pkt.o
obj-$(CONFIG_QCOM_SMP2P_SLEEPSTATE) += smp2p_sleepstate.o
obj-$(CONFIG_QCOM_QDSS_BRIDGE) += qdss_bridge.o
obj-$(CONFIG_MSM_QBT_HANDLER) += qbt_handler.o
obj-$(CONFIG_QSEE_IPC_IRQ) += qsee_ipc_irq.o
obj-$(CONFIG_QSEE_IPC_IRQ_BRIDGE) += qsee_ipc_irq_bridge.o
obj-$(CONFIG_QPNP_PBS) += qpnp-pbs.o
obj-$(CONFIG_QTI_SYSTEM_PM) += system_pm.o
obj-$(CONFIG_MSM_REMOTEQDSS) += remoteqdss.o
obj-$(CONFIG_MSM_EVENT_TIMER) += event_timer.o
obj-$(CONFIG_MSM_IDLE_STATS)	+= lpm-stats.o
ifdef CONFIG_QCOM_RPMH
       obj-$(CONFIG_QTI_RPM_STATS_LOG) += rpmh_master_stat.o
else
       obj-$(CONFIG_QTI_RPM_STATS_LOG) += rpm_master_stat.o
endif
obj-$(CONFIG_QTI_RPM_STATS_LOG) += rpm_stats.o
obj-$(CONFIG_QCOM_MEM_OFFLINE) += mem-offline.o
obj-$(CONFIG_QTI_DDR_STATS_LOG) += ddr_stats.o
obj-$(CONFIG_QMP_DEBUGFS_CLIENT) += qmp-debugfs-client.o
obj-$(CONFIG_QCOM_HYP_CORE_CTL) += hyp_core_ctl.o
obj-$(CONFIG_MSM_PERFORMANCE) += msm_performance.o
ifdef CONFIG_DEBUG_FS
obj-$(CONFIG_MSM_RPM_SMD)   +=  rpm-smd-debug.o
endif
obj-$(CONFIG_QCOM_CDSP_RM) += cdsprm.o
obj-$(CONFIG_ICNSS) += icnss.o
obj-$(CONFIG_ICNSS_QMI) += icnss_qmi.o wlan_firmware_service_v01.o
obj-$(CONFIG_RMNET_CTL) += rmnet_ctl/
obj-$(CONFIG_QCOM_CX_IPEAK) += cx_ipeak.o
obj-$(CONFIG_QTI_L2_REUSE) += l2_reuse.o
obj-$(CONFIG_ICNSS2) += icnss2/
obj-$(CONFIG_QTI_HW_KEY_MANAGER) += hwkm_qti.o
hwkm_qti-y += hwkm.o crypto-qti-hwkm.o
obj-$(CONFIG_SERIAL_NUM) += serial_num.o

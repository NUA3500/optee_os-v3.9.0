// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 *
 */
#include <crypto/crypto.h>
#include <kernel/delay.h>
#include <kernel/pseudo_ta.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>
#include <kernel/tee_time.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <io.h>
#include <string.h>
#include <ks_pta_client.h>

#define PTA_NAME "nvt_ks.pta"

#define USE_GEN_NONCE
#define TRNG_BUSY_TIMEOUT	2000

/*----------------------------------------------------------------------*/
/*  NUA3500 Key Store registers                                         */
/*----------------------------------------------------------------------*/
#define KS_CTL			(ks_base + 0x00)
#define KS_CTL_START			(0x1 << 0)
#define KS_CTL_OPMODE_POS		1
#define KS_CTL_OPMODE_MSK		(0x7 << KS_CTL_OPMODE_POS)
#define KS_CTL_CONT			(0x1 << 7)
#define KS_CTL_INIT			(0x1 << 8)
#define KS_CTL_SILENT			(0x1 << 10)
#define KS_CTL_SCMB			(0x1 << 11)
#define KS_CTL_TCLR			(0x1 << 14)
#define KS_CTL_IEN			(0x1 << 15)
#define KS_METADATA		(ks_base + 0x04)
#define KS_META_DST_POS			30
#define KS_META_DST_MSK			(0x3 << KS_META_DST_POS)
#define KS_META_KNUM_POS		20
#define KS_META_KNUM_MSK		(0x3f << KS_META_KNUM_POS)
#define KS_META_SIZE_POS		8
#define KS_META_SIZE_MSK		(0x1f << KS_META_SIZE_POS)
#define KS_STS			(ks_base + 0x08)
#define KS_STS_IF			(0x1 << 0)
#define KS_STS_EIF			(0x1 << 1)
#define KS_STS_BUSY			(0x1 << 2)
#define KS_STS_SRAMFULL			(0x1 << 3)
#define KS_STS_INITDONE			(0x1 << 7)
#define KS_STS_RAMINV_POS		8
#define KS_STS_RAMINV_MSK		(0xFFFFFF << 8)
#define KS_REMAIN		(ks_base + 0x0C)
#define KS_REMAIN_RRMNG_POS		0
#define KS_REMAIN_RRMNG_MSK		(0x1FFF << 0)
#define KS_SCMBKEY(x)		(ks_base + 0x10 + ((x) * 0x04))
#define KS_KEY(x)		(ks_base + 0x20 + ((x) * 0x04))
#define KS_OTPSTS		(ks_base + 0x40)

#define KS_SRAM			0
#define KS_OTP			2

#define KS_CLT_FUNC_MASK        (KS_CTL_IEN | KS_CTL_TCLR | KS_CTL_SCMB | \
				 KS_CTL_SILENT)

#define KS_OP_READ		(0x0 << KS_CTL_OPMODE_POS)
#define KS_OP_WRITE		(0x1 << KS_CTL_OPMODE_POS)
#define KS_OP_ERASE		(0x2 << KS_CTL_OPMODE_POS)
#define KS_OP_ERASE_ALL		(0x3 << KS_CTL_OPMODE_POS)
#define KS_OP_REVOKE		(0x4 << KS_CTL_OPMODE_POS)
#define KS_OP_REMAN		(0x5 << KS_CTL_OPMODE_POS)

static uint16_t _keylen2wcnt[21] = {4, 6, 6, 7, 8, 8, 8, 9, 12, 13, 16, 17,
				    18, 0, 0, 0, 32, 48, 64, 96, 128};

static TEE_Result nua3500_ks_init(void)
{
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_NSEC);
	vaddr_t ks_base = core_mmu_get_va(KS_BASE, MEM_AREA_IO_SEC);
	vaddr_t tsi_base = core_mmu_get_va(TSI_BASE, MEM_AREA_IO_SEC);

	if (!(io_read32(sys_base + SYS_CHIPCFG) & TSIEN)) {
		if ((io_read32(tsi_base + 0x210) & 0x7) != 0x2) {
			do {
				io_write32(tsi_base + 0x100, 0x59);
				io_write32(tsi_base + 0x100, 0x16);
				io_write32(tsi_base + 0x100, 0x88);
			} while (io_read32(tsi_base + 0x100) == 0UL);

			io_write32(tsi_base + 0x240, TSI_PLL_SETTING);

			/* wait PLL stable */
			while ((io_read32(tsi_base + 0x250) & 0x4) == 0)
				;

			/* Select TSI HCLK from PLL */
			io_write32(tsi_base + 0x210, (io_read32(tsi_base +
				   0x210) & ~0x7) | 0x2);
		}

		/* enable Key Store engine clock */
		io_write32(tsi_base + 0x204, io_read32(tsi_base + 0x204) |
			   (1 << 14));

		/*
		 * Initialize Key Store
		 */
		io_write32(KS_CTL, KS_CTL_INIT | KS_CTL_START);

		/* Waiting for init done */
		while ((io_read32(KS_STS) & KS_STS_INITDONE) == 0)
			;

		/* Waiting for busy cleared */
		while (io_read32(KS_STS) & KS_STS_BUSY)
			;
	}
	return TEE_SUCCESS;
}

static TEE_Result nua3500_ks_read(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   ks_base = core_mmu_get_va(KS_BASE, MEM_AREA_IO_SEC);
	uint32_t  offset, cont_msk, remain_cnt;
	uint32_t  *key_buff;
	uint32_t  i, cnt;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.a == KS_SRAM) {
		if (params[0].value.b > 31)
			return TEE_ERROR_KS_INVALID;
	} else {
		if (params[0].value.a == KS_OTP) {
			if (params[0].value.b > 9)
				return TEE_ERROR_KS_INVALID;
		} else {
			return TEE_ERROR_KS_INVALID;
		}
	}

	if (io_read32(KS_STS) & KS_STS_BUSY) {
		EMSG("KS is busy!\n");
		return TEE_ERROR_KS_BUSY;
	}

	/* Specify the key number */
	io_write32(KS_METADATA, (params[0].value.a << KS_META_DST_POS) |
		   params[0].value.b << KS_META_KNUM_POS);

	/* Clear Status */
	io_write32(KS_STS, KS_STS_EIF | KS_STS_IF);

	offset = 0;
	cont_msk = 0;
	remain_cnt = params[1].memref.size;
	key_buff = params[1].memref.buffer;

	do {
		/* Trigger to read the key */
		io_write32(KS_CTL, cont_msk | KS_OP_READ | KS_CTL_START |
			   (io_read32(KS_CTL) & KS_CLT_FUNC_MASK));

		/* Waiting for key store processing */
		while (io_read32(KS_STS) & KS_STS_BUSY)
			;

		/* Read the key to key buffer */
		cnt = 8;
		if (remain_cnt < cnt)
			cnt = remain_cnt;
		for (i = 0; i < cnt; i++) {
			key_buff[offset + i] = io_read32(KS_KEY(i));
			// EMSG("R[%d]:0x%08x\n", i, key_buff[offset + i]);
		}

		cont_msk = KS_CTL_CONT;
		remain_cnt -= cnt;
		offset += cnt;

		/* Check error flag */
		if (io_read32(KS_STS) & KS_STS_EIF)
			break;
	} while (remain_cnt > 0);

	/* Check error flag */
	if (io_read32(KS_STS) & KS_STS_EIF) {
		EMSG("KS EIF set on writing SRAM keys!\n");
		return TEE_ERROR_KS_FAIL;
	}
	return TEE_SUCCESS;
}

static TEE_Result nua3500_ks_write(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   ks_base = core_mmu_get_va(KS_BASE, MEM_AREA_IO_SEC);
	uint32_t  offset, cont_msk, buff_remain, key_wcnt;
	uint32_t  *key_buff;
	uint32_t  i, cnt;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.a == KS_OTP) {
		if (((params[0].value.b & KS_META_KNUM_MSK) >>
		    KS_META_KNUM_POS) > 8)
			return TEE_ERROR_KS_INVALID;
	} else {
		if (params[0].value.a != KS_SRAM)
			return TEE_ERROR_KS_INVALID;
	}

	if (io_read32(KS_STS) & KS_STS_BUSY) {
		EMSG("KS is busy!\n");
		return TEE_ERROR_KS_BUSY;
	}

	io_write32(KS_METADATA, (params[0].value.a << KS_META_DST_POS) |
		   params[0].value.b);

	/* Get word count of a key by indexing to size table */
	i = ((params[0].value.b & KS_META_SIZE_MSK) >> KS_META_SIZE_POS);
	key_wcnt = _keylen2wcnt[i];
	if (key_wcnt == 0) {			/* Invalid key length */
		EMSG("Invalid key length!\n");
		return TEE_ERROR_KS_INVALID;
	}

	buff_remain = params[1].memref.size;
	key_buff = params[1].memref.buffer;
	io_write32(KS_STS, KS_STS_EIF);		/* Clear error flag */
	offset = 0;
	cont_msk = 0;
	do {
		/* Prepare the key to write */
		cnt = 8;
		if (key_wcnt < cnt)
			cnt = key_wcnt;
		for (i = 0; (i < cnt) && (buff_remain > 0); i++) {
			// EMSG("w 0x%x\n", key_buff[offset + i]);
			io_write32(KS_KEY(i), key_buff[offset + i]);
			buff_remain--;
		}

		if (i < cnt) {
			EMSG("Key buffer not enough!\n");
			return TEE_ERROR_KS_INVALID;
		}

		/* Clear Status */
		io_write32(KS_STS, KS_STS_EIF | KS_STS_IF);

		/* Write the key */
		io_write32(KS_CTL, cont_msk | KS_OP_WRITE | KS_CTL_START |
			   (io_read32(KS_CTL) & KS_CLT_FUNC_MASK));

		cont_msk = KS_CTL_CONT;
		key_wcnt -= cnt;
		offset += cnt;

		/* Waiting for key store processing */
		while (io_read32(KS_STS) & KS_STS_BUSY)
			;

	} while (key_wcnt > 0);

	/* Check error flag */
	if (io_read32(KS_STS) & KS_STS_EIF) {
		EMSG("KS EIF set on writing SRAM keys!\n");
		return TEE_ERROR_KS_FAIL;
	}

	/* return key number */
	params[2].value.a = (io_read32(KS_METADATA) & KS_META_KNUM_MSK) >>
			     KS_META_KNUM_POS;
	return TEE_SUCCESS;
}

static TEE_Result nua3500_ks_erase(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   ks_base = core_mmu_get_va(KS_BASE, MEM_AREA_IO_SEC);

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.a == KS_SRAM) {
		if (params[0].value.b > 31)
			return TEE_ERROR_KS_INVALID;
	} else {
		if (params[0].value.a == KS_OTP) {
			if (params[0].value.b > 9)
				return TEE_ERROR_KS_INVALID;
		} else {
			return TEE_ERROR_KS_INVALID;
		}
	}

	if (io_read32(KS_STS) & KS_STS_BUSY) {
		EMSG("KS is busy!\n");
		return TEE_ERROR_KS_BUSY;
	}

	/* Specify the key number */
	io_write32(KS_METADATA, (params[0].value.a << KS_META_DST_POS) |
		   params[0].value.b << KS_META_KNUM_POS);

	/* Clear Status */
	io_write32(KS_STS, KS_STS_EIF | KS_STS_IF);

	/* Erase the key */
	io_write32(KS_CTL, KS_OP_ERASE | KS_CTL_START |
		   (io_read32(KS_CTL) & KS_CLT_FUNC_MASK));

	/* Waiting for processing */
	while (io_read32(KS_STS) & KS_STS_BUSY)
		;

	/* Check error flag */
	if (io_read32(KS_STS) & KS_STS_EIF) {
		EMSG("KS EIF set on erasing a key!\n");
		return TEE_ERROR_KS_FAIL;
	}
	return TEE_SUCCESS;
}

static TEE_Result nua3500_ks_erase_all(void)
{
	vaddr_t   ks_base = core_mmu_get_va(KS_BASE, MEM_AREA_IO_SEC);

	if (io_read32(KS_STS) & KS_STS_BUSY) {
		EMSG("KS is busy!\n");
		return TEE_ERROR_KS_BUSY;
	}

	io_write32(KS_METADATA, 0);

	/* Clear Status */
	io_write32(KS_STS, KS_STS_EIF | KS_STS_IF);

	/* Erase all */
	io_write32(KS_CTL, KS_OP_ERASE_ALL | KS_CTL_START |
		   (io_read32(KS_CTL) & KS_CLT_FUNC_MASK));

	/* Waiting for processing */
	while (io_read32(KS_STS) & KS_STS_BUSY)
		;

	/* Check error flag */
	if (io_read32(KS_STS) & KS_STS_EIF) {
		EMSG("KS EIF set on erase all!\n");
		return TEE_ERROR_KS_FAIL;
	}
	return TEE_SUCCESS;
}

static TEE_Result nua3500_ks_revoke(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   ks_base = core_mmu_get_va(KS_BASE, MEM_AREA_IO_SEC);

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.a == KS_SRAM) {
		if (params[0].value.b > 31)
			return TEE_ERROR_KS_INVALID;
	} else {
		if (params[0].value.a == KS_OTP) {
			if (params[0].value.b > 9)
				return TEE_ERROR_KS_INVALID;
		} else {
			return TEE_ERROR_KS_INVALID;
		}
	}

	if (io_read32(KS_STS) & KS_STS_BUSY) {
		EMSG("KS is busy!\n");
		return TEE_ERROR_KS_BUSY;
	}

	/* Specify the key number */
	io_write32(KS_METADATA, (params[0].value.a << KS_META_DST_POS) |
		   params[0].value.b << KS_META_KNUM_POS);

	/* Clear Status */
	io_write32(KS_STS, KS_STS_EIF | KS_STS_IF);

	/* Erase the key */
	io_write32(KS_CTL, KS_OP_REVOKE | KS_CTL_START |
		   (io_read32(KS_CTL) & KS_CLT_FUNC_MASK));

	/* Waiting for processing */
	while (io_read32(KS_STS) & KS_STS_BUSY)
		;

	/* Check error flag */
	if (io_read32(KS_STS) & KS_STS_EIF) {
		EMSG("KS EIF set on revoking a key!\n");
		return TEE_ERROR_KS_FAIL;
	}
	return TEE_SUCCESS;
}

static TEE_Result nua3500_ks_remain(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   ks_base = core_mmu_get_va(KS_BASE, MEM_AREA_IO_SEC);
	uint32_t  reg_data;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (io_read32(KS_STS) & KS_STS_BUSY) {
		EMSG("KS is busy!\n");
		return TEE_ERROR_KS_BUSY;
	}

	/* Clear Status */
	io_write32(KS_STS, KS_STS_EIF | KS_STS_IF);

	reg_data = io_read32(KS_REMAIN);
	params[0].value.a = (reg_data & KS_REMAIN_RRMNG_MSK) >>
			     KS_REMAIN_RRMNG_POS;
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	EMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (nCommandID) {
	case PTA_CMD_KS_INIT:
		return nua3500_ks_init();

	case PTA_CMD_KS_READ:
		return nua3500_ks_read(nParamTypes, pParams);

	case PTA_CMD_KS_WRITE:
		return nua3500_ks_write(nParamTypes, pParams);

	case PTA_CMD_KS_ERASE:
		return nua3500_ks_erase(nParamTypes, pParams);

	case PTA_CMD_KS_ERASE_ALL:
		return nua3500_ks_erase_all();

	case PTA_CMD_KS_REVOKE:
		return nua3500_ks_revoke(nParamTypes, pParams);

	case PTA_CMD_KS_REMAIN:
		return nua3500_ks_remain(nParamTypes, pParams);

	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_KS_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);

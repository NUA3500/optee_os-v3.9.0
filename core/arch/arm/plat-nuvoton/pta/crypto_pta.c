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
#include <crypto_pta.h>
#include <crypto_pta_client.h>

#define PTA_NAME "nvt_crypto.pta"

#define CRYPTO_BUSY_TIMEOUT	2000

#define nu_write_reg(reg, val)	io_write32(crypto_base + (reg), (val))
#define nu_read_reg(reg)	io_read32(crypto_base + (reg))

static bool is_timeout(TEE_Time *t_start, uint32_t timeout)
{
	TEE_Time  t_now;
	uint32_t  time_elapsed;

	tee_time_get_sys_time(&t_now);
	time_elapsed = (t_now.seconds - t_start->seconds) * 1000 +
		    (int)t_now.millis - (int)t_start->millis;

	if (time_elapsed > timeout)
		return true;
	return false;
}

static TEE_Result nua3500_crypto_init(void)
{
	vaddr_t sys_base = core_mmu_get_va(SYS_BASE, MEM_AREA_IO_NSEC);
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

		/* enable Crypto engine clock */
		io_write32(tsi_base + 0x204, io_read32(tsi_base + 0x204) |
			   (1 << 12));
	}
	return TEE_SUCCESS;
}

static TEE_Result nua3500_crypto_aes_run(uint32_t types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   crypto_base = core_mmu_get_va(CRYPTO_BASE, MEM_AREA_IO_SEC);
	uint32_t  *reg_map;
	uint32_t  i;
	TEE_Time  t_start;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(AES_STS) & AES_STS_BUSY) ||
	       (nu_read_reg(INTSTS) & (INTSTS_AESIF | INTSTS_AESEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	nu_write_reg(AES_CTL, 0);
	nu_write_reg(INTEN, nu_read_reg(INTEN) | (INTEN_AESIEN |
					INTEN_AESEIEN));
	nu_write_reg(INTSTS, (INTSTS_AESIF | INTSTS_AESEIF));

	nu_write_reg(AES_KSCTL, params[0].value.a);

	reg_map = params[1].memref.buffer;

	nu_write_reg(AES_GCM_IVCNT(0), reg_map[AES_GCM_IVCNT(0) / 4]);
	nu_write_reg(AES_GCM_IVCNT(1), 0);
	nu_write_reg(AES_GCM_ACNT(0), reg_map[AES_GCM_ACNT(0) / 4]);
	nu_write_reg(AES_GCM_ACNT(1), 0);
	nu_write_reg(AES_GCM_PCNT(0), reg_map[AES_GCM_PCNT(0) / 4]);
	nu_write_reg(AES_GCM_PCNT(1), 0);

	for (i = 0; i < 8; i++)
		nu_write_reg(AES_KEY(i), reg_map[AES_KEY(i) / 4]);

	for (i = 0; i < 4; i++)
		nu_write_reg(AES_IV(i), reg_map[AES_IV(i) / 4]);

	nu_write_reg(AES_SADDR, reg_map[AES_SADDR / 4]);
	nu_write_reg(AES_DADDR, reg_map[AES_DADDR / 4]);
	nu_write_reg(AES_CNT, reg_map[AES_CNT / 4]);

	nu_write_reg(AES_CTL, reg_map[AES_CTL / 4]);

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(AES_STS) & AES_STS_BUSY) ||
	       !(nu_read_reg(INTSTS) & (INTSTS_AESIF | INTSTS_AESEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_TIMEOUT;
	}

	nu_write_reg(INTSTS, (INTSTS_AESIF | INTSTS_AESEIF));

	for (i = 0; i < 4; i++)
		reg_map[AES_FDBCK(i) / 4] = nu_read_reg(AES_FDBCK(i));

	return TEE_SUCCESS;
}

static TEE_Result nua3500_crypto_sha_run(uint32_t types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   crypto_base = core_mmu_get_va(CRYPTO_BASE, MEM_AREA_IO_SEC);
	uint32_t  *reg_map;
	uint32_t  i;
	TEE_Time  t_start;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_time_get_sys_time(&t_start);
	while (nu_read_reg(HMAC_STS) & HMAC_STS_BUSY) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	nu_write_reg(INTEN, nu_read_reg(INTEN) | (INTEN_HMACIEN |
					INTEN_HMACEIEN));
	nu_write_reg(INTSTS, (INTSTS_HMACIF | INTSTS_HMACEIF));

	nu_write_reg(HMAC_KSCTL, params[0].value.a);

	reg_map = params[1].memref.buffer;

	nu_write_reg(HMAC_KEYCNT, reg_map[HMAC_KEYCNT / 4]);
	nu_write_reg(HMAC_SADDR, reg_map[HMAC_SADDR / 4]);
	nu_write_reg(HMAC_DMACNT, reg_map[HMAC_DMACNT / 4]);
	nu_write_reg(HMAC_FBADDR, reg_map[HMAC_FBADDR / 4]);

	nu_write_reg(HMAC_CTL, reg_map[HMAC_CTL / 4]);

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(HMAC_STS) & HMAC_STS_BUSY) ||
	       !(nu_read_reg(INTSTS) & (INTSTS_HMACIF | INTSTS_HMACEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}
	nu_write_reg(INTSTS, (INTSTS_HMACIF | INTSTS_HMACEIF));

	if (reg_map[HMAC_CTL / 4] & HMAC_CTL_DMALAST) {
		for (i = 0; i < 16; i++)
			reg_map[HMAC_DGST(i) / 4] = nu_read_reg(HMAC_DGST(i));
	}
	return TEE_SUCCESS;
}

static TEE_Result nua3500_crypto_ecc_run(uint32_t types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   crypto_base = core_mmu_get_va(CRYPTO_BASE, MEM_AREA_IO_SEC);
	uint32_t  *reg_map;
	uint32_t  i;
	TEE_Time  t_start;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(ECC_STS) & ECC_STS_BUSY) ||
	       (nu_read_reg(INTSTS) & (INTSTS_ECCIF | INTSTS_ECCEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	nu_write_reg(ECC_CTL, 0);
	nu_write_reg(INTEN, nu_read_reg(INTEN) | (INTEN_ECCIEN |
					INTEN_ECCEIEN));
	nu_write_reg(INTSTS, (INTSTS_ECCIF | INTSTS_ECCEIF));

	nu_write_reg(ECC_KSCTL, params[0].value.a);
	nu_write_reg(ECC_KSXY, params[0].value.b);

	reg_map = params[1].memref.buffer;

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_X1(i), reg_map[ECC_X1(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_Y1(i), reg_map[ECC_Y1(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_X2(i), reg_map[ECC_X2(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_Y2(i), reg_map[ECC_Y2(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_A(i), reg_map[ECC_A(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_B(i), reg_map[ECC_B(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_N(i), reg_map[ECC_N(i) / 4]);

	for (i = 0; i < ECC_KEY_WCNT; i++)
		nu_write_reg(ECC_K(i), reg_map[ECC_K(i) / 4]);

	nu_write_reg(ECC_CTL, reg_map[ECC_CTL / 4]);

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(ECC_STS) & ECC_STS_BUSY) ||
	       !(nu_read_reg(INTSTS) & (INTSTS_ECCIF | INTSTS_ECCEIF))) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	nu_write_reg(INTSTS, (INTSTS_ECCIF | INTSTS_ECCEIF));

	for (i = 0; i < ECC_KEY_WCNT; i++)
		reg_map[ECC_X1(i) / 4] = nu_read_reg(ECC_X1(i));

	for (i = 0; i < ECC_KEY_WCNT; i++)
		reg_map[ECC_Y1(i) / 4] = nu_read_reg(ECC_Y1(i));

	for (i = 0; i < ECC_KEY_WCNT; i++)
		reg_map[ECC_X2(i) / 4] = nu_read_reg(ECC_X2(i));

	for (i = 0; i < ECC_KEY_WCNT; i++)
		reg_map[ECC_Y2(i) / 4] = nu_read_reg(ECC_Y2(i));

	return TEE_SUCCESS;
}

static TEE_Result nua3500_crypto_rsa_run(uint32_t types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	vaddr_t   crypto_base = core_mmu_get_va(CRYPTO_BASE, MEM_AREA_IO_SEC);
	uint32_t  *reg_map;
	TEE_Time  t_start;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	tee_time_get_sys_time(&t_start);
	while (nu_read_reg(RSA_STS) & RSA_STS_BUSY) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}

	nu_write_reg(HMAC_CTL, 0);
	nu_write_reg(INTEN, nu_read_reg(INTEN) | (INTEN_HMACIEN |
					INTEN_HMACEIEN));
	nu_write_reg(INTSTS, (INTSTS_HMACIF | INTSTS_HMACEIF));

	nu_write_reg(RSA_KSCTL, params[0].value.a);
	nu_write_reg(RSA_KSSTS0, params[2].value.a);
	nu_write_reg(RSA_KSSTS1, params[2].value.b);

	reg_map = params[1].memref.buffer;

	nu_write_reg(RSA_SADDR0, reg_map[RSA_SADDR0 / 4]);
	nu_write_reg(RSA_SADDR1, reg_map[RSA_SADDR1 / 4]);
	nu_write_reg(RSA_SADDR2, reg_map[RSA_SADDR2 / 4]);
	nu_write_reg(RSA_SADDR3, reg_map[RSA_SADDR3 / 4]);
	nu_write_reg(RSA_SADDR4, reg_map[RSA_SADDR4 / 4]);
	nu_write_reg(RSA_DADDR, reg_map[RSA_DADDR / 4]);
	nu_write_reg(RSA_MADDR0, reg_map[RSA_MADDR0 / 4]);
	nu_write_reg(RSA_MADDR1, reg_map[RSA_MADDR1 / 4]);
	nu_write_reg(RSA_MADDR2, reg_map[RSA_MADDR2 / 4]);
	nu_write_reg(RSA_MADDR3, reg_map[RSA_MADDR3 / 4]);
	nu_write_reg(RSA_MADDR4, reg_map[RSA_MADDR4 / 4]);
	nu_write_reg(RSA_MADDR5, reg_map[RSA_MADDR5 / 4]);
	nu_write_reg(RSA_MADDR6, reg_map[RSA_MADDR6 / 4]);

	nu_write_reg(RSA_CTL, reg_map[RSA_CTL / 4]);

	tee_time_get_sys_time(&t_start);
	while ((nu_read_reg(RSA_STS) & RSA_STS_BUSY) ||
	       !(nu_read_reg(RSA_CTL) & RSA_CTL_START)) {
		if (is_timeout(&t_start, 500) == true)
			return TEE_ERROR_CRYPTO_BUSY;
	}
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (nCommandID) {
	case PTA_CMD_CRYPTO_INIT:
		return nua3500_crypto_init();

	case PTA_CMD_CRYPTO_AES_RUN:
		return nua3500_crypto_aes_run(nParamTypes, pParams);

	case PTA_CMD_CRYPTO_SHA_RUN:
		return nua3500_crypto_sha_run(nParamTypes, pParams);

	case PTA_CMD_CRYPTO_ECC_RUN:
		return nua3500_crypto_ecc_run(nParamTypes, pParams);

	case PTA_CMD_CRYPTO_RSA_RUN:
		return nua3500_crypto_rsa_run(nParamTypes, pParams);

	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_CRYPTO_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);

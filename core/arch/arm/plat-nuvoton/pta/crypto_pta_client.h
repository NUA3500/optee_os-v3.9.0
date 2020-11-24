/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 */
#ifndef __CRYPTO_PTA_CLIENT_H
#define __CRYPTO_PTA_CLIENT_H

#define PTA_CRYPTO_UUID { 0x61d3c750, 0x9e72, 0x46b6, \
		{ 0x85, 0x7c, 0x46, 0xfa, 0x51, 0x27, 0x32, 0xac } }

#define TEE_ERROR_CRYPTO_BUSY		0x00000001
#define TEE_ERROR_CRYPTO_FAIL		0x00000002
#define TEE_ERROR_CRYPTO_INVALID	0x00000003
#define TEE_ERROR_CRYPTO_TIMEOUT	0x00000004

/*
 * PTA_CMD_CRYPTO_INIT - Initialize Crypto Engine
 *
 * param[0] unused
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_CRYPTO_FAIL - Initialization failed
 */
#define PTA_CMD_CRYPTO_INIT		0x1

/*
 * PTA_CMD_CRYPTO_AES_RUN - Run AES encrypt/decrypt
 *
 * param[0] (in value) - value.a: register AES_KSCTL
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - AES encrypt/decrypt operation failed
 */
#define PTA_CMD_CRYPTO_AES_RUN		0x2

/*
 * PTA_CMD_CRYPTO_SHA_RUN - Run SHA engine
 *
 * param[0] (in value) - value.a: register HMAC_KSCTL
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - SHA operation failed
 */
#define PTA_CMD_CRYPTO_SHA_RUN		0x5

/*
 * PTA_CMD_CRYPTO_ECC_RUN - Run ECC engine
 *
 * param[0] (in value) - value.a: register ECC_KSCTL
 *                       value.b: register ECC_KSXY
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - ECC operation failed
 */
#define PTA_CMD_CRYPTO_ECC_RUN		0x8

/*
 * PTA_CMD_CRYPTO_RSA_RUN - Run RSA engine
 *
 * param[0] (in value) - value.a: register RSA_KSCTL
 * param[1] (inout memref) - memref.size: size of register map
 *                           memref.buffer: register map buffer
 * param[2] (in value) - value.a: register RSA_KSSTS0
 *                       value.b: register RSA_KSSTS1
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_CRYPTO_INVALID - Invalid input param
 * TEE_ERROR_CRYPTO_FAIL - RSA operation failed
 */
#define PTA_CMD_CRYPTO_RSA_RUN		0x10

#endif /* __CRYPTO_PTA_CLIENT_H */

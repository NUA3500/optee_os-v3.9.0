/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
 *
 */
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <tee/entry_std.h>
#include <tee/entry_fast.h>
#include <io.h>
#include <whc.h>
#include <tsi_cmd.h>

typedef struct err_code_t {
	int	code;
	char	str[32];
} ERR_CODE_T;

ERR_CODE_T _err_code_tbl[] = {
	{ ST_SUCCESS,              "ST_SUCCESS" },
	{ ST_WAIT_TSI_SYNC,        "ST_WAIT_TSI_SYNC" },
	{ ST_UNKNOWN_CMD,          "ST_UNKNOWN_CMD" },
	{ ST_NO_TSI_IMAGE,         "ST_NO_TSI_IMAGE" },
	{ ST_CMD_QUEUE_FULL,       "ST_CMD_QUEUE_FULL" },
	{ ST_TIME_OUT,             "ST_TIME_OUT" },
	{ ST_INVALID_PARAM,        "ST_INVALID_PARAM" },
	{ ST_NO_AVAIL_SESSION,     "ST_NO_AVAIL_SESSION" },
	{ ST_INVALID_SESSION_ID,   "ST_INVALID_SESSION_ID" },
	{ ST_INVALID_OPERATION,    "ST_INVALID_OPERATION"},
	{ ST_HW_NOT_READY,         "ST_HW_NOT_READY"},
	{ ST_HW_ERROR,             "ST_HW_ERROR" },
	{ ST_HW_BUSY,              "ST_HW_BUSY" },
	{ ST_HW_TIME_OUT,          "ST_HW_TIME_OUT" },
	{ ST_BUS_ERROR,            "ST_BUS_ERROR" },
	{ ST_ECC_UNKNOWN_CURVE,    "ST_ECC_UNKNOWN_CURVE" },
	{ ST_ECC_INVALID_PRIV_KEY, "ST_ECC_INVALID_PRIV_KEY" },
	{ ST_SIG_VERIFY_ERROR,     "ST_SIG_VERIFY_ERROR" },
	{ ST_KS_READ_PROTECT,      "ST_KS_READ_PROTECT"},
	{ ST_KS_FULL,              "ST_KS_FULL" },
	{ ST_WHC_TX_BUSY,          "ST_WHC_TX_BUSY" },
	{ ST_CMD_ACK_TIME_OUT,     "ST_CMD_ACK_TIME_OUT" },
};

void tsi_print_err_code(int code)
{
	uint32_t i;

	for (i = 0; i < sizeof(_err_code_tbl) / sizeof(ERR_CODE_T); i++) {
		if (_err_code_tbl[i].code == code) {
			EMSG("  [%s]\n", _err_code_tbl[i].str);
			return;
		}
	}
	EMSG("\nUnknow error code 0x%x!\n", code);
}

static int tsi_send_command(TSI_REQ_T *req)
{
	int	i;

	//t0 = get_ticks();
	for (i = 0; i < 4; i++) {
		if (WHC1->TXSTS & (1 << i))	/* Check CHxRDY */
			break;
	}

	if (i >= 4) {
		/* No WHC channel is ready for sending message */
		return ST_WHC_TX_BUSY;
	}
	
	EMSG("TSI CMD: 0x%x 0x%x 0x%x 0x%x\n", req->cmd[0], req->cmd[1],
	     req->cmd[2], req->cmd[3]);

	WHC1->TMDAT[i][0] = req->cmd[0];
	WHC1->TMDAT[i][1] = req->cmd[1];
	WHC1->TMDAT[i][2] = req->cmd[2];
	WHC1->TMDAT[i][3] = req->cmd[3];
	WHC1->TXCTL = (1 << i);	/* send message */
	req->tx_channel = i;

	//req->tx_jiffy = get_ticks();
	return 0;
}

//int tsi_wait_ack(TSI_REQ_T *req, int time_out)
static int tsi_wait_ack(TSI_REQ_T *req)
{
	int	i;

	//t0 = get_ticks();
	while (1) {
		for (i = 0; i < 4; i++) {
			if (WHC1->RXSTS & (1 << i)) {	/* Check CHxRDY */
				if ((WHC1->RMDAT[i][0] & TCK_CHR_MASK) ==
					(req->cmd[0] & TCK_CHR_MASK)) {
					req->ack[0] = WHC1->RMDAT[i][0];
					req->ack[1] = WHC1->RMDAT[i][1];
					req->ack[2] = WHC1->RMDAT[i][2];
					req->ack[3] = WHC1->RMDAT[i][3];
					WHC1->RXCTL = (1 << i);	/* set CHxACK */

					//EMSG("ACK: 0x%x 0x%x 0x%x 0x%x\n",
					// req->ack[0], req->ack[1], req->ack[2],
					// req->ack[3]);
					return 0;
				}
			}
		}
	}
}

static int tsi_send_command_and_wait(TSI_REQ_T *req, int time_out)
{
	int ret;

	if (time_out == 0)
		return -1;

	ret = tsi_send_command(req);
	if (ret != 0)
		return ret;

	//ret = tsi_wait_ack(req, time_out);
	ret = tsi_wait_ack(req);
	if (ret != 0)
		return ret;
	return TA_GET_STATUS(req);
}

/*
 * @brief    Force TSI go back to initial state.
 * @return   0            success
 * @return   otherwise    Refer to ST_XXX error code.
 */
int TSI_Sync(void)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = CMD_TSI_SYNC << 16;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Get the version of TSI firmware.
 * @param[out]  ver_code     TSI firmware version code.
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_Get_Version(uint32_t *ver_code)
{
	TSI_REQ_T req;
	int ret;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = CMD_TSI_GET_VERSION << 16;
	ret = tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
	*ver_code = req.ack[1];
	return ret;
}

/*
 * @brief    Reset TSI.
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_Reset(void)
{
	TSI_REQ_T req;
	int ret;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = CMD_TSI_RESET << 16;
	ret = tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
	return ret;
}

/*
 * @brief    Reset TSI.
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_Config_UART(uint32_t line, uint32_t baud)
{
	TSI_REQ_T req;
	int ret;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = CMD_TSI_CONFIG_UART << 16;
	req.cmd[1] = 0x11520087;
	req.cmd[2] = line;
	req.cmd[3] = baud;
	ret = tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
	return ret;
}

/*
 * @brief    Set TSI system clock.
 * @param[in]  pllsrc   0: PLL clock source from HXT; 1: PLL clock source from HIRC.
 * @param[in]  clksel   Select TSI system clock rate
 *                      0:  72 MHz
 *                      1:  96 MHz
 *                      2: 144 MHz
 *                      3: 172 MHz
 *                      4: 192 MHz
 *                      5: 224 MHz
 *                      6: 240 MHz
 * @return   0          success
 * @return   otherwise  Refer to ST_XXX error code.
 */
int TSI_Set_Clock(int pllsrc, int clksel)
{
	TSI_REQ_T req;
	int ret;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_TSI_SET_CLOCK << 16);
	if (pllsrc != 0)
		req.cmd[1] |= (1 << 3);
	req.cmd[1] |= (clksel & 0x7);

	ret = tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
	if (ret != 0)
		return ret;
	return 0;
}

/*
 * @brief    Request an encrypt/decrypt session for AES or SHA.
 * @param[in]   class_code   The command class. Should be C_CODE_AES or C_CODE_SHA.
 * @param[out]  session_id   The session ID.
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_Open_Session(int class_code, int *session_id)
{
	TSI_REQ_T req;
	int ret;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_TSI_OPEN_SESSION << 16) | class_code;
	ret = tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
	if (ret != 0)
		return ret;
	*session_id = req.ack[1] & 0xff;
	return 0;
}

/*
 * @brief    Close an opened session.
 * @param[in]   class_code   The command class. Should be C_CODE_AES or C_CODE_SHA.
 * @param[in]   session_id   The session ID.
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_Close_Session(int class_code, int session_id)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_TSI_CLOSE_SESSION << 16) | (class_code << 8) | session_id;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Configure AES encrypt/decrypt mode.
 * @param[in]  sid      The session ID obtained from TSI_Open_Session().
 * @param[in]  kinswap  1: Swap key and initial vector
 *                      0: Do not swap key and initial vector
 * @param[in]  koutswap 1: Swap feedback output
 *                      0: Do not swap AES feedback output
 * @param[in]  inswap   1: Swap input data
 *                      0: Do not swap input data
 * @param[in]  outswap  1: Swap output data
 *                      0: Do not swap output data
 * @param[in]  sm4en    1: Use SM4 cipher
 *                      0: Use AES cipher
 * @param[in]  encrypt  1: Execute encrypt operation
 *                      0: Execute decrypt operation
 * @param[in]  mode     Operation mode
 *                      - \ref AES_MODE_ECB
 *                      - \ref AES_MODE_CBC
 *                      - \ref AES_MODE_CFB
 *                      - \ref AES_MODE_OFB
 *                      - \ref AES_MODE_CTR
 *                      - \ref AES_MODE_CBC_CS1
 *                      - \ref AES_MODE_CBC_CS2
 *                      - \ref AES_MODE_CBC_CS3
 *                      - \ref AES_MODE_GCM
 *                      - \ref AES_MODE_GHASH
 *                      - \ref AES_MODE_CCM
 * @param[in]  keysz    Key size
 *                      - \ref AES_KEY_SIZE_128
 *                      - \ref AES_KEY_SIZE_192
 *                      - \ref AES_KEY_SIZE_256
 * @param[in]  ks       Key source
 *                      SEL_KEY_FROM_REG:      Key is assigned by AES_Set_Key
 *                      SEL_KEY_FROM_KS_SRAM:  Key is from TSI Key Store SRAM
 *                      SEL_KEY_FROM_KS_OTP:   Key is from TSI Key Store OTP
 * @param[in]  ks_num   Key Store key number
 * @return   0          success
 * @return   otherwise  Refer to ST_XXX error code.
 */
int TSI_AES_Set_Mode(int sid, int kinswap, int koutswap, int inswap,
		     int outswap, int sm4en, int encrypt, int mode, int keysz,
		     int ks, int ks_num)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_AES_SET_MODE << 16) | sid;
	req.cmd[1] = (kinswap << 25) | (koutswap << 24) | (inswap << 23) |
			 (outswap << 22) | (sm4en << 17) | (encrypt << 16) |
			 (mode << 8) | (keysz << 2);
	req.cmd[2] = (ks << 5) | ks_num;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Set AES/SM4 initial vector.
 * @param[in]  sid           The session ID obtained from TSI_Open_Session().
 * @param[in]  iv_addr       Address of the buffer for initial vector
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_AES_Set_IV(int sid, uint32_t iv_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_AES_SET_IV << 16) | sid;
	req.cmd[1] = iv_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Set AES/SM4 initial vector.
 * @param[in]  sid           The session ID obtained from TSI_Open_Session().
 * @param[in]  keysz         Key size
 *                           - \ref AES_KEY_SIZE_128
 *                           - \ref AES_KEY_SIZE_192
 *                           - \ref AES_KEY_SIZE_256
 * @param[in]  key_addr       Address of the buffer for AES/SM4 key
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_AES_Set_Key(int sid, int keysz, uint32_t key_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_AES_SET_KEY << 16) | sid;

	if (keysz == AES_KEY_SIZE_128)
		req.cmd[1] = 4;
	else if (keysz == AES_KEY_SIZE_192)
		req.cmd[1] = 6;
	else
		req.cmd[1] = 8;

	req.cmd[2] = key_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Start AES encrypt/decrypt.
 * @param[in]  sid           The session ID obtained from TSI_Open_Session().
 * @param[in]  is_last       1: Is the last run of this AES/SM4 session.
 *                           0: Is not the last session.
 * @param[in]  data_cnt      AES/SM4 encrypt/decrypt data count in bytes
 * @param[in]  src_addr      DMA input data address
 * @param[in]  dest_addr     DMA output data address
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_AES_Run(int sid, int is_last, int data_cnt, uint32_t src_addr,
		uint32_t dest_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_AES_RUN << 16) | sid;
	req.cmd[1] = (is_last << 24) | data_cnt;
	req.cmd[2] = src_addr;
	req.cmd[3] = dest_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Start AES encrypt/decrypt.
 * @param[in]  sid           The session ID obtained from TSI_Open_Session().
 * @param[in]  is_last       1: Is the last run of this AES/SM4 session.
 *                           0: Is not the last session.
 * @param[in]  data_cnt      AES/SM4 encrypt/decrypt data count in bytes
 * @param[in]  src_addr      DMA input data address
 * @param[in]  dest_addr     DMA output data address
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_AES_GCM_Run(int sid, int is_last, int data_cnt, uint32_t param_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_AES_GCM_RUN << 16) | sid;
	req.cmd[1] = (is_last << 24) | data_cnt;
	req.cmd[2] = param_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Read or write AES/SM4 intermediate feedback data.
 * @param[in]  sid           The session ID obtained from TSI_Open_Session().
 * @param[in]  rw            1: write feedback data
 *                           0: read feedback data
 * @param[in]  wcnt          Word count of feedback data
 * @param[in]  fdbck_addr    Feedback data address
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_Access_Feedback(int sid, int rw, int wcnt, uint32_t fdbck_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_AES_ACCESS_FEEDBACK << 16) | sid;
	req.cmd[1] = (rw << 7) | wcnt;
	req.cmd[2] = fdbck_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Start to process the first block of a SHA session.
 * @param[in]  sid      The session ID obtained from TSI_Open_Session().
 * @param[in]  inswap   1: Swap input data
 *                      0: Do not swap input data
 * @param[in]  outswap  1: Swap output data
 *                      0: Do not swap output data
 * @param[in]  mode_sel SHA engine mode
 *                      - \ref SHA_MODE_SEL_SHA1
 *                      - \ref SHA_MODE_SEL_SHA2
 *                      - \ref SHA_MODE_SEL_SHA3
 *                      - \ref SHA_MODE_SEL_SM3
 *                      - \ref SHA_MODE_SEL_MD5
 * @param[in]  hmac     1: Use HMAC key
 *                      0: No HMAC
 * @param[in]  mode     Operation mode
 *                      - \ref SHA_MODE_SHA1
 *                      - \ref SHA_MODE_SHA224
 *                      - \ref SHA_MODE_SHA256
 *                      - \ref SHA_MODE_SHA384
 *                      - \ref SHA_MODE_SHA512
 *                      - \ref SHA_MODE_SHAKE128
 *                      - \ref SHA_MODE_SHAKE256
 * @param[in]  keylen   HMAC key length in bytes. Only effective when <hmac> is 1.
 * @param[in]  ks       Key source
 *                      SEL_KEY_FROM_REG:      HMAC key is from TSI_SHA_Update()
 *                      SEL_KEY_FROM_KS_SRAM:  HMAC key is from TSI Key Store SRAM
 *                      SEL_KEY_FROM_KS_OTP:   HMAC key is from TSI Key Store OTP
 * @param[in]  ks_num   Key Store key number
 * @return   0          success
 * @return   otherwise  Refer to ST_XXX error code.
 */
int TSI_SHA_Start(int sid, int inswap, int outswap, int mode_sel, int hmac,
		  int mode, int keylen, int ks, int ks_num)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_SHA_START << 16) | sid;
	req.cmd[1] = (inswap << 23) | (outswap << 22) | (mode_sel << 12) |
			(hmac << 11) | (mode << 8);
	req.cmd[2] = keylen;
	req.cmd[3] = (ks << 5) | ks_num;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Update SHA data.
 * @param[in]  sid           The session ID obtained from TSI_Open_Session().
 * @param[in]  data_cnt      byte count of input data
 * @param[in]  src_addr      Address of input data
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_SHA_Update(int sid, int data_cnt, uint32_t src_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_SHA_UPDATE << 16) | sid;
	req.cmd[1] = data_cnt;
	req.cmd[2] = src_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Update the last block of data and get result digest.
 * @param[in]  sid           The session ID obtained from TSI_Open_Session().
 * @param[in]  wcnt          Word count of output digest
 * @param[in]  data_cnt      Byte count of input data
 * @param[in]  src_addr      Address of input data
 * @param[in]  dest_addr     Address of output digest
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_SHA_Finish(int sid, int wcnt, int data_cnt, uint32_t src_addr,
		   uint32_t dest_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_SHA_FINISH << 16) | sid;
	req.cmd[1] = (wcnt << 24) | data_cnt;
	req.cmd[2] = src_addr;
	req.cmd[3] = dest_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Run SHA all at once.
 * @param[in]  inswap        1: Swap input data
 *                           0: Do not swap input data
 * @param[in]  outswap       1: Swap output data
 *                           0: Do not swap output data
 * @param[in]  mode_sel      SHA engine mode
 *                           - \ref SHA_MODE_SEL_SHA1
 *                           - \ref SHA_MODE_SEL_SHA2
 *                           - \ref SHA_MODE_SEL_SHA3
 *                           - \ref SHA_MODE_SEL_SM3
 *                           - \ref SHA_MODE_SEL_MD5
 * @param[in]  mode          Operation mode
 *                           - \ref SHA_MODE_SHA1
 *                           - \ref SHA_MODE_SHA224
 *                           - \ref SHA_MODE_SHA256
 *                           - \ref SHA_MODE_SHA384
 *                           - \ref SHA_MODE_SHA512
 *                           - \ref SHA_MODE_SHAKE128
 *                           - \ref SHA_MODE_SHAKE256
 * @param[in]  wcnt          Word count of output digest
 * @param[in]  data_cnt      Byte count of input data
 * @param[in]  src_addr      Address of input data
 * @param[in]  dest_addr     Address of output digest
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_SHA_All_At_Once(int inswap, int outswap, int mode_sel, int mode,
			int wcnt, int data_cnt, uint32_t src_addr,
			uint32_t dest_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_SHA_ALL_AT_ONCE << 16) | ((data_cnt >> 8) & 0xffff);
	req.cmd[1] = ((data_cnt & 0xff) << 24) | (inswap << 23) | (outswap << 22) |
			(mode_sel << 12) | (mode << 8) | wcnt;
	req.cmd[2] = src_addr;
	req.cmd[3] = dest_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Generate an ECC public key.
 * @param[in]  curve_id      ECC curve ID
 * @param[in]  is_ecdh       Only used when psel is ECC_KEY_SEL_KS_SRAM.
 *                           0: is not ECDH key.
 *                           1: is ECDH key.
 * @param[in]  psel          Select private key source
 *                           ECC_KEY_SEL_TRNG    : Private key is generated by TRNG
 *                           ECC_KEY_SEL_KS_OTP  : Private Key is from Key Store OTP
 *                           ECC_KEY_SEL_KS_SRAM : Private Key is from Key Store SRAM
 *                           ECC_KEY_SEL_USER    : User defined private key
 * @param[in]  d_knum        The Key Store key index. Effective only when <psel>
 *                           is 0x01 or 0x02.
 * @param[in]  priv_key      Address of input private key. Effective only when
 *                           <psel> is 0x03.
 * @param[in]  pub_key       Address of the output public key.
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_ECC_GenPublicKey(int curve_id, int is_ecdh, int psel,
			 int d_knum, uint32_t priv_key, uint32_t pub_key)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_ECC_GEN_PUB_KEY << 16) | curve_id;
	req.cmd[1] = (is_ecdh << 10) | (psel << 8) | d_knum;
	req.cmd[2] = priv_key;
	req.cmd[3] = pub_key;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Generate an ECC signature.
 * @param[in]  curve_id      ECC curve ID
 * @param[in]  rsel          0: Random number is generated by TSI TRNG
 *                           1: Use the random number specified in parameter block.
 * @param[in]  psel          Select private key source
 *                           ECC_KEY_SEL_TRNG    : Private key is generated by TRNG
 *                           ECC_KEY_SEL_KS_OTP  : Private Key is from Key Store OTP
 *                           ECC_KEY_SEL_KS_SRAM : Private Key is from Key Store SRAM
 *                           ECC_KEY_SEL_USER    : User defined private key
 * @param[in]  d_knum        The Key Store key index. Effective only when <psel>
 *                           is 0x01 or 0x02.
 * @param[in]  param_addr    Address of the input parameter block, including message
 *                           and private key.
 *                           The private key in parameter block is effective only
 *                           when <psel> is 0x03.
 * @param[in]  sig_addr      Address of the output signature.
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_ECC_GenSignature(int curve_id, int rsel, int psel, int d_knum,
			 uint32_t param_addr, uint32_t sig_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_ECC_GEN_SIG << 16) | curve_id;
	req.cmd[1] = (rsel << 10) | (psel << 8) | d_knum;
	req.cmd[2] = param_addr;
	req.cmd[3] = sig_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Generate an ECC signature.
 * @param[in]  curve_id      ECC curve ID
 * @param[in]  psel          Select public key source
 *                           ECC_KEY_SEL_KS_OTP : Public key is from Key Store OTP
 *                           ECC_KEY_SEL_KS_SRAM: Public key is from Key Store SRAM
 *                           ECC_KEY_SEL_USER   : Public key is from parameter block
 * @param[in]  x_knum        The Key Store key number of public key X. Effective
 *                           only when <psel> is 0x01 or 0x02.
 * @param[in]  y_knum        The Key Store key number of public key Y. Effective only
 *                           when <psel> is 0x01 or 0x02.
 * @param[in]  param_addr    Address of the input parameter block.
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_ECC_VerifySignature(int curve_id, int psel, int x_knum,
			    int y_knum, uint32_t param_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_ECC_VERIFY_SIG << 16) | curve_id;
	req.cmd[1] = (psel << 16) | (y_knum << 8) | x_knum;
	req.cmd[2] = param_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

/*
 * @brief    Execute ECC point multiplication.
 * @param[in]  curve_id      ECC curve ID
 * @param[in]  type          Type of multipler k. 0x1: is ECDH key
 * @param[in]  msel          Select the source of multiplier
 *                           0x1: Multiplier is from Key Store OTP
 *                           0x2: Multiplier is from Key Store SRAM
 *                           0x3: Multiplier is from parameter block
 * @param[in]  sps           Select the source of input point
 *                           0x1: Input point is from Key Store OTP
 *                           0x2: Input point is from Key Store SRAM
 *                           0x3: Input point is from parameter block
 * @param[in]  m_knum        The Key Store key number of multiplier.
 *                            Used only when <ms> is 0x01 or 0x02.
 * @param[in]  x_knum        The Key Store key number of input point X.
 *                           Effective only when <msel> is 0x01 or 0x02.
 * @param[in]  y_knum        The Key Store key number of input point Y.
 *                           Effective only when <msel> is 0x01 or 0x02.
 * @param[in]  param_addr    Address of the input parameter block.
 * @param[in]  dest_addr     Address of the output ECC point.
 * @return   0               success
 * @return   otherwise       Refer to ST_XXX error code.
 */
int TSI_ECC_Multiply(int curve_id, int type, int msel, int sps,
		     int m_knum, int x_knum, int y_knum, uint32_t param_addr,
		     uint32_t dest_addr)
{
	TSI_REQ_T req;

	memset(&req, 0, sizeof(req));
	req.cmd[0] = (CMD_ECC_MULTIPLY << 16) | curve_id;
	req.cmd[1] = (type << 28) | (msel << 26) | (sps << 24) | (m_knum << 16) |
			(x_knum << 8) | (y_knum);
	req.cmd[2] = param_addr;
	req.cmd[3] = dest_addr;
	return tsi_send_command_and_wait(&req, CMD_TIME_OUT_2S);
}

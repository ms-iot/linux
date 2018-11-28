/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * Author: Jiri Appl <jiria@microsoft.com>
 *
 * OP-TEE fTPM TA TPM driver
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 */

#include <linux/tee_drv.h>

#include "tpm.h"

#define TEEC_CONFIG_PAYLOAD_REF_COUNT 4
#define TEEC_LOGIN_PUBLIC             0x00000000
#define TEEC_SUCCESS                  0x00000000

#define FTPM_OPTEE_TA_SUBMIT_COMMAND  0

#define FTPM_RESPONSE_SIZE_MAX        TPM_BUFSIZE
#define FTPM_SHM_SIZE                 (TPM_BUFSIZE + FTPM_RESPONSE_SIZE_MAX)

struct tpm_tee_context 
{
	struct tpm_chip *chip;

	size_t response_offset;
	size_t response_length;

	struct tee_shm *shm;

	struct tee_context *optee_context;

	bool optee_session_opened;
	u32 optee_session_id;

	bool chip_registered;
};

static struct tpm_tee_context tpm_tee_context = { 0 };

static int ftpm_optee_tpm_op_recv(struct tpm_chip *chip, u8 *buf, size_t len)
{
	size_t response_length;
	int rc;

	response_length = tpm_tee_context.response_length;
	if (len < response_length) {
		rc = -EIO;
		goto cleanup;
	}

	memcpy(
		buf, 
		tpm_tee_context.shm->kaddr + tpm_tee_context.response_offset, 
		tpm_tee_context.response_length);

	tpm_tee_context.response_length = 0;

	rc = response_length;

cleanup:
	return rc;
}

static int ftpm_optee_tpm_op_send(struct tpm_chip *chip, u8 *buf, size_t len)
{
	int rc = 0;
	size_t response_length;
	u8* response_buffer;
	struct tpm_output_header* response_header;
	struct tee_param submit_command_params[TEEC_CONFIG_PAYLOAD_REF_COUNT] = {
		{ .attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT },
		{ .attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT },
		{ .attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE },
		{ .attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE }
	};
	struct tee_ioctl_invoke_arg submit_command_args;

	if (len > (FTPM_SHM_SIZE - FTPM_RESPONSE_SIZE_MAX)) {
		rc = -EIO;
		goto cleanup;
	}

	tpm_tee_context.response_offset = len;
	tpm_tee_context.response_length = 0;
	memset(tpm_tee_context.shm->kaddr, 0, FTPM_SHM_SIZE);

	submit_command_args.func = FTPM_OPTEE_TA_SUBMIT_COMMAND;
	submit_command_args.session = tpm_tee_context.optee_session_id;
	submit_command_args.num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;

	// request
	submit_command_params[0].u.memref.size = len;
	submit_command_params[0].u.memref.shm = tpm_tee_context.shm;
	submit_command_params[0].u.memref.shm_offs = 0;
	memcpy(submit_command_params[0].u.memref.shm->kaddr, buf, len);

	// response
	submit_command_params[1].u.memref.size = FTPM_RESPONSE_SIZE_MAX;
	submit_command_params[1].u.memref.shm = tpm_tee_context.shm;
	submit_command_params[1].u.memref.shm_offs = tpm_tee_context.response_offset;

	rc = tee_client_invoke_func(
		tpm_tee_context.optee_context, 
		&submit_command_args, 
		submit_command_params);
	if (rc || submit_command_args.ret) {
		rc = rc ? rc : submit_command_args.ret;
		goto cleanup;
	}

	response_buffer = submit_command_params[1].u.memref.shm->kaddr + 
		submit_command_params[1].u.memref.shm_offs;
	response_header = (struct tpm_output_header*)response_buffer;
	response_length = be32_to_cpu(response_header->length);

	if (response_length > FTPM_RESPONSE_SIZE_MAX) {
		rc = -EIO;
		goto cleanup;
	}

	tpm_tee_context.response_length = response_length;

cleanup:
	return rc;
}

static void ftpm_optee_tpm_op_cancel(struct tpm_chip *chip)
{
	// unnecessary
	return;
}

static u8 ftpm_optee_tpm_op_status(struct tpm_chip *chip)
{
	// unnecessary
	return 0;
}

static bool ftpm_optee_tpm_req_canceled(struct tpm_chip *chip, u8 status)
{
	// unnecessary
	return 0;
}

static const struct tpm_class_ops ftpm_optee_tpm_ops = {
	.flags = TPM_OPS_AUTO_STARTUP,
	.req_complete_mask = 0,
	.req_complete_val = 0,
	.recv = ftpm_optee_tpm_op_recv,
	.send = ftpm_optee_tpm_op_send,
	.cancel = ftpm_optee_tpm_op_cancel,
	.status = ftpm_optee_tpm_op_status,
	.req_canceled = ftpm_optee_tpm_req_canceled
};

static void ftpm_optee_cleanup(void)
{
	if (tpm_tee_context.chip_registered)
		tpm_chip_unregister(tpm_tee_context.chip);

	if (tpm_tee_context.chip != NULL)
		put_device(&tpm_tee_context.chip->dev);

	if (tpm_tee_context.optee_context != NULL)	{
		if (tpm_tee_context.optee_session_opened) {
			tee_client_close_session(
				tpm_tee_context.optee_context, 
				tpm_tee_context.optee_session_id);
			tpm_tee_context.optee_session_opened = FALSE;
		}

		if (tpm_tee_context.shm) {
			tee_shm_free(tpm_tee_context.shm);
			tpm_tee_context.shm = NULL;
		}

		tee_client_close_context(tpm_tee_context.optee_context);
		tpm_tee_context.optee_context = NULL;
	}
}

static int ftpm_optee_match_func(
	struct tee_ioctl_version_data *version,
	const void * data)
{
	if (version->impl_id == TEE_OPTEE_CAP_TZ &&
		version->impl_caps == TEE_IMPL_ID_OPTEE &&
		version->gen_caps == TEE_GEN_CAP_GP)
		return 1;

	return 0;
}

static int __init ftpm_optee_module_init(void)
{
	int rc;
	struct tee_context *optee_context;
	struct tee_shm *shm;
	struct tpm_chip *chip;

	// bc50d971-d4c9-42c4-82cb-343fb7f37896	
	struct tee_ioctl_open_session_arg open_session_args = {
		.uuid = { 0xbc, 0x50, 0xd9, 0x71, 
			0xd4, 0xc9, 0x42, 0xc4, 
			0x82, 0xcb, 0x34, 0x3f, 
			0xb7, 0xf3, 0x78, 0x96 },
		.clnt_login = TEE_IOCTL_LOGIN_PUBLIC,
		.num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT
	};

	struct tee_param open_session_params[TEEC_CONFIG_PAYLOAD_REF_COUNT] = {
		{ .attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE },
		{ .attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE },
		{ .attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE },
		{ .attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE }
	};

	optee_context = tee_client_open_context(
		NULL, 
		ftpm_optee_match_func, 
		NULL,
		NULL);

	if (IS_ERR(optee_context))	{
		rc = PTR_ERR(optee_context);
		goto cleanup;
	}
	tpm_tee_context.optee_context = optee_context; 

	shm = tee_shm_alloc(
		tpm_tee_context.optee_context, 
		FTPM_SHM_SIZE, 
		TEE_SHM_MAPPED | TEE_SHM_DMA_BUF);

	if (IS_ERR(shm)) {
		rc = PTR_ERR(shm);
		goto cleanup;
	}
	tpm_tee_context.shm = shm;

	rc = tee_client_open_session(
		tpm_tee_context.optee_context, 
		&open_session_args, 
		open_session_params);

	if (rc != TEEC_SUCCESS)	{
		rc = -EPERM;
		goto cleanup;
	}

	tpm_tee_context.optee_session_opened = TRUE;
	tpm_tee_context.optee_session_id = open_session_args.session;

	chip = tpm_chip_alloc(NULL, &ftpm_optee_tpm_ops);
	if (IS_ERR(chip)) {
		rc = PTR_ERR(chip);
		goto cleanup;
	}
	tpm_tee_context.chip = chip;

	tpm_tee_context.chip->flags |= TPM_CHIP_FLAG_TPM2;

	rc = tpm_chip_register(tpm_tee_context.chip);
	if (rc)
		goto cleanup;
	
	tpm_tee_context.chip_registered = TRUE;

cleanup:
	if (rc)
		ftpm_optee_cleanup();

	return rc;
}

static void __exit ftpm_optee_module_exit(void)
{
	ftpm_optee_cleanup();
}

module_init(ftpm_optee_module_init);
module_exit(ftpm_optee_module_exit);

MODULE_AUTHOR("Jiri Appl (jiria@microsoft.com)");
MODULE_DESCRIPTION("fTPM OP-TEE TA Driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");

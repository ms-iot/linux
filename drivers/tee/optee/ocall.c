// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Microsoft Corporation
 *
 * The object used to hold OCALL context is struct optee_call_ctx, which lives
 * inside struct optee_session. The latter carries a binary semaphore. All
 * functions in this file, unless otherwise noted, assume that their caller
 * holds the semaphore for the given session when the functions take a session
 * as a parameter, or for the given calling context's parent session when the
 * functions take a pointer to the embedded calling context.
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include "optee_private.h"

static void optee_ocall_inc_memrefs_refcount(struct tee_param *params,
					     u32 num_params,
					     struct optee_call_ctx *call_ctx)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		struct tee_shm *shm;
		struct tee_param *p = params + n;

		if (!tee_param_is_memref(p))
			continue;

		shm = p->u.memref.shm;
		if (!shm->ocall_link.next) {
			list_add(&p->u.memref.shm->ocall_link,
				 &call_ctx->list_shm);
			tee_shm_get(p->u.memref.shm);
		}
	}
}

static void optee_ocall_dec_memrefs_refcount(struct tee_param *params,
					     u32 num_params,
					     struct optee_call_ctx *call_ctx)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		struct tee_shm *shm;
		struct tee_param *p = params + n;

		if (!tee_param_is_memref(p))
			continue;

		shm = p->u.memref.shm;
		if (shm->ocall_link.next) {
			tee_shm_put(p->u.memref.shm);
			list_del(&p->u.memref.shm->ocall_link);

			/*
			 * Set the list entry to NULL to avoid depending on
			 * internal poison values being kept as-is in the
			 * future. Note that this prevents the list debug
			 * mechanism (CONFIG_DEBUG_LIST=y) from doing its job.
			 */
			memset(&p->u.memref.shm->ocall_link, 0,
			       sizeof(p->u.memref.shm->ocall_link));
		}
	}
}

void optee_ocall_prologue(struct optee_call_ctx *call_ctx)
{
	struct optee *optee = tee_get_drvdata(call_ctx->ctx->teedev);

	optee_cq_wait_init(&optee->call_queue, &call_ctx->waiter);
}

void optee_ocall_epilogue(struct optee_call_ctx *call_ctx)
{
	struct optee *optee = tee_get_drvdata(call_ctx->ctx->teedev);

	optee_rpc_finalize_call(call_ctx);
	optee_cq_wait_final(&optee->call_queue, &call_ctx->waiter);
}

void optee_ocall_cancel(struct optee_call_ctx *call_ctx)
{
	int rc;
	struct tee_shm *shm;

	rc = optee_do_call_with_ctx(call_ctx);
	if (rc == -EAGAIN)
		pr_warn("received an OCALL while cancelling an OCALL");

	tee_shm_free(call_ctx->msg_shm);

	list_for_each_entry(shm, &call_ctx->list_shm, ocall_link)
		tee_shm_put(shm);
	optee_ocall_epilogue(call_ctx);

	if (call_ctx->cancel_cb)
		call_ctx->cancel_cb(call_ctx);
}

void optee_ocall_cancel_with_code(struct optee_call_ctx *call_ctx, u32 code)
{
	call_ctx->rpc_arg->ret = code;
	call_ctx->rpc_arg->ret_origin = TEEC_ORIGIN_COMMS;
	optee_ocall_cancel(call_ctx);
}

void optee_ocall_notify_session_close(struct optee_session *session)
{
	if (session->call_ctx.rpc_shm)
		optee_ocall_cancel_with_code(&session->call_ctx,
					     TEEC_ERROR_TARGET_DEAD);
}

/*
 * Callers need not hold any semaphores, this function acquires and releases
 * them as needed.
 */
void optee_ocall_notify_context_release(struct tee_context *ctx)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct optee_session *sess;

	if (!ctxdata)
		return;

	mutex_lock(&ctxdata->mutex);
	list_for_each_entry(sess, &ctxdata->sess_list, list_node) {
		if (sess->call_ctx.rpc_shm) {
			down(&sess->sem);
			optee_ocall_cancel_with_code(&sess->call_ctx,
						     TEEC_ERROR_TARGET_DEAD);
			up(&sess->sem);
		}
	}
	mutex_unlock(&ctxdata->mutex);
}

int optee_ocall_process_request(struct tee_ioctl_invoke_arg *arg,
				struct tee_param *params, u32 num_params,
				struct tee_param *ocall,
				struct optee_call_ctx *call_ctx)
{
	struct tee_shm *shm;
	size_t shm_sz;

	struct optee_msg_param *msg_param;
	u32 msg_num_params;
	u64 func;

	int rc = 0;

	/*
	 * Points to the octets of the UUID corresponding to the TA requesting
	 * the OCALL, if applicable for this call.
	 */
	void *clnt_id;

	/* Verify that we are able to handle this request */
	switch (call_ctx->rpc_arg->cmd) {
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		if (num_params < 1) {
			rc = -EINVAL;
			goto exit_set_ret;
		}
		break;
	case OPTEE_MSG_RPC_CMD_OCALL:
		/* Checked below */
		break;
	default:
		rc = -EINVAL;
		goto exit_set_ret;
	}

	/* Clear out the parameters of the original function invocation */
	memset(params, 0, num_params * sizeof(*params));

	/* Set up the OCALL request */
	switch (call_ctx->rpc_arg->cmd) {
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		ocall->u.value.a = TEE_IOCTL_OCALL_CMD_SHM_ALLOC;

		shm_sz = call_ctx->rpc_arg->params[0].u.value.b;
		params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
		params[0].u.value.a = 0;
		params[0].u.value.b = shm_sz;
		params[0].u.value.c = 0;
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		ocall->u.value.a = TEE_IOCTL_OCALL_CMD_SHM_FREE;

		shm = (struct tee_shm *)(uintptr_t)
			call_ctx->rpc_arg->params[0].u.value.b;
		params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT;
		params[0].u.value.a = tee_shm_get_id(shm);
		params[0].u.value.b = 0;
		params[0].u.value.c = 0;
		break;
	case OPTEE_MSG_RPC_CMD_OCALL:
		func = call_ctx->rpc_arg->params[0].u.value.a;
		if (func > U32_MAX) {
			rc = -EINVAL;
			goto exit_set_ret;
		}

		msg_num_params = call_ctx->rpc_arg->num_params - 2;
		if (num_params < msg_num_params) {
			rc = -EINVAL;
			goto exit_set_ret;
		}

		msg_param = call_ctx->rpc_arg->params + 2;
		rc = optee_from_msg_param(params, msg_num_params, msg_param);
		if (rc)
			goto exit_set_ret;

		optee_ocall_inc_memrefs_refcount(params, msg_num_params,
						 call_ctx);

		ocall->u.value.a = TEE_IOCTL_OCALL_CMD_INVOKE;

		arg->func = (u32)func;
		clnt_id = &call_ctx->rpc_arg->params[1].u.value;
		memcpy(&ocall->u.value.b, clnt_id, TEE_IOCTL_UUID_LEN);
		break;
	default:
		/* NOT REACHED */
		rc = -EINVAL;
		goto exit_set_ret;
	}

	arg->ret = TEEC_SUCCESS;
	arg->ret_origin = TEEC_ORIGIN_COMMS;

	return rc;

exit_set_ret:
	call_ctx->rpc_arg->ret = TEEC_ERROR_BAD_PARAMETERS;
	call_ctx->rpc_arg->ret_origin = TEEC_ORIGIN_COMMS;
	return rc;
}

int optee_ocall_process_reply(struct tee_ioctl_invoke_arg *arg,
			      struct tee_param *params, u32 num_params,
			      struct tee_param *ocall,
			      struct optee_call_ctx *call_ctx)
{
	void *shm_pages_list;
	struct tee_shm *shm;
	u64 shm_id;

	struct optee_msg_param *msg_param;
	u32 msg_num_params;

	int rc = 0;

	switch (tee_param_get_ocall_func(ocall)) {
	case TEE_IOCTL_OCALL_CMD_SHM_ALLOC:
		if (arg->ret != TEEC_SUCCESS)
			goto exit_propagate_ret;

		if (num_params < 1) {
			rc = -EINVAL;
			goto exit_set_ret;
		}

		shm_id = params[0].u.value.a;
		if (shm_id > INT_MAX) {
			rc = -EINVAL;
			goto exit_set_ret;
		}

		shm = tee_shm_get_from_id(call_ctx->ctx, (int)shm_id);
		if (IS_ERR(shm)) {
			rc = PTR_ERR(shm);
			goto exit_set_ret;
		}

		rc = optee_rpc_process_shm_alloc(shm, call_ctx->rpc_arg->params,
						 &shm_pages_list);

		/* The CA holds a reference */
		tee_shm_put(shm);

		if (rc)
			goto exit_set_ret;

		if (shm_pages_list)
			optee_free_pages_list(shm_pages_list, shm->num_pages);
		break;
	case TEE_IOCTL_OCALL_CMD_SHM_FREE:
		if (arg->ret != TEEC_SUCCESS)
			goto exit_propagate_ret;
		break;
	case TEE_IOCTL_OCALL_CMD_INVOKE:
		if (arg->ret_origin != TEEC_ORIGIN_CLIENT_APP)
			goto exit_propagate_ret;

		msg_num_params = call_ctx->rpc_arg->num_params - 2;
		if (num_params < msg_num_params) {
			rc = -EINVAL;
			goto exit_set_ret;
		}

		msg_param = call_ctx->rpc_arg->params + 2;
		rc = optee_to_msg_param(msg_param, msg_num_params, params);
		if (rc)
			goto exit_set_ret;

		optee_ocall_dec_memrefs_refcount(params, msg_num_params,
						 call_ctx);

		call_ctx->rpc_arg->params[0].u.value.b = arg->ret;
		call_ctx->rpc_arg->params[0].u.value.c = arg->ret_origin;
		break;
	default:
		rc = -EINVAL;
		goto exit_set_ret;
	}

	call_ctx->rpc_arg->ret = TEEC_SUCCESS;
	call_ctx->rpc_arg->ret_origin = TEEC_ORIGIN_COMMS;

	return rc;

exit_propagate_ret:
	call_ctx->rpc_arg->ret = arg->ret;
	call_ctx->rpc_arg->ret_origin = arg->ret_origin;
	return -EINVAL;
exit_set_ret:
	call_ctx->rpc_arg->ret = TEEC_ERROR_BAD_PARAMETERS;
	call_ctx->rpc_arg->ret_origin = TEEC_ORIGIN_COMMS;
	return rc;
}

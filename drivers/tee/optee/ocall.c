// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Microsoft Corporation
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

	mutex_lock(&call_ctx->mutex);
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
	mutex_unlock(&call_ctx->mutex);
}

static void optee_ocall_dec_memrefs_refcount(struct tee_param *params,
					     u32 num_params,
					     struct optee_call_ctx *call_ctx)
{
	size_t n;

	mutex_lock(&call_ctx->mutex);
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
	mutex_unlock(&call_ctx->mutex);
}

static void optee_ocall_cancel_worker(struct optee_call_ctx *call_ctx)
{
	int rc;
	struct tee_shm *shm;

	if (call_ctx->cancel_code != U32_MAX) {
		call_ctx->rpc_arg->ret = call_ctx->cancel_code;
		call_ctx->rpc_arg->ret_origin = TEEC_ORIGIN_COMMS;
	}

	rc = optee_do_call_with_ctx(call_ctx);
	if (rc == -EINTR)
		pr_warn("cancellation of OCALL was marked as cancelled");
	else if (rc == -EAGAIN)
		pr_warn("received an OCALL while cancelling an OCALL");

	call_ctx->cancelled = true;

	optee_ocall_epilogue(call_ctx);

	list_for_each_entry(shm, &call_ctx->list_shm, ocall_link)
		tee_shm_put(shm);

	if (call_ctx->cancel_cb)
		call_ctx->cancel_cb(call_ctx);
}

static void optee_ocall_finalize(struct optee_context_data *ctxdata,
				 struct optee_call_ctx *call_ctx)
{
	atomic_set(&call_ctx->attached, false);
	idr_remove(&ctxdata->ocalls, call_ctx->id);

	mutex_lock(&call_ctx->mutex);
	optee_ocall_cancel_with_code(call_ctx, TEEC_ERROR_TARGET_DEAD);
	mutex_unlock(&call_ctx->mutex);

	optee_ocall_ctx_put(call_ctx);
}

static void optee_ocall_ctx_destroy(struct optee_call_ctx *call_ctx)
{
	struct optee_context_data *ctxdata = call_ctx->ctx->data;

	if (atomic_cmpxchg(&call_ctx->attached, true, false)) {
		mutex_lock(&ctxdata->mutex);
		idr_remove(&ctxdata->ocalls, call_ctx->id);
		mutex_unlock(&ctxdata->mutex);
	}

	mutex_destroy(&call_ctx->mutex);
	tee_shm_free(call_ctx->msg_shm);
	kfree(call_ctx);
}

static void optee_ocall_ctx_release(struct kref *ref)
{
	struct optee_call_ctx *call_ctx =
		container_of(ref, struct optee_call_ctx, ref);

	atomic_set(&call_ctx->releasing, true);
	optee_ocall_ctx_destroy(call_ctx);
}

struct optee_call_ctx *
optee_ocall_ctx_alloc(struct tee_context *ctx, u32 num_params,
		      optee_ocall_cancel_callback_t cancel_cb)
{
	struct optee_call_ctx *call_ctx;
	int rc = -ENOMEM;

	call_ctx = kzalloc(sizeof(*call_ctx), GFP_KERNEL);
	if (!call_ctx)
		goto exit_no_ctx;

	call_ctx->msg_shm = optee_get_msg_arg(ctx, num_params,
					      &call_ctx->msg_arg,
					      &call_ctx->msg_parg);
	if (IS_ERR(call_ctx->msg_shm))
		goto exit_no_msg;

	kref_init(&call_ctx->ref);
	mutex_init(&call_ctx->mutex);
	INIT_LIST_HEAD(&call_ctx->list_shm);

	call_ctx->id = -1;
	call_ctx->ctx = ctx;
	call_ctx->cancel_cb = cancel_cb;
	call_ctx->cancel_code = U32_MAX;

	return call_ctx;

exit_no_msg:
	kfree(call_ctx);
exit_no_ctx:
	return ERR_PTR(rc);
}

struct optee_call_ctx *optee_ocall_ctx_get_from_id(struct tee_context *ctx,
						   int id)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct optee_call_ctx *call_ctx;

	mutex_lock(&ctxdata->mutex);
	call_ctx = idr_find(&ctxdata->ocalls, id);
	if (!call_ctx)
		call_ctx = ERR_PTR(-EINVAL);
	else
		optee_ocall_ctx_get(call_ctx);
	mutex_unlock(&ctxdata->mutex);

	return call_ctx;
}

void optee_ocall_ctx_get(struct optee_call_ctx *call_ctx)
{
	if (atomic_read(&call_ctx->releasing))
		return;

	kref_get(&call_ctx->ref);
}

void optee_ocall_ctx_put(struct optee_call_ctx *call_ctx)
{
	if (atomic_read(&call_ctx->releasing))
		return;

	kref_put(&call_ctx->ref, optee_ocall_ctx_release);
}

int optee_ocall_register(struct optee_call_ctx *call_ctx)
{
	struct optee_context_data *ctxdata = call_ctx->ctx->data;
	int id;

	mutex_lock(&ctxdata->mutex);
	id = idr_alloc(&ctxdata->ocalls, call_ctx, 1, 0, GFP_KERNEL);
	if (id > 0) {
		call_ctx->id = id;
		optee_ocall_ctx_get(call_ctx);
		atomic_set(&call_ctx->attached, true);
	}
	mutex_unlock(&ctxdata->mutex);

	return id > 0 ? 0 : -ENOSPC;
}

void optee_ocall_deregister(struct optee_call_ctx *call_ctx)
{
	struct optee_context_data *ctxdata = call_ctx->ctx->data;
	struct optee_call_ctx *found_ctx;

	if (atomic_cmpxchg(&call_ctx->attached, true, false)) {
		mutex_lock(&ctxdata->mutex);
		found_ctx = idr_remove(&ctxdata->ocalls, call_ctx->id);
		if (found_ctx == call_ctx)
			optee_ocall_ctx_put(call_ctx);
		mutex_unlock(&ctxdata->mutex);
	}
}

/* Caller must hold call_ctx->mutex */
void optee_ocall_prologue(struct optee_call_ctx *call_ctx)
{
	struct optee *optee = tee_get_drvdata(call_ctx->ctx->teedev);

	if (call_ctx->enqueued)
		return;

	call_ctx->enqueued = true;
	optee_cq_wait_init(&optee->call_queue, &call_ctx->waiter);
}

/* Caller must hold call_ctx->mutex */
void optee_ocall_epilogue(struct optee_call_ctx *call_ctx)
{
	struct optee *optee = tee_get_drvdata(call_ctx->ctx->teedev);

	if (!call_ctx->enqueued)
		return;

	call_ctx->enqueued = false;
	optee_rpc_finalize_call(call_ctx);
	optee_cq_wait_final(&optee->call_queue, &call_ctx->waiter);
}

/* Caller must hold call_ctx->mutex */
void optee_ocall_cancel(struct optee_call_ctx *call_ctx)
{
	if (call_ctx->pending && !call_ctx->cancelled)
		optee_ocall_cancel_worker(call_ctx);
}

/* Caller must hold call_ctx->mutex */
void optee_ocall_cancel_with_code(struct optee_call_ctx *call_ctx, u32 code)
{
	if (call_ctx->pending && !call_ctx->cancelled) {
		call_ctx->cancel_code = code;
		optee_ocall_cancel_worker(call_ctx);
	}
}

void optee_ocall_notify_session_close(struct optee_session *session)
{
	struct optee_context_data *ctxdata = session->ctx->data;
	struct optee_call_ctx *call_ctx;
	int id;

	if (!ctxdata)
		return;

	mutex_lock(&ctxdata->mutex);
	idr_for_each_entry(&ctxdata->ocalls, call_ctx, id)
		if (call_ctx->session == session->session_id)
			optee_ocall_finalize(ctxdata, call_ctx);
	mutex_unlock(&ctxdata->mutex);
}

void optee_ocall_notify_context_release(struct tee_context *ctx)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct optee_call_ctx *call_ctx;
	int id;

	if (!ctxdata)
		return;

	mutex_lock(&ctxdata->mutex);
	idr_for_each_entry(&ctxdata->ocalls, call_ctx, id)
		optee_ocall_finalize(ctxdata, call_ctx);
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
		ocall->u.value.a =
			TEE_IOCTL_OCALL_MAKE_PAIR(TEE_IOCTL_OCALL_CMD_SHM_ALLOC,
						  call_ctx->id);

		shm_sz = call_ctx->rpc_arg->params[0].u.value.b;
		params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT;
		params[0].u.value.a = 0;
		params[0].u.value.b = shm_sz;
		params[0].u.value.c = 0;
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		ocall->u.value.a =
			TEE_IOCTL_OCALL_MAKE_PAIR(TEE_IOCTL_OCALL_CMD_SHM_FREE,
						  call_ctx->id);

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

		ocall->u.value.a =
			TEE_IOCTL_OCALL_MAKE_PAIR(TEE_IOCTL_OCALL_CMD_INVOKE,
						  call_ctx->id);

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

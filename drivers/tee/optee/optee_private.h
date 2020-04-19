/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef OPTEE_PRIVATE_H
#define OPTEE_PRIVATE_H

#include <linux/arm-smccc.h>
#include <linux/semaphore.h>
#include <linux/tee_drv.h>
#include <linux/types.h>
#include "optee_msg.h"

#define OPTEE_MAX_ARG_SIZE	1024

/* Some Global Platform error codes used in this driver */
#define TEEC_SUCCESS			0x00000000
#define TEEC_ERROR_BAD_PARAMETERS	0xFFFF0006
#define TEEC_ERROR_NOT_SUPPORTED	0xFFFF000A
#define TEEC_ERROR_COMMUNICATION	0xFFFF000E
#define TEEC_ERROR_OUT_OF_MEMORY	0xFFFF000C
#define TEEC_ERROR_SHORT_BUFFER		0xFFFF0010
#define TEEC_ERROR_TARGET_DEAD		0xFFFF3024

#define TEEC_ORIGIN_COMMS		0x00000002
#define TEEC_ORIGIN_CLIENT_APP		0x00000005

typedef void (optee_invoke_fn)(unsigned long, unsigned long, unsigned long,
				unsigned long, unsigned long, unsigned long,
				unsigned long, unsigned long,
				struct arm_smccc_res *);

struct optee_call_queue {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct list_head waiters;
};

struct optee_wait_queue {
	/* Serializes access to this struct */
	struct mutex mu;
	struct list_head db;
};

/**
 * struct optee_supp - supplicant synchronization struct
 * @ctx			the context of current connected supplicant.
 *			if !NULL the supplicant device is available for use,
 *			else busy
 * @mutex:		held while accessing content of this struct
 * @req_id:		current request id if supplicant is doing synchronous
 *			communication, else -1
 * @reqs:		queued request not yet retrieved by supplicant
 * @idr:		IDR holding all requests currently being processed
 *			by supplicant
 * @reqs_c:		completion used by supplicant when waiting for a
 *			request to be queued.
 */
struct optee_supp {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct tee_context *ctx;

	int req_id;
	struct list_head reqs;
	struct idr idr;
	struct completion reqs_c;
};

/**
 * struct optee - main service struct
 * @supp_teedev:	supplicant device
 * @teedev:		client device
 * @invoke_fn:		function to issue smc or hvc
 * @call_queue:		queue of threads waiting to call @invoke_fn
 * @wait_queue:		queue of threads from secure world waiting for a
 *			secure world sync object
 * @supp:		supplicant synchronization struct for RPC to supplicant
 * @pool:		shared memory pool
 * @memremaped_shm	virtual address of memory in shared memory pool
 * @sec_caps:		secure world capabilities defined by
 *			OPTEE_SMC_SEC_CAP_* in optee_smc.h
 */
struct optee {
	struct tee_device *supp_teedev;
	struct tee_device *teedev;
	optee_invoke_fn *invoke_fn;
	struct optee_call_queue call_queue;
	struct optee_wait_queue wait_queue;
	struct optee_supp supp;
	struct tee_shm_pool *pool;
	void *memremaped_shm;
	u32 sec_caps;
};

struct optee_call_waiter {
	struct list_head list_node;
	struct completion c;
};

struct optee_call_ctx;
typedef void (*optee_ocall_cancel_callback_t)(struct optee_call_ctx *call_ctx);

/**
 * struct optee_call_ctx - holds context that is preserved during one STD call
 * @pages_list:		list of pages allocated for RPC requests
 * @num_entries:	numbers of pages in 'pages_list'
 * @ctx:		TEE context whence the OCALL originated, if any
 * @cancel_cb:		callback function run after the OCALL is cancelled
 * @msg_shm:		shared memory object used for calling into OP-TEE
 * @msg_arg:		arguments used for calling into OP-TEE, namely the data
 *			behind 'msg_shm'
 * @msg_parg:		physical pointer underlying 'msg_shm'
 * @rpc_shm:		shared memory object used for responding to RPCs
 * @rpc_arg:		arguments used for responding to RPCs, namely the data
 *			behind 'rpc_shm'
 * @list_shm:		list of shared memory objects used by an OCALL to which
 *			a reference is kept by the driver until the OCALL is
 *			complete or cancelled, effectively preventing the CA
 *			from releasing the SHM while an OCALL request or reply
 *			is being processed
 * @thread_id:		secure thread Id whence the OCALL originated and which
 *			must be resumed when replying to the OCALL
 * @waiter:		object used to wait until a secure thread becomes
 *			available is the previous call into OP-TEE failed
 *			because all secure threads are in use
 */
struct optee_call_ctx {
	/* Information about pages list used in last allocation */
	void *pages_list;
	size_t num_entries;

	/* OCALL support */
	struct tee_context *ctx;
	optee_ocall_cancel_callback_t cancel_cb;

	struct tee_shm *msg_shm;
	struct optee_msg_arg *msg_arg;
	phys_addr_t msg_parg;

	struct tee_shm *rpc_shm;
	struct optee_msg_arg *rpc_arg;

	struct list_head list_shm;

	u32 thread_id;
	struct optee_call_waiter waiter;
};

struct optee_session {
	struct list_head list_node;
	u32 session_id;
	/* Serializes access to the elements that follow */
	struct semaphore sem;
	struct optee_call_ctx call_ctx;
};

struct optee_context_data {
	/* Serializes access to this struct */
	struct mutex mutex;
	struct list_head sess_list;
};

struct optee_rpc_param {
	u32	a0;
	u32	a1;
	u32	a2;
	u32	a3;
	u32	a4;
	u32	a5;
	u32	a6;
	u32	a7;
};

/*
 * RPC support
 */

void optee_handle_rpc(struct tee_context *ctx, struct optee_rpc_param *param,
		      struct optee_call_ctx *call_ctx);
bool optee_rpc_is_ocall(struct optee_rpc_param *param,
			struct optee_call_ctx *call_ctx);
int optee_rpc_process_shm_alloc(struct tee_shm *shm,
				struct optee_msg_param *msg_param, void **list);
void optee_rpc_finalize_call(struct optee_call_ctx *call_ctx);

/*
 * Wait queue
 */

void optee_wait_queue_init(struct optee_wait_queue *wq);
void optee_wait_queue_exit(struct optee_wait_queue *wq);

/*
 * Call queue
 */

void optee_cq_wait_init(struct optee_call_queue *cq,
			struct optee_call_waiter *w);
void optee_cq_wait_for_completion(struct optee_call_queue *cq,
				  struct optee_call_waiter *w);
void optee_cq_complete_one(struct optee_call_queue *cq);
void optee_cq_wait_final(struct optee_call_queue *cq,
			 struct optee_call_waiter *w);

/*
 * Supplicant
 */

u32 optee_supp_thrd_req(struct tee_context *ctx, u32 func, size_t num_params,
			struct tee_param *param);

int optee_supp_read(struct tee_context *ctx, void __user *buf, size_t len);
int optee_supp_write(struct tee_context *ctx, void __user *buf, size_t len);
void optee_supp_init(struct optee_supp *supp);
void optee_supp_uninit(struct optee_supp *supp);
void optee_supp_release(struct optee_supp *supp);

int optee_supp_recv(struct tee_context *ctx, u32 *func, u32 *num_params,
		    struct tee_param *param);
int optee_supp_send(struct tee_context *ctx, u32 ret, u32 num_params,
		    struct tee_param *param);

/*
 * Calls into OP-TEE
 */

u32 optee_do_call_with_arg(struct tee_context *ctx, phys_addr_t parg);
u32 optee_do_call_with_ctx(struct optee_call_ctx *call_ctx);

/*
 * Sessions
 */

int optee_open_session(struct tee_context *ctx,
		       struct tee_ioctl_open_session_arg *arg,
		       struct tee_param *param);
int optee_close_session(struct tee_context *ctx, u32 session);

/*
 * Function invocations
 */

int optee_invoke_func(struct tee_context *ctx, struct tee_ioctl_invoke_arg *arg,
		      struct tee_param *param);

/*
 * Cancellations
 */

int optee_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session);

/*
 * Shared memory
 */

void optee_enable_shm_cache(struct optee *optee);
void optee_disable_shm_cache(struct optee *optee);

int optee_shm_register(struct tee_context *ctx, struct tee_shm *shm,
		       struct page **pages, size_t num_pages,
		       unsigned long start);
int optee_shm_unregister(struct tee_context *ctx, struct tee_shm *shm);

int optee_shm_register_supp(struct tee_context *ctx, struct tee_shm *shm,
			    struct page **pages, size_t num_pages,
			    unsigned long start);
int optee_shm_unregister_supp(struct tee_context *ctx, struct tee_shm *shm);

/*
 * Paremeters
 */

int optee_from_msg_param(struct tee_param *params, size_t num_params,
			 const struct optee_msg_param *msg_params);
int optee_to_msg_param(struct optee_msg_param *msg_params, size_t num_params,
		       const struct tee_param *params);

/*
 * RPC memory
 */

u64 *optee_allocate_pages_list(size_t num_entries);
void optee_free_pages_list(void *array, size_t num_entries);
void optee_fill_pages_list(u64 *dst, struct page **pages, int num_pages,
			   size_t page_offset);

/*
 * Devices
 */

int optee_enumerate_devices(void);

/*
 * OCALLs
 */

void optee_ocall_prologue(struct optee_call_ctx *call_ctx);
void optee_ocall_epilogue(struct optee_call_ctx *call_ctx);

void optee_ocall_cancel(struct optee_call_ctx *call_ctx);
void optee_ocall_cancel_with_code(struct optee_call_ctx *call_ctx, u32 code);

void optee_ocall_notify_session_close(struct optee_session *session);
void optee_ocall_notify_context_release(struct tee_context *ctx);

int optee_ocall_process_request(struct tee_ioctl_invoke_arg *arg,
				struct tee_param *params, u32 num_params,
				struct tee_param *ocall,
				struct optee_call_ctx *call_ctx);
int optee_ocall_process_reply(struct tee_ioctl_invoke_arg *arg,
			      struct tee_param *params, u32 num_params,
			      struct tee_param *ocall,
			      struct optee_call_ctx *call_ctx);

/*
 * Small helpers
 */

static inline void *reg_pair_to_ptr(u32 reg0, u32 reg1)
{
	return (void *)(unsigned long)(((u64)reg0 << 32) | reg1);
}

static inline void reg_pair_from_64(u32 *reg0, u32 *reg1, u64 val)
{
	*reg0 = val >> 32;
	*reg1 = val;
}

#endif /*OPTEE_PRIVATE_H*/

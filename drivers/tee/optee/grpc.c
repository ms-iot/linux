#include <linux/slab.h>
#include "optee_private.h"

struct optee_grpc_req {
	struct list_head link;

	u32 key;
	u32 func;
	u32 session_id;
	u32 ret;
	size_t num_params;
	struct tee_param *param;

	struct completion c;
};

void optee_grpc_init(struct optee_grpc *grpc)
{
	memset(grpc, 0, sizeof(*grpc));
	mutex_init(&grpc->mutex);
	init_completion(&grpc->reqs_c);
	idr_init(&grpc->idr);
	INIT_LIST_HEAD(&grpc->reqs);
	grpc->req_id = -1;
}

void optee_grpc_uninit(struct optee_grpc *grpc)
{
	mutex_destroy(&grpc->mutex);
	idr_destroy(&grpc->idr);
}

u32 optee_grpc_req(struct optee_session *sess, u32 key, u32 func, size_t num_params,
		      struct tee_param *param)
{
	struct optee_grpc_req *req;
	u32 ret;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	init_completion(&req->c);
	req->key = key;
	req->func = func;
	req->session_id = sess->session_id;
	req->num_params = num_params;
	req->param = param;

	mutex_lock(&sess->grpc.mutex);
	list_add_tail(&req->link, &sess->grpc.reqs);
	mutex_unlock(&sess->grpc.mutex);

	complete(&sess->grpc.reqs_c);

	if (wait_for_completion_interruptible(&req->c))
		req->ret = TEEC_ERROR_COMMUNICATION;

	ret = req->ret;
	kfree(req);

	return ret;
}

static struct optee_grpc_req *grpc_pop_entry(struct optee_session *sess,
					      u32 num_params, int *id)
{
	struct optee_grpc_req *req;

	if (sess->grpc.req_id != -1)
		return ERR_PTR(-EINVAL);
	
	if (list_empty(&sess->grpc.reqs))
		return NULL;
	
	req = list_first_entry(&sess->grpc.reqs, struct optee_grpc_req, link);

	if (num_params < req->num_params) {
		return ERR_PTR(-EINVAL);
	}

	*id = idr_alloc(&sess->grpc.idr, req, 1, 0, GFP_KERNEL);
	if (*id < 0)
		return ERR_PTR(-ENOMEM);
	
	list_del(&req->link);

	return req;
}

int optee_grpc_recv(struct tee_context *ctx, u32 session, u32 *key, u32 *func, u32 num_params,
				struct tee_param *param)
{
	struct optee_context_data *ctxdata = ctx->data;
	struct optee_session *sess;
	struct optee_grpc_req *req;
	int id;

	mutex_lock(&ctxdata->mutex);
	sess = optee_find_session(ctxdata, session);
	mutex_unlock(&ctxdata->mutex);
	if (!sess)
		return -EINVAL;
	
	while (true) {
		mutex_lock(&sess->grpc.mutex);
		req = grpc_pop_entry(sess, num_params, &id);
		mutex_unlock(&sess->grpc.mutex);

		if (req) {
			if (IS_ERR(req))
				return PTR_ERR(req);
			break;
		}

		if (wait_for_completion_interruptible(&sess->grpc.reqs_c))
			return -ERESTARTSYS;
	}

	mutex_lock(&sess->grpc.mutex);
	sess->grpc.req_id = id;
	mutex_unlock(&sess->grpc.mutex);

	*key = req->key;
	*func = req->func;
	memcpy(param, req->param,
		   sizeof(struct tee_param) * req->num_params);

	return 0;
}

int optee_grpc_send(struct tee_context *ctx, struct tee_ioctl_grpc_send_arg *arg,
		      struct tee_param *param)
{
	return 1;
}

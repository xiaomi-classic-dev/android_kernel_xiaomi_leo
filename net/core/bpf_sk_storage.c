/* SPDX-License-Identifier: GPL-2.0 */
/* Socket-local BPF map storage for this kernel's legacy map API. */
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <net/sock.h>

struct bpf_sk_storage_elem {
	struct hlist_node node;
	struct rcu_head rcu;
	struct bpf_map *map;
	u8 value[0] __aligned(8);
};

struct bpf_sk_storage {
	struct hlist_head elems;
	spinlock_t lock;
	struct rcu_head rcu;
};

static struct bpf_sk_storage_elem *
sk_storage_lookup(struct bpf_sk_storage *storage, struct bpf_map *map)
{
	struct bpf_sk_storage_elem *elem;

	if (!storage)
		return NULL;
	hlist_for_each_entry_rcu(elem, &storage->elems, node)
		if (elem->map == map)
			return elem;
	return NULL;
}

static void sk_storage_elem_free_rcu(struct rcu_head *rcu)
{
	struct bpf_sk_storage_elem *elem =
		container_of(rcu, struct bpf_sk_storage_elem, rcu);

	bpf_map_put(elem->map);
	kfree(elem);
}

void bpf_sk_storage_free(struct sock *sk)
{
	struct bpf_sk_storage *storage;
	struct bpf_sk_storage_elem *elem;
	struct hlist_node *next;
	unsigned long flags;

	storage = xchg(&sk->sk_bpf_storage, NULL);
	if (!storage)
		return;
	spin_lock_irqsave(&storage->lock, flags);
	hlist_for_each_entry_safe(elem, next, &storage->elems, node) {
		hlist_del_rcu(&elem->node);
		call_rcu(&elem->rcu, sk_storage_elem_free_rcu);
	}
	spin_unlock_irqrestore(&storage->lock, flags);
	kfree_rcu(storage, rcu);
}

static struct bpf_sk_storage *sk_storage_get_or_create(struct sock *sk)
{
	struct bpf_sk_storage *storage, *new_storage;

	storage = rcu_dereference(sk->sk_bpf_storage);
	if (storage)
		return storage;
	new_storage = kzalloc(sizeof(*new_storage), GFP_ATOMIC | __GFP_NOWARN);
	if (!new_storage)
		return NULL;
	INIT_HLIST_HEAD(&new_storage->elems);
	spin_lock_init(&new_storage->lock);
	storage = cmpxchg(&sk->sk_bpf_storage, NULL, new_storage);
	if (storage) {
		kfree(new_storage);
		return storage;
	}
	return new_storage;
}

static void *sk_storage_get(struct bpf_map *map, struct sock *sk,
			    const void *init_value, u64 flags)
{
	struct bpf_sk_storage *storage;
	struct bpf_sk_storage_elem *elem, *new_elem;
	unsigned long irqflags;
	void *value = NULL;

	if (!sk || !sk_fullsock(sk) || flags > BPF_SK_STORAGE_GET_F_CREATE)
		return NULL;
	if (!atomic_inc_not_zero(&sk->sk_refcnt))
		return NULL;
	rcu_read_lock();
	storage = rcu_dereference(sk->sk_bpf_storage);
	elem = sk_storage_lookup(storage, map);
	if (elem) {
		value = elem->value;
		goto out;
	}
	if (!(flags & BPF_SK_STORAGE_GET_F_CREATE))
		goto out;
	storage = sk_storage_get_or_create(sk);
	if (!storage)
		goto out;
	new_elem = kzalloc(sizeof(*new_elem) + map->value_size,
			   GFP_ATOMIC | __GFP_NOWARN);
	if (!new_elem)
		goto out;
	if (init_value)
		memcpy(new_elem->value, init_value, map->value_size);
	if (IS_ERR(bpf_map_inc(map, false))) {
		kfree(new_elem);
		goto out;
	}
	new_elem->map = map;
	spin_lock_irqsave(&storage->lock, irqflags);
	elem = sk_storage_lookup(storage, map);
	if (elem) {
		value = elem->value;
		spin_unlock_irqrestore(&storage->lock, irqflags);
		bpf_map_put(map);
		kfree(new_elem);
		goto out;
	}
	hlist_add_head_rcu(&new_elem->node, &storage->elems);
	value = new_elem->value;
	spin_unlock_irqrestore(&storage->lock, irqflags);
out:
	rcu_read_unlock();
	sock_put(sk);
	return value;
}

BPF_CALL_4(bpf_sk_storage_get, struct bpf_map *, map, struct sock *, sk,
	   void *, value, u64, flags)
{
	return (unsigned long)sk_storage_get(map, sk, value, flags);
}

const struct bpf_func_proto bpf_sk_storage_get_proto = {
	.func = bpf_sk_storage_get,
	.gpl_only = false,
	.ret_type = RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_SOCK_COMMON,
	.arg3_type = ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_sk_storage_get_cg_sock_proto = {
	.func = bpf_sk_storage_get,
	.gpl_only = false,
	.ret_type = RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_CTX,
	.arg3_type = ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type = ARG_ANYTHING,
};

static int sk_storage_delete(struct bpf_map *map, struct sock *sk)
{
	struct bpf_sk_storage *storage;
	struct bpf_sk_storage_elem *elem;
	unsigned long irqflags;
	int ret = -ENOENT;

	if (!sk || !sk_fullsock(sk))
		return -EINVAL;
	rcu_read_lock();
	storage = rcu_dereference(sk->sk_bpf_storage);
	if (storage) {
		spin_lock_irqsave(&storage->lock, irqflags);
		elem = sk_storage_lookup(storage, map);
		if (elem) {
			hlist_del_rcu(&elem->node);
			call_rcu(&elem->rcu, sk_storage_elem_free_rcu);
			ret = 0;
		}
		spin_unlock_irqrestore(&storage->lock, irqflags);
	}
	rcu_read_unlock();
	return ret;
}

BPF_CALL_2(bpf_sk_storage_delete, struct bpf_map *, map, struct sock *, sk)
{
	return sk_storage_delete(map, sk);
}

const struct bpf_func_proto bpf_sk_storage_delete_proto = {
	.func = bpf_sk_storage_delete,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_SOCK_COMMON,
};

const struct bpf_func_proto bpf_sk_storage_delete_cg_sock_proto = {
	.func = bpf_sk_storage_delete,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_CTX,
};

int bpf_sk_storage_copy(struct bpf_map *map, void *key, void *value)
{
	struct bpf_sk_storage *storage;
	struct bpf_sk_storage_elem *elem;
	struct socket *sock;
	int err = -ENOENT;

	sock = sockfd_lookup(*(int *)key, &err);
	if (!sock)
		return err;
	if (!sock->sk)
		goto out;
	rcu_read_lock();
	storage = rcu_dereference(sock->sk->sk_bpf_storage);
	elem = sk_storage_lookup(storage, map);
	if (elem) {
		memcpy(value, elem->value, map->value_size);
		err = 0;
	}
	rcu_read_unlock();
out:
	sockfd_put(sock);
	return err;
}

int bpf_sk_storage_update_user(struct bpf_map *map, void *key,
			       void *value, u64 flags)
{
	struct bpf_sk_storage *storage;
	struct bpf_sk_storage_elem *elem, *new_elem;
	struct socket *sock;
	unsigned long irqflags;
	int err = -ENOENT;

	if (flags > BPF_EXIST)
		return -EINVAL;
	sock = sockfd_lookup(*(int *)key, &err);
	if (!sock)
		return err;
	if (!sock->sk || !sk_fullsock(sock->sk)) {
		err = -EINVAL;
		goto out_sock;
	}
	new_elem = kzalloc(sizeof(*new_elem) + map->value_size,
			   GFP_KERNEL | __GFP_NOWARN);
	if (!new_elem) {
		err = -ENOMEM;
		goto out_sock;
	}
	memcpy(new_elem->value, value, map->value_size);
	if (IS_ERR(bpf_map_inc(map, false))) {
		err = -EBUSY;
		goto out_elem;
	}
	new_elem->map = map;
	rcu_read_lock();
	storage = sk_storage_get_or_create(sock->sk);
	if (!storage) {
		err = -ENOMEM;
		goto out_ref;
	}
	spin_lock_irqsave(&storage->lock, irqflags);
	elem = sk_storage_lookup(storage, map);
	if ((elem && flags == BPF_NOEXIST) ||
	    (!elem && flags == BPF_EXIST)) {
		err = elem ? -EEXIST : -ENOENT;
		spin_unlock_irqrestore(&storage->lock, irqflags);
		goto out_ref;
	}
	if (elem) {
		hlist_del_rcu(&elem->node);
		call_rcu(&elem->rcu, sk_storage_elem_free_rcu);
	}
	hlist_add_head_rcu(&new_elem->node, &storage->elems);
	spin_unlock_irqrestore(&storage->lock, irqflags);
	rcu_read_unlock();
	sockfd_put(sock);
	return 0;
out_ref:
	rcu_read_unlock();
	bpf_map_put(map);
out_elem:
	kfree(new_elem);
out_sock:
	sockfd_put(sock);
	return err;
}

int bpf_sk_storage_delete_user(struct bpf_map *map, void *key)
{
	struct bpf_sk_storage *storage;
	struct bpf_sk_storage_elem *elem;
	struct socket *sock;
	unsigned long irqflags;
	int err = -ENOENT;

	sock = sockfd_lookup(*(int *)key, &err);
	if (!sock)
		return err;
	if (!sock->sk)
		goto out;
	rcu_read_lock();
	storage = rcu_dereference(sock->sk->sk_bpf_storage);
	if (storage) {
		spin_lock_irqsave(&storage->lock, irqflags);
		elem = sk_storage_lookup(storage, map);
		if (elem) {
			hlist_del_rcu(&elem->node);
			call_rcu(&elem->rcu, sk_storage_elem_free_rcu);
			err = 0;
		}
		spin_unlock_irqrestore(&storage->lock, irqflags);
	}
	rcu_read_unlock();
out:
	sockfd_put(sock);
	return err;
}

static struct bpf_map *sk_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_map *map;
	int ret;

	if (attr->key_size != sizeof(int) || !attr->value_size ||
	    attr->max_entries || attr->map_flags != BPF_F_NO_PREALLOC ||
	    attr->value_size > KMALLOC_MAX_SIZE -
				 sizeof(struct bpf_sk_storage_elem))
		return ERR_PTR(-EINVAL);
	ret = bpf_map_precharge_memlock(1);
	if (ret)
		return ERR_PTR(ret);
	map = kzalloc(sizeof(*map), GFP_USER);
	if (!map)
		return ERR_PTR(-ENOMEM);
	map->key_size = attr->key_size;
	map->value_size = attr->value_size;
	map->max_entries = 0;
	map->map_flags = attr->map_flags;
	map->pages = 1;
	return map;
}

static void sk_storage_map_free(struct bpf_map *map)
{
	/* Each live socket element holds a map reference. */
	kfree(map);
}

static int sk_storage_no_next_key(struct bpf_map *map, void *key,
				   void *next_key)
{
	return -EOPNOTSUPP;
}

static void *sk_storage_no_lookup(struct bpf_map *map, void *key)
{
	return NULL;
}

static int sk_storage_no_update(struct bpf_map *map, void *key, void *value,
				 u64 flags)
{
	return -EOPNOTSUPP;
}

static int sk_storage_no_delete(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

static const struct bpf_map_ops sk_storage_ops = {
	.map_alloc = sk_storage_map_alloc,
	.map_free = sk_storage_map_free,
	.map_get_next_key = sk_storage_no_next_key,
	.map_lookup_elem = sk_storage_no_lookup,
	.map_update_elem = sk_storage_no_update,
	.map_delete_elem = sk_storage_no_delete,
};

static struct bpf_map_type_list sk_storage_type __read_mostly = {
	.ops = &sk_storage_ops,
	.type = BPF_MAP_TYPE_SK_STORAGE,
};

static int __init register_sk_storage_map(void)
{
	bpf_register_map_type(&sk_storage_type);
	return 0;
}
late_initcall(register_sk_storage_map);

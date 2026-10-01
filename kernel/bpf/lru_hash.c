/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded BPF LRU hash map for the legacy 3.10 BPF map interface. */
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/jhash.h>
#include <linux/rculist.h>
#include <linux/slab.h>

struct lru_hash_elem {
	struct hlist_node hash_node;
	struct list_head lru_node;
	struct rcu_head rcu;
	u32 hash;
	bool linked;
	u8 data[0] __aligned(8);
};

struct lru_hash_map {
	struct bpf_map map;
	struct hlist_head *buckets;
	struct list_head lru;
	spinlock_t lock;
	u32 n_buckets;
	u32 count;
	u32 value_offset;
};

static struct hlist_head *lru_bucket(struct lru_hash_map *lru, u32 hash)
{
	return &lru->buckets[hash & (lru->n_buckets - 1)];
}

static struct lru_hash_elem *lru_find(struct lru_hash_map *lru,
					      const void *key, u32 hash)
{
	struct lru_hash_elem *elem;

	hlist_for_each_entry_rcu(elem, lru_bucket(lru, hash), hash_node)
		if (elem->hash == hash &&
		    !memcmp(elem->data, key, lru->map.key_size))
			return elem;
	return NULL;
}

static void lru_free_rcu(struct rcu_head *rcu)
{
	struct lru_hash_elem *elem = container_of(rcu, struct lru_hash_elem,
						      rcu);
	kfree(elem);
}

static void lru_unlink(struct lru_hash_map *lru, struct lru_hash_elem *elem)
{
	hlist_del_rcu(&elem->hash_node);
	list_del(&elem->lru_node);
	elem->linked = false;
	lru->count--;
	call_rcu(&elem->rcu, lru_free_rcu);
}

static struct bpf_map *lru_hash_alloc(union bpf_attr *attr)
{
	struct lru_hash_map *lru;
	u64 cost, elem_size;
	u32 i, buckets;
	int ret;

	if (attr->map_flags & ~(BPF_F_RDONLY | BPF_F_WRONLY) ||
	    !attr->max_entries || !attr->key_size || !attr->value_size ||
	    attr->key_size > MAX_BPF_STACK ||
	    attr->value_size >= (1 << (KMALLOC_SHIFT_MAX - 1)) -
				    MAX_BPF_STACK - sizeof(struct lru_hash_elem))
		return ERR_PTR(-EINVAL);
	buckets = roundup_pow_of_two(attr->max_entries);
	if (!buckets || buckets > U32_MAX / sizeof(struct hlist_head))
		return ERR_PTR(-E2BIG);
	elem_size = sizeof(struct lru_hash_elem) +
		    round_up(attr->key_size, 8) + round_up(attr->value_size, 8);
	cost = sizeof(*lru) + (u64)buckets * sizeof(struct hlist_head) +
		(u64)attr->max_entries * elem_size;
	if (cost >= U32_MAX - PAGE_SIZE)
		return ERR_PTR(-E2BIG);
	ret = bpf_map_precharge_memlock(round_up(cost, PAGE_SIZE) >> PAGE_SHIFT);
	if (ret)
		return ERR_PTR(ret);
	lru = kzalloc(sizeof(*lru), GFP_USER);
	if (!lru)
		return ERR_PTR(-ENOMEM);
	lru->buckets = kcalloc(buckets, sizeof(*lru->buckets), GFP_USER);
	if (!lru->buckets) {
		kfree(lru);
		return ERR_PTR(-ENOMEM);
	}
	for (i = 0; i < buckets; i++)
		INIT_HLIST_HEAD(&lru->buckets[i]);
	INIT_LIST_HEAD(&lru->lru);
	spin_lock_init(&lru->lock);
	lru->n_buckets = buckets;
	lru->value_offset = round_up(attr->key_size, 8);
	lru->map.key_size = attr->key_size;
	lru->map.value_size = attr->value_size;
	lru->map.max_entries = attr->max_entries;
	lru->map.map_flags = attr->map_flags;
	lru->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;
	return &lru->map;
}

static void *lru_hash_lookup(struct bpf_map *map, void *key)
{
	struct lru_hash_map *lru = container_of(map, struct lru_hash_map, map);
	struct lru_hash_elem *elem;
	unsigned long flags;
	u32 hash = jhash(key, map->key_size, 0);

	WARN_ON_ONCE(!rcu_read_lock_held());
	elem = lru_find(lru, key, hash);
	if (!elem)
		return NULL;
	spin_lock_irqsave(&lru->lock, flags);
	if (elem->linked)
		list_move(&elem->lru_node, &lru->lru);
	spin_unlock_irqrestore(&lru->lock, flags);
	return elem->data + lru->value_offset;
}

static int lru_hash_update(struct bpf_map *map, void *key, void *value,
			   u64 map_flags)
{
	struct lru_hash_map *lru = container_of(map, struct lru_hash_map, map);
	struct lru_hash_elem *elem, *old;
	unsigned long flags;
	u32 hash = jhash(key, map->key_size, 0);
	u32 size = sizeof(*elem) + lru->value_offset +
		   round_up(map->value_size, 8);
	int ret = 0;

	if (map_flags > BPF_EXIST)
		return -EINVAL;
	elem = kzalloc(size, GFP_ATOMIC | __GFP_NOWARN);
	if (!elem)
		return -ENOMEM;
	memcpy(elem->data, key, map->key_size);
	memcpy(elem->data + lru->value_offset, value, map->value_size);
	elem->hash = hash;
	spin_lock_irqsave(&lru->lock, flags);
	old = lru_find(lru, key, hash);
	if (old && map_flags == BPF_NOEXIST) {
		ret = -EEXIST;
		goto unlock;
	}
	if (!old && map_flags == BPF_EXIST) {
		ret = -ENOENT;
		goto unlock;
	}
	if (old)
		lru_unlink(lru, old);
	else if (lru->count == map->max_entries) {
		old = list_entry(lru->lru.prev, struct lru_hash_elem,
				 lru_node);
		lru_unlink(lru, old);
	}
	hlist_add_head_rcu(&elem->hash_node, lru_bucket(lru, hash));
	list_add(&elem->lru_node, &lru->lru);
	elem->linked = true;
	lru->count++;
unlock:
	spin_unlock_irqrestore(&lru->lock, flags);
	if (ret)
		kfree(elem);
	return ret;
}

static int lru_hash_delete(struct bpf_map *map, void *key)
{
	struct lru_hash_map *lru = container_of(map, struct lru_hash_map, map);
	struct lru_hash_elem *elem;
	unsigned long flags;
	u32 hash = jhash(key, map->key_size, 0);
	int ret = -ENOENT;

	spin_lock_irqsave(&lru->lock, flags);
	elem = lru_find(lru, key, hash);
	if (elem) {
		lru_unlink(lru, elem);
		ret = 0;
	}
	spin_unlock_irqrestore(&lru->lock, flags);
	return ret;
}

static int lru_hash_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct lru_hash_map *lru = container_of(map, struct lru_hash_map, map);
	struct lru_hash_elem *elem;
	unsigned long flags;
	int ret = -ENOENT;

	spin_lock_irqsave(&lru->lock, flags);
	if (!list_empty(&lru->lru)) {
		if (key) {
			u32 hash = jhash(key, map->key_size, 0);

			elem = lru_find(lru, key, hash);
			if (elem) {
				if (elem->lru_node.next == &lru->lru)
					goto unlock;
				elem = list_entry(elem->lru_node.next,
						  struct lru_hash_elem, lru_node);
			}
		} else {
			elem = NULL;
		}
		if (!elem)
			elem = list_first_entry(&lru->lru,
						struct lru_hash_elem, lru_node);
		if (elem) {
			memcpy(next_key, elem->data, map->key_size);
			ret = 0;
		}
	}
unlock:
	spin_unlock_irqrestore(&lru->lock, flags);
	return ret;
}

static void lru_hash_free(struct bpf_map *map)
{
	struct lru_hash_map *lru = container_of(map, struct lru_hash_map, map);
	struct lru_hash_elem *elem, *tmp;

	synchronize_rcu();
	rcu_barrier();
	list_for_each_entry_safe(elem, tmp, &lru->lru, lru_node)
		kfree(elem);
	kfree(lru->buckets);
	kfree(lru);
}

static const struct bpf_map_ops lru_hash_ops = {
	.map_alloc = lru_hash_alloc,
	.map_free = lru_hash_free,
	.map_get_next_key = lru_hash_next_key,
	.map_lookup_elem = lru_hash_lookup,
	.map_update_elem = lru_hash_update,
	.map_delete_elem = lru_hash_delete,
};

static struct bpf_map_type_list lru_hash_type __read_mostly = {
	.ops = &lru_hash_ops,
	.type = BPF_MAP_TYPE_LRU_HASH,
};

static int __init register_lru_hash_map(void)
{
	bpf_register_map_type(&lru_hash_type);
	return 0;
}
late_initcall(register_lru_hash_map);

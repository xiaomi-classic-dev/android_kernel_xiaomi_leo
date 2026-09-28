/* SPDX-License-Identifier: GPL-2.0-only */
/* Device hash map control plane, based on Linux 5.4 kernel/bpf/devmap.c.
 * XDP redirect is not exposed by this legacy kernel. Entries still hold real
 * netdev references and are removed when their device is unregistered.
 */
#include <linux/bpf.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/nsproxy.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/log2.h>
#include <net/net_namespace.h>

struct devmap_entry {
	struct hlist_node node;
	struct rcu_head rcu;
	struct net_device *dev;
	u32 key;
};

struct devmap_hash {
	struct bpf_map map;
	struct hlist_head *buckets;
	struct list_head list;
	spinlock_t lock;
	u32 n_buckets;
	u32 count;
};

static LIST_HEAD(devmaps);
static DEFINE_SPINLOCK(devmaps_lock);

static struct devmap_entry *devmap_find(struct devmap_hash *d, u32 key)
{
	struct devmap_entry *e;
	hlist_for_each_entry_rcu(e, &d->buckets[key & (d->n_buckets - 1)], node)
		if (e->key == key)
			return e;
	return NULL;
}

static void devmap_entry_free(struct rcu_head *rcu)
{
	struct devmap_entry *e = container_of(rcu, struct devmap_entry, rcu);
	dev_put(e->dev);
	kfree(e);
}

static struct bpf_map *devmap_alloc(union bpf_attr *attr)
{
	struct devmap_hash *d;
	u32 i, n;
	u64 cost;
	int err;

	if (!capable(CAP_NET_ADMIN))
		return ERR_PTR(-EPERM);
	if (!attr->max_entries || attr->key_size != 4 || attr->value_size != 4 ||
	    attr->map_flags & ~(BPF_F_RDONLY | BPF_F_WRONLY) ||
	    attr->max_entries > (1U << 30))
		return ERR_PTR(-EINVAL);
	n = roundup_pow_of_two(attr->max_entries);
	cost = sizeof(*d) + (u64)n * sizeof(struct hlist_head) +
	       (u64)attr->max_entries * sizeof(struct devmap_entry);
	if (cost >= U32_MAX - PAGE_SIZE)
		return ERR_PTR(-E2BIG);
	err = bpf_map_precharge_memlock(round_up(cost, PAGE_SIZE) >> PAGE_SHIFT);
	if (err)
		return ERR_PTR(err);
	d = kzalloc(sizeof(*d), GFP_USER);
	if (!d)
		return ERR_PTR(-ENOMEM);
	d->buckets = bpf_map_area_alloc(n * sizeof(*d->buckets));
	if (!d->buckets) {
		kfree(d);
		return ERR_PTR(-ENOMEM);
	}
	for (i = 0; i < n; i++)
		INIT_HLIST_HEAD(&d->buckets[i]);
	d->n_buckets = n;
	d->map.map_type = attr->map_type;
	d->map.key_size = attr->key_size;
	d->map.value_size = attr->value_size;
	d->map.max_entries = attr->max_entries;
	d->map.map_flags = attr->map_flags | BPF_F_RDONLY_PROG;
	d->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;
	spin_lock_init(&d->lock);
	spin_lock(&devmaps_lock);
	list_add_tail_rcu(&d->list, &devmaps);
	spin_unlock(&devmaps_lock);
	return &d->map;
}

static void devmap_free(struct bpf_map *map)
{
	struct devmap_hash *d = container_of(map, struct devmap_hash, map);
	struct devmap_entry *e;
	struct hlist_node *tmp;
	u32 i;

	spin_lock(&devmaps_lock);
	list_del_rcu(&d->list);
	spin_unlock(&devmaps_lock);
	synchronize_rcu();
	for (i = 0; i < d->n_buckets; i++) {
		hlist_for_each_entry_safe(e, tmp, &d->buckets[i], node) {
			dev_put(e->dev);
			kfree(e);
		}
	}
	/* Deferred entries do not reference d, so no global rcu_barrier needed. */
	bpf_map_area_free(d->buckets);
	kfree(d);
}

static void *devmap_lookup(struct bpf_map *map, void *key)
{
	struct devmap_hash *d = container_of(map, struct devmap_hash, map);
	struct devmap_entry *e = devmap_find(d, *(u32 *)key);
	return e ? &e->dev->ifindex : NULL;
}

static int devmap_update(struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct devmap_hash *d = container_of(map, struct devmap_hash, map);
	struct devmap_entry *e, *old;
	unsigned long irqflags;
	int ret = 0;

	if (flags > BPF_EXIST)
		return -EINVAL;
	e = kzalloc(sizeof(*e), GFP_ATOMIC | __GFP_NOWARN);
	if (!e)
		return -ENOMEM;
	e->dev = dev_get_by_index(current->nsproxy->net_ns, *(u32 *)value);
	if (!e->dev) {
		kfree(e);
		return -EINVAL;
	}
	e->key = *(u32 *)key;
	spin_lock_irqsave(&d->lock, irqflags);
	/* Serialize this check with NETDEV_UNREGISTER's removal pass. */
	if (e->dev->reg_state != NETREG_REGISTERED) {
		ret = -ENODEV;
		goto out;
	}
	old = devmap_find(d, e->key);
	if (old && flags == BPF_NOEXIST) {
		ret = -EEXIST;
		goto out;
	}
	if (!old && flags == BPF_EXIST) {
		ret = -ENOENT;
		goto out;
	}
	if (!old && d->count == map->max_entries) {
		ret = -E2BIG;
		goto out;
	}
	if (old) {
		hlist_replace_rcu(&old->node, &e->node);
		call_rcu(&old->rcu, devmap_entry_free);
	} else {
		hlist_add_head_rcu(&e->node, &d->buckets[e->key & (d->n_buckets - 1)]);
		d->count++;
	}
out:
	spin_unlock_irqrestore(&d->lock, irqflags);
	if (ret) {
		dev_put(e->dev);
		kfree(e);
	}
	return ret;
}

static int devmap_delete(struct bpf_map *map, void *key)
{
	struct devmap_hash *d = container_of(map, struct devmap_hash, map);
	struct devmap_entry *e;
	unsigned long flags;

	spin_lock_irqsave(&d->lock, flags);
	e = devmap_find(d, *(u32 *)key);
	if (e) {
		hlist_del_rcu(&e->node);
		d->count--;
		call_rcu(&e->rcu, devmap_entry_free);
	}
	spin_unlock_irqrestore(&d->lock, flags);
	return e ? 0 : -ENOENT;
}

static int devmap_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct devmap_hash *d = container_of(map, struct devmap_hash, map);
	struct devmap_entry *e = key ? devmap_find(d, *(u32 *)key) : NULL;
	struct hlist_node *node;
	u32 i = 0;

	if (e) {
		node = rcu_dereference_raw(e->node.next);
		if (node) {
			e = hlist_entry(node, struct devmap_entry, node);
			goto found;
		}
		i = (e->key & (d->n_buckets - 1)) + 1;
	}
	for (; i < d->n_buckets; i++) {
		node = rcu_dereference_raw(d->buckets[i].first);
		if (node) {
			e = hlist_entry(node, struct devmap_entry, node);
			goto found;
		}
	}
	return -ENOENT;
found:
	*(u32 *)next_key = e->key;
	return 0;
}

static int devmap_netdev_event(struct notifier_block *nb,
			      unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct devmap_hash *d;
	struct devmap_entry *e;
	struct hlist_node *tmp;
	unsigned long flags;
	u32 i;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;
	rcu_read_lock();
	list_for_each_entry_rcu(d, &devmaps, list) {
		spin_lock_irqsave(&d->lock, flags);
		for (i = 0; i < d->n_buckets; i++) {
			hlist_for_each_entry_safe(e, tmp, &d->buckets[i], node) {
				if (e->dev != dev)
					continue;
				hlist_del_rcu(&e->node);
				d->count--;
				call_rcu(&e->rcu, devmap_entry_free);
			}
		}
		spin_unlock_irqrestore(&d->lock, flags);
	}
	rcu_read_unlock();
	return NOTIFY_OK;
}

static struct notifier_block devmap_notifier = {
	.notifier_call = devmap_netdev_event,
};

static const struct bpf_map_ops devmap_ops = {
	.map_alloc = devmap_alloc,
	.map_free = devmap_free,
	.map_lookup_elem = devmap_lookup,
	.map_update_elem = devmap_update,
	.map_delete_elem = devmap_delete,
	.map_get_next_key = devmap_next_key,
};

static struct bpf_map_type_list devmap_type = {
	.ops = &devmap_ops,
	.type = BPF_MAP_TYPE_DEVMAP_HASH,
};

static int __init register_devmap_hash(void)
{
	int err = register_netdevice_notifier(&devmap_notifier);
	if (err)
		return err;
	bpf_register_map_type(&devmap_type);
	return 0;
}
late_initcall(register_devmap_hash);

/*
 * Match-all traffic-control classifier.
 *
 * Adapted from Linux v4.10 net/sched/cls_matchall.c for this kernel's
 * tcf_proto_ops interface and software-only traffic control.
 *
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>

struct cls_mall_head {
	struct tcf_exts exts;
	struct tcf_result res;
	u32 handle;
	u32 flags;
	struct rcu_head rcu;
};

static int mall_classify(struct sk_buff *skb, const struct tcf_proto *tp,
			 struct tcf_result *res)
{
	struct cls_mall_head *head = rcu_dereference_bh(tp->root);

	if (!head)
		return -1;

	*res = head->res;
	return tcf_exts_exec(skb, &head->exts, res);
}

static int mall_init(struct tcf_proto *tp)
{
	return 0;
}

static void mall_destroy_rcu(struct rcu_head *rcu)
{
	struct cls_mall_head *head = container_of(rcu, struct cls_mall_head,
						  rcu);

	tcf_exts_destroy(&head->exts);
	kfree(head);
}

static bool mall_destroy(struct tcf_proto *tp, bool force)
{
	struct cls_mall_head *head = rtnl_dereference(tp->root);

	if (!head)
		return true;
	if (!force)
		return false;

	RCU_INIT_POINTER(tp->root, NULL);
	tcf_unbind_filter(tp, &head->res);
	call_rcu(&head->rcu, mall_destroy_rcu);
	return true;
}

static unsigned long mall_get(struct tcf_proto *tp, u32 handle)
{
	struct cls_mall_head *head = rtnl_dereference(tp->root);

	if (head && (!handle || handle == head->handle))
		return (unsigned long)head;
	return 0;
}

static const struct nla_policy mall_policy[TCA_MATCHALL_MAX + 1] = {
	[TCA_MATCHALL_CLASSID] = { .type = NLA_U32 },
	[TCA_MATCHALL_FLAGS] = { .type = NLA_U32 },
};

static int mall_change(struct net *net, struct sk_buff *in_skb,
		       struct tcf_proto *tp, unsigned long base, u32 handle,
		       struct nlattr **tca, unsigned long *arg, bool ovr)
{
	struct cls_mall_head *old = rtnl_dereference(tp->root);
	struct nlattr *tb[TCA_MATCHALL_MAX + 1];
	struct cls_mall_head *new;
	struct tcf_exts e;
	u32 flags = 0;
	int err;

	if (!tca[TCA_OPTIONS])
		return -EINVAL;
	if (old && (unsigned long)old != *arg)
		return -EEXIST;
	if (old && handle && handle != old->handle)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_MATCHALL_MAX, tca[TCA_OPTIONS],
			       mall_policy);
	if (err < 0)
		return err;

	if (tb[TCA_MATCHALL_FLAGS]) {
		flags = nla_get_u32(tb[TCA_MATCHALL_FLAGS]);
		/* This kernel has no matchall hardware offload path. */
		if (flags & ~TCA_CLS_FLAGS_SKIP_HW)
			return -EOPNOTSUPP;
	}

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOBUFS;

	new->handle = handle ? handle : old ? old->handle : 1;
	new->flags = flags;
	tcf_exts_init(&new->exts, TCA_MATCHALL_ACT, 0);
	tcf_exts_init(&e, TCA_MATCHALL_ACT, 0);
	err = tcf_exts_validate(net, tp, tb, tca[TCA_RATE], &e, ovr);
	if (err < 0)
		goto errout;

	if (tb[TCA_MATCHALL_CLASSID]) {
		new->res.classid = nla_get_u32(tb[TCA_MATCHALL_CLASSID]);
		tcf_bind_filter(tp, &new->res, base);
	}
	tcf_exts_change(tp, &new->exts, &e);

	rcu_assign_pointer(tp->root, new);
	*arg = (unsigned long)new;
	if (old) {
		tcf_unbind_filter(tp, &old->res);
		call_rcu(&old->rcu, mall_destroy_rcu);
	}
	return 0;

errout:
	tcf_exts_destroy(&e);
	kfree(new);
	return err;
}

static int mall_delete(struct tcf_proto *tp, unsigned long arg)
{
	struct cls_mall_head *head = rtnl_dereference(tp->root);

	if (!head || (unsigned long)head != arg)
		return -ENOENT;

	RCU_INIT_POINTER(tp->root, NULL);
	tcf_unbind_filter(tp, &head->res);
	call_rcu(&head->rcu, mall_destroy_rcu);
	return 0;
}

static void mall_walk(struct tcf_proto *tp, struct tcf_walker *arg)
{
	struct cls_mall_head *head = rtnl_dereference(tp->root);

	if (!head)
		return;
	if (arg->count < arg->skip)
		goto skip;
	if (arg->fn(tp, (unsigned long)head, arg) < 0)
		arg->stop = 1;
skip:
	arg->count++;
}

static int mall_dump(struct net *net, struct tcf_proto *tp, unsigned long fh,
		     struct sk_buff *skb, struct tcmsg *t)
{
	struct cls_mall_head *head = (struct cls_mall_head *)fh;
	unsigned char *begin = skb_tail_pointer(skb);
	struct nlattr *nest;

	if (!head)
		return skb->len;

	t->tcm_handle = head->handle;
	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (!nest)
		goto nla_put_failure;

	if (head->res.classid &&
	    nla_put_u32(skb, TCA_MATCHALL_CLASSID, head->res.classid))
		goto nla_put_failure;
	if (head->flags &&
	    nla_put_u32(skb, TCA_MATCHALL_FLAGS, head->flags))
		goto nla_put_failure;
	if (tcf_exts_dump(skb, &head->exts) < 0)
		goto nla_put_failure;

	nla_nest_end(skb, nest);
	if (tcf_exts_is_available(&head->exts) &&
	    tcf_exts_dump_stats(skb, &head->exts) < 0)
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, begin);
	return -1;
}

static struct tcf_proto_ops cls_mall_ops __read_mostly = {
	.kind		= "matchall",
	.classify	= mall_classify,
	.init		= mall_init,
	.destroy	= mall_destroy,
	.get		= mall_get,
	.change		= mall_change,
	.delete		= mall_delete,
	.walk		= mall_walk,
	.dump		= mall_dump,
	.owner		= THIS_MODULE,
};

static int __init cls_mall_init(void)
{
	return register_tcf_proto_ops(&cls_mall_ops);
}

static void __exit cls_mall_exit(void)
{
	unregister_tcf_proto_ops(&cls_mall_ops);
}

module_init(cls_mall_init);
module_exit(cls_mall_exit);

MODULE_AUTHOR("Jiri Pirko <jiri@mellanox.com>");
MODULE_DESCRIPTION("Match-all classifier");
MODULE_LICENSE("GPL v2");

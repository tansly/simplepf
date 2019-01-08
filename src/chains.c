/*
 * simplepf, a simple packet filtering firewall
 * Copyright (C) 2019 Yağmur Oymak
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "chains.h"
#include "uapi/simplepf.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/slab.h>

struct chain_node {
	struct list_head list;
	struct simplepf_rule rule;
};

/*
 * Chains are RCU-protected linked lists.
 * Read mostly in chain traversals by netfilter hooks,
 * written rarely for update requests by userspace.
 * TODO: Consider parallel writers. If there may be parallel writers,
 * we'll need an additional synchronization mechanism to serialize them,
 * such as a spinlock.
 */
static LIST_HEAD(input_chain);
static LIST_HEAD(output_chain);

static struct list_head *chains[__SIMPLEPF_CHAIN_LAST] = {
	[SIMPLEPF_CHAIN_INPUT] = &input_chain,
	[SIMPLEPF_CHAIN_OUTPUT] = &output_chain
};

/*
 * TODO: Default actions may be set by userspace in the future.
 * Just ACCEPT by default for the time being.
 */
static enum simplepf_action default_actions[__SIMPLEPF_CHAIN_LAST] = {
	[SIMPLEPF_CHAIN_INPUT] = SIMPLEPF_ACTION_ACCEPT,
	[SIMPLEPF_CHAIN_OUTPUT] = SIMPLEPF_ACTION_ACCEPT,
};

/*
 * Tries to match the given rule with sk_buff.
 * If match is successful, returns the action specified in the rule.
 * Else, returns __SIMPLEPF_ACTION_LAST.
 * XXX: Do we need the hook state?
 */
static enum simplepf_action match_rule(const struct simplepf_rule *rule,
		const struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	return __SIMPLEPF_ACTION_LAST; // TODO
}

/*
 * XXX: We do not handle concurrent mutators yet.
 */
int simplepf_add_rule(enum simplepf_chain_id chain_id,
		const struct simplepf_rule *rule)
{
	struct list_head *chain;
	struct chain_node *new;

	if (chain_id >= __SIMPLEPF_CHAIN_LAST) {
		return -EINVAL;
	}

	new = kmalloc(sizeof *new, GFP_KERNEL);
	if (!new) {
		return -ENOMEM;
	}
	new->rule = *rule;

	/*
	 * XXX: chain_id will be an arbitrary input from userspace.
	 * Should we use nospec stuff here (Spectre mitigations)?
	 */
	chain = chains[chain_id];

	/*
	 * From rculist.h:
	 * The caller must take whatever precautions are necessary
	 * (such as holding appropriate locks) to avoid racing
	 * with another list-mutation primitive, such as list_add_tail_rcu()
	 * or list_del_rcu(), running on this same list.
	 * However, it is perfectly legal to run concurrently with
	 * the _rcu list-traversal primitives, such as
	 * list_for_each_entry_rcu().
	 *
	 * TODO: Synchronization among mutators
	 */
	list_add_tail_rcu(&new->list, chain);

	return 0;
}

/*
 * TODO: Implement actual chain traversal.
 * Obviously the chain must be set up first.
 */
enum simplepf_action simplepf_traverse_chain(enum simplepf_chain_id chain_id,
		const struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct list_head *chain;
	struct chain_node *node;

	if (chain_id >= __SIMPLEPF_CHAIN_LAST) {
		/*
		 * This should not be possible. The caller will
		 * be us (the module), so the chain id is not an arbitrary input.
		 * So this case indicates a programming error.
		 */
		printk(KERN_DEBUG "simplepf: Chain id (=%d) out of range. "
				"Accepting packet. "
				"This may be a bug.\n", chain_id);
		return SIMPLEPF_ACTION_ACCEPT;
	}

	chain = chains[chain_id];

	if (!chain) {
		return default_actions[chain_id];
	}

	rcu_read_lock();
	list_for_each_entry_rcu(node, chain, list) {
		enum simplepf_action action;
		action = match_rule(&node->rule, skb, state);
		if (action != __SIMPLEPF_ACTION_LAST) {
			rcu_read_unlock();
			return action;
		}
	}
	rcu_read_unlock();
	return default_actions[chain_id];
}

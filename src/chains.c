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
#include <linux/mutex.h>
#include <linux/nospec.h>

struct chain_node {
	struct list_head list;
	struct simplepf_rule rule;
};

/*
 * Chains are RCU-protected linked lists.
 * Read mostly in chain traversals by netfilter hooks,
 * written rarely for update requests by userspace.
 */
static LIST_HEAD(input_chain);
static LIST_HEAD(output_chain);

static struct list_head *chains[__SIMPLEPF_CHAIN_LAST] = {
	[SIMPLEPF_CHAIN_INPUT] = &input_chain,
	[SIMPLEPF_CHAIN_OUTPUT] = &output_chain
};

/*
 * Mutexes to protect the chains.
 */
static DEFINE_MUTEX(input_chain_mutex);
static DEFINE_MUTEX(output_chain_mutex);

static struct mutex *chain_mutexes[__SIMPLEPF_CHAIN_LAST] = {
	[SIMPLEPF_CHAIN_INPUT] = &input_chain_mutex,
	[SIMPLEPF_CHAIN_OUTPUT] = &output_chain_mutex,
};

/*
 * Accept by default.
 */
static enum simplepf_action default_actions[__SIMPLEPF_CHAIN_LAST] = {
	[SIMPLEPF_CHAIN_INPUT] = SIMPLEPF_ACTION_ACCEPT,
	[SIMPLEPF_CHAIN_OUTPUT] = SIMPLEPF_ACTION_ACCEPT,
};

/*
 * Tries to match the given rule with sk_buff.
 * Will always be given non-null parameters.
 * If match is successful, returns the action specified in the rule.
 * Else, returns __SIMPLEPF_ACTION_LAST.
 * XXX: Do we need the hook state?
 */
static enum simplepf_action match_rule(const struct simplepf_rule *rule,
		const struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct iphdr *ip_header = ip_hdr(skb);

	if (rule->filter_saddr && rule->ip_saddr != ip_header->saddr) {
		return __SIMPLEPF_ACTION_LAST;
	}

	if (rule->filter_daddr && rule->ip_daddr != ip_header->daddr) {
		return __SIMPLEPF_ACTION_LAST;
	}

	if (rule->filter_proto && rule->ip_protocol != ip_header->protocol) {
		return __SIMPLEPF_ACTION_LAST;
	}

	switch (ip_header->protocol) {
	case IPPROTO_ICMP:
	{
		struct icmphdr *icmp_header = icmp_hdr(skb);
		if (rule->filter_icmp_type &&
				rule->icmp_type != icmp_header->type) {
			return __SIMPLEPF_ACTION_LAST;
		}
	}
	break;

	case IPPROTO_TCP:
	{
		struct tcphdr *tcp_header = tcp_hdr(skb);
		if (rule->filter_sport &&
				rule->transport_sport != tcp_header->source) {
			return __SIMPLEPF_ACTION_LAST;
		}
		if (rule->filter_dport &&
				rule->transport_dport != tcp_header->dest) {
			return __SIMPLEPF_ACTION_LAST;
		}
	}
	break;

	case IPPROTO_UDP:
	{
		struct udphdr *udp_header = udp_hdr(skb);
		if (rule->filter_sport &&
				rule->transport_sport != udp_header->source) {
			return __SIMPLEPF_ACTION_LAST;
		}
		if (rule->filter_dport &&
				rule->transport_dport != udp_header->dest) {
			return __SIMPLEPF_ACTION_LAST;
		}

	}
	break;

	/*
	 * Not matched any of the protocols we support.
	 * Let the packet pass.
	 */
	default:
	return __SIMPLEPF_ACTION_LAST;

	}

	/*
	 * If we've come to this point, every filter that has its filter_*
	 * set to true has matched the packet. Note that this may also mean
	 * that no filter_* was set to true, i.e. this rule matches all packets.
	 */
	return rule->action;
}

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

	chain_id = array_index_nospec(chain_id, __SIMPLEPF_CHAIN_LAST);
	chain = chains[chain_id];

	mutex_lock(chain_mutexes[chain_id]);
	list_add_tail_rcu(&new->list, chain);
	mutex_unlock(chain_mutexes[chain_id]);

	return 0;
}

int simplepf_flush_chain(enum simplepf_chain_id chain_id)
{
	struct list_head *chain;
	struct chain_node *node;
	struct chain_node *n;

	if (chain_id >= __SIMPLEPF_CHAIN_LAST) {
		return -EINVAL;
	}

	chain_id = array_index_nospec(chain_id, __SIMPLEPF_CHAIN_LAST);
	chain = chains[chain_id];

	mutex_lock(chain_mutexes[chain_id]);
	list_for_each_entry_safe(node, n, chain, list) {
		list_del_rcu(&node->list);
		synchronize_rcu();
		kfree(node);
	}
	mutex_unlock(chain_mutexes[chain_id]);

	return 0;
}

enum simplepf_action simplepf_traverse_chain(enum simplepf_chain_id chain_id,
		const struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct list_head *chain;
	struct chain_node *node;

	if (chain_id >= __SIMPLEPF_CHAIN_LAST) {
		/*
		 * This should not be possible. We (the module) provide a
		 * hardcoded chain id, so the chain id is not an arbitrary input.
		 * This may indicate a programming error.
		 */
		printk(KERN_DEBUG "simplepf: Chain id (=%d) out of range. "
				"Accepting packet. "
				"This may be a bug.\n", chain_id);
		return SIMPLEPF_ACTION_ACCEPT;
	}

	/*
	 * No Spectre stuff because chain_id is not user input.
	 */
	chain = chains[chain_id];

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

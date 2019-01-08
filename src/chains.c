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

struct simplepf_chain_node {
	struct list_head node;

	/*
	 * TODO: Reconsider the types.
	 *
	 * XXX: We're wasting space with this scheme. Can we find a better way
	 * for checking the filter options?
	 */

	int filter_saddr;
	int ip_saddr;

	int filter_daddr;
	int ip_daddr;

	int filter_proto;
	int ip_protocol;

	int filter_sport;
	int transport_sport;

	int filter_dport;
	int transport_dport;

	enum simplepf_action action;
};

/*
 * Chains are RCU protected linked lists.
 */
static LIST_HEAD(input_chain);
static LIST_HEAD(output_chain);

static struct list_head *chains[__SIMPLEPF_CHAIN_LAST] = {
	[SIMPLEPF_CHAIN_INPUT] = &input_chain,
	[SIMPLEPF_CHAIN_OUTPUT] = &output_chain
};

/*
 * TODO: Default actions are ACCEPT for the time being.
 * These will be set by userspace in the future.
 */
static enum simplepf_action default_actions[__SIMPLEPF_CHAIN_LAST] = {
	[SIMPLEPF_CHAIN_INPUT] = SIMPLEPF_ACTION_ACCEPT,
	[SIMPLEPF_CHAIN_OUTPUT] = SIMPLEPF_ACTION_ACCEPT,
};

/*
 * TODO: Implement actual chain traversal.
 * Obviously the chain must be set up first.
 */
enum simplepf_action simplepf_traverse_chain(enum simplepf_chain_id chain_id,
		const struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct list_head *chain;

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

	return default_actions[chain_id];
}

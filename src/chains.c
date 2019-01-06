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

/*
 * TODO: This will be a list that will be filled by input from userspace.
 * Most likely we'll need to use a synchronization mechanism like RCU.
 */
struct chain_node {
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
 * TODO: Default actions are ACCEPT for the time being.
 * These will be set by userspace in the future.
 */
static enum simplepf_action default_actions[__SIMPLEPF_CHAIN_LAST] = {
	[SIMPLEPF_CHAIN_INPUT] = SIMPLEPF_ACTION_ACCEPT,
	[SIMPLEPF_CHAIN_OUTPUT] = SIMPLEPF_ACTION_ACCEPT,
};

/*
 * TODO: Fill this array.
 */
static struct simplepf_chain_node *chains[__SIMPLEPF_CHAIN_LAST] = {
	[SIMPLEPF_CHAIN_INPUT] = NULL,
	[SIMPLEPF_CHAIN_OUTPUT] = NULL
};

/*
 * TODO: Implement actual chain traversal.
 * Obviously the chain must be set up first.
 */
enum simplepf_action simplepf_traverse_chain(enum simplepf_chain_id chain_id,
		const struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	struct simplepf_chain_node *chain;

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
	/*
	 * TODO: The chain should be traversed.
	 */

	/*
	 * XXX: This is just for satisfying minimal homework specifications
	 * as quickly as possible.
	 */
	if (chain_id == SIMPLEPF_CHAIN_INPUT) {
		struct iphdr *ip_header;
		u8 addr[4];
		const char *end;
		int in4_pton_ret;

		ip_header = ip_hdr(skb);

		/*
		 * Prevent all ICMP traffic. (input)
		 */
		if (ip_header->protocol == IPPROTO_ICMP) {
			printk(KERN_INFO "simplepf: ICMP input dropped\n");
			return SIMPLEPF_ACTION_DROP;
		}

		/*
		 * XXX: IP address is hardcoded here.
		 * It will most likely change on a reboot.
		 */
		in4_pton_ret = in4_pton("192.168.122.122", -1, addr, -1, &end);

		if (in4_pton_ret == 0) {
			printk(KERN_DEBUG "simplepf: in4_pton() returned %d. "
					"This may be a bug.\n", in4_pton_ret);
			return default_actions[chain_id];
		}

		/*
		 * Prevent B from doing a telnet to Machine A.
		 */

		if (memcmp(&ip_header->saddr, addr, 4) != 0) {
			return default_actions[chain_id];
		}

		if (ip_header->protocol == IPPROTO_TCP) {
			struct tcphdr *tcp_header;

			tcp_header = tcp_hdr(skb);

			if (tcp_header->dest == htons(23)) {
				printk(KERN_INFO "simplepf: telnet input dropped\n");
				return SIMPLEPF_ACTION_DROP;
			}
		}
	} else /* if (chain_id == SIMPLEPF_CHAIN_OUTPUT) */ {
		struct iphdr *ip_header;

		ip_header = ip_hdr(skb);
		/*
		 * Prevent all ICMP traffic. (output)
		 */
		if (ip_header->protocol == IPPROTO_ICMP) {
			printk(KERN_INFO "simplepf: ICMP output dropped\n");
			return SIMPLEPF_ACTION_DROP;
		}
	}

	return default_actions[chain_id];
}

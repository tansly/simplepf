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

#ifndef _SIMPLEPF_CHAINS_H
#define _SIMPLEPF_CHAINS_H

#include "uapi/simplepf.h"

#include <linux/skbuff.h>
#include <linux/netfilter.h>

/*
 * Flush the chain with the given id. Frees allocated resources as well.
 * Returns 0 on success.
 * Returns -EINVAL if chain_id does not specify a valid chain.
 */
int simplepf_flush_chain(enum simplepf_chain_id chain_id);

/*
 * Traverses a chain, returns the action determined by the chain.
 * @skb and @state are the pointers that are passed by netfilter to our hook.
 * Validity of skb (!= NULL) is checked by the hook; so this function assumes
 * that it is non-null.
 * @chain_id is the id of the chain to be traversed.
 * Returns a simplepf action.
 * XXX: Do we need the hook state?
 */
enum simplepf_action simplepf_traverse_chain(enum simplepf_chain_id chain_id,
		const struct sk_buff *skb,
		const struct nf_hook_state *state);

/*
 * Add (append) the given rule to the chain with the given ID.
 * Returns 0 on success.
 * Returns -EINVAL if chain_id does not specify a valid chain.
 * Returns -ENOMEM on memory allocation failure.
 * Handles the synchronization among concurrent readers/writers;
 * safe to call concurrently.
 */
int simplepf_add_rule(enum simplepf_chain_id chain_id,
		const struct simplepf_rule *rule);

/*
 * Convert a simplepf return value to a netfilter value.
 * SIMPLEPF_ACTION_ACCEPT -> NF_ACCEPT
 * SIMPLEPF_ACTION_DROP -> NF_DROP
 */
static inline int simplepf_to_nf(enum simplepf_action action)
{
	switch (action) {
	case SIMPLEPF_ACTION_ACCEPT:
		return NF_ACCEPT;
	case SIMPLEPF_ACTION_DROP:
		return NF_DROP;
	default:
		printk(KERN_DEBUG "simplepf: Action id (=%d) out of range. "
				"Accepting packet. This may be a bug", action);
		return NF_ACCEPT;
	}
}

#endif	/* _SIMPLEPF_CHAINS_H */

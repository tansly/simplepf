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
 * TODO: Consider finding a better place to define this function.
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

/*
 * Traverses a chain, returns the action determined by the chain.
 * @skb and @state are the pointers that are passed by netfilter to our hook.
 * Validity of skb (!= NULL) is checked by the hook; so this function assumes
 * that it is non-null.
 * @chain_id is the id of the chain to be traversed.
 * Returns a simplepf action.
 */
enum simplepf_action simplepf_traverse_chain(enum simplepf_chain_id chain_id,
		const struct sk_buff *skb,
		const struct nf_hook_state *state);

#endif	/* _SIMPLEPF_CHAINS_H */

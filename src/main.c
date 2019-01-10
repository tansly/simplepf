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

#include "uapi/simplepf.h"
#include "chains.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/socket.h>

/*
 * Following hooks check the validity of skb and if valid, passes them to
 * simplepf_traverse_chain. They translate the simplepf action they get from the
 * chain traversal to a NF action.
 * If skb is not valid, chain traversal is not invoked and a NF_ACCEPT is returned
 * immediately.
 */

static unsigned int hook_local_in(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	enum simplepf_action action;

	if (!skb) {
		return NF_ACCEPT;
	}

	action = simplepf_traverse_chain(SIMPLEPF_CHAIN_INPUT, skb, state);

	return simplepf_to_nf(action);
}

static unsigned int hook_local_out(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	enum simplepf_action action;

	if (!skb) {
		return NF_ACCEPT;
	}

	action = simplepf_traverse_chain(SIMPLEPF_CHAIN_OUTPUT, skb, state);

	return simplepf_to_nf(action);
}

static struct nf_hook_ops ops_local_in = {
	.hook = hook_local_in,
	/* struct net_device *dev, TODO: for what? */
	/* void *priv, unused */
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops ops_local_out = {
	.hook = hook_local_out,
	/* struct net_device *dev, TODO: for what? */
	/* void *priv, unused */
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST
};

static int __init simplepf_init(void)
{
	int err;

	err = nf_register_net_hook(&init_net, &ops_local_in);
	if (err)
		goto register_in_fail;

	err = nf_register_net_hook(&init_net, &ops_local_out);
	if (err)
		goto register_out_fail;

	return 0;

register_out_fail:
	nf_unregister_net_hook(&init_net, &ops_local_in);
register_in_fail:
	return err;
}

static void __exit simplepf_exit(void)
{
	nf_unregister_net_hook(&init_net, &ops_local_in);
	nf_unregister_net_hook(&init_net, &ops_local_out);

	/*
	 * At this point, we would (hopefully) have stopped new hook calls
	 * and also any new updates (by disabling whatever communication
	 * mechanism we use to communicate with the userspace).
	 *
	 * We don't need to check the return value of the following calls.
	 * The only error they can return is EINVAL if the given chain id is
	 * invalid. We are providing hardcoded id's that we know are valid.
	 * The check is only required for cases where the id may be arbitrary
	 * input from userspace.
	 */
	simplepf_flush_chain(SIMPLEPF_CHAIN_INPUT);
	simplepf_flush_chain(SIMPLEPF_CHAIN_OUTPUT);

	/*
	 * Chains are RCU-protected. Make sure all RCU callbacks are fired
	 * before unloading the module.
	 *
	 * Even though we're not using RCU callbacks, in which case this may be
	 * unnecessary, still do this just to be safe. We may need it in the
	 * future, who knows?
	 */
	rcu_barrier();
}

module_init(simplepf_init);
module_exit(simplepf_exit);

MODULE_AUTHOR("Yağmur Oymak");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple packet filtering firewall");

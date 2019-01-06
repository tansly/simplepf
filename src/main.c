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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static unsigned int hook_local_in(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	return NF_DROP;
}

static unsigned int hook_local_out(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	return NF_DROP;
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
}

module_init(simplepf_init);
module_exit(simplepf_exit);

MODULE_AUTHOR("Yağmur Oymak");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple packet filtering firewall");

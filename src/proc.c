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
#include "proc.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

/*
 * @pos is not used in this implementation.
 *
 * Only a write of a full cmd struct (sizeof(struct simplepf_cmd)) is considered
 * valid; -EINVAL is returned on invalid writes and no action is taken.
 * -EINVAL is returned if cmd.type is invalid.
 * -EFAULT  is returned if copy_from_user() fails.
 * If the called chain operation (add, flush...) returns an error, this
 * functions propagates that error.
 */
static ssize_t rules_write(struct file *filp, const char __user *buf,
		size_t nbytes, loff_t *pos)
{
	struct simplepf_cmd cmd;

	if (nbytes != sizeof cmd) {
		return -EINVAL;
	}

	if (copy_from_user(&cmd, buf, sizeof cmd)) {
		return -EFAULT;
	}

	switch (cmd.type) {
	case SIMPLEPF_CMD_ADD:
	{
		int err = simplepf_add_rule(cmd.chain_id, &cmd.rule);
		if (err) {
			return err;
		}
	}
	break;

	case SIMPLEPF_CMD_FLUSH:
	{
		int err = simplepf_flush_chain(cmd.chain_id);
		if (err) {
			return err;
		}
	}
	break;

	default:
		return -EINVAL;
	}

	/*
	 * Success
	 */
	return nbytes;
}

static struct file_operations rules_fops = {
	.owner = THIS_MODULE,
	.write = rules_write
};

/*
 * /proc/simplepf/ directory.
 */
static struct proc_dir_entry *proc_dir;

/*
 * /proc/simplepf/rules file.
 * User writes a simplepf_cmd struct to this file to manipulate the chains.
 * TODO: Define the commands and document them.
 * TODO: What to do on read? How to present existing rules to user?
 */
static struct proc_dir_entry *proc_rules;

int __init simplepf_proc_init(void)
{
	int err;

	proc_dir = proc_mkdir("simplepf", NULL);
	if (!proc_dir) {
		err = -ENOMEM;
		printk(KERN_INFO "simplepf: Failed to create /proc/simplepf\n");
		goto proc_dir_fail;
	}

	proc_rules = proc_create("rules", 0200, proc_dir, &rules_fops);
	if (!proc_rules) {
		err = -ENOMEM;
		printk(KERN_INFO "simplepf: Failed to create /proc/simplepf/rules\n");
		goto proc_rules_fail;
	}

	return 0;

proc_rules_fail:
	proc_remove(proc_dir);
proc_dir_fail:
	return err;
}

void __exit simplepf_proc_cleanup(void)
{
	proc_remove(proc_rules);
	proc_remove(proc_dir);
}

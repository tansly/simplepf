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

static int __init simplepf_init(void)
{
	pr_info("Hello: Module loaded at 0x%p\n", simplepf_init);
	return 0;
}

static void __exit simplepf_exit(void)
{
	pr_info("Bye: Module unloaded from 0x%p\n", simplepf_exit);
}

module_init(simplepf_init);
module_exit(simplepf_exit);

MODULE_AUTHOR("Yağmur Oymak");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple packet filtering firewall");

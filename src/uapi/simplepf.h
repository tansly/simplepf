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

#ifndef _SIMPLEPF_SIMPLEPF_H
#define _SIMPLEPF_SIMPLEPF_H

enum simplepf_action {
	SIMPLEPF_ACTION_ACCEPT,
	SIMPLEPF_ACTION_DROP,
	__SIMPLEPF_ACTION_LAST
};

enum simplepf_chain_id {
	SIMPLEPF_CHAIN_INPUT = 0,
	SIMPLEPF_CHAIN_OUTPUT,
	__SIMPLEPF_CHAIN_LAST
};

/*
 * Rule descriptor struct. This struct is what will be filled by userspace.
 * Each chain node will store one rule descriptor.
 * Fields that are used to match packets will be provided in network byte order.
 */
struct simplepf_rule {
	/*
	 * TODO: Reconsider the types.
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

#endif	/* _SIMPLEPF_SIMPLEPF_H */

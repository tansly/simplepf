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

#include <linux/types.h>

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
 *
 * Fields are interpreted as follows:
 *  filter_* signify that if the rule will filter according to the following field.
 *  For example, if filter_saddr is true, the rule filters by the source addr,
 *  i.e. only matches packets with hdr->saddr == rule->ip_saddr.
 *  If all of the fields that has its respective filter_* field set to true
 *  match the incoming packet, we consider it a match. Otherwise, i.e. if any
 *  of the fields do not match, there is no match and we skip the rule.
 *  Think of it as a "logical and" operation.
 *
 * Note that if none of the filter_* are set, the rule matches ALL packets.
 *  TODO: Think of alignment/padding issues.
 *  XXX: We should not let anyone set port numbers for ICMP filters or
 *  ICMP types for UDP/TCP filters.
 */
struct simplepf_rule {
	bool filter_saddr;
	__u32 ip_saddr;

	bool filter_daddr;
	__u32 ip_daddr;

	bool filter_proto;
	__u8 ip_protocol;

	bool filter_icmp_type;
	__u8 icmp_type;

	bool filter_sport;
	__u16 transport_sport;

	bool filter_dport;
	__u16 transport_dport;

	enum simplepf_action action;
};

/*
 * TODO: Document the semantics of commands once the interface is stable.
 */
enum simplepf_cmd_type {
	SIMPLEPF_CMD_ADD,
	SIMPLEPF_CMD_FLUSH,
	__SIMPLEPF_CMD_LAST
};

struct simplepf_cmd {
	enum simplepf_cmd_type type;
	enum simplepf_chain_id chain_id;
	struct simplepf_rule rule;
};

#endif	/* _SIMPLEPF_SIMPLEPF_H */

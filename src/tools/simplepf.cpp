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

#include "../uapi/simplepf.h"

#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>
#include <linux/types.h>
#include <unistd.h>

int main()
{
	int fd;
	fd = open("/proc/simplepf/rules", O_WRONLY);
	if (fd == -1) {
		perror("open()");
		return 1;
	}


	struct simplepf_cmd cmd;
	cmd.type = SIMPLEPF_CMD_ADD;
	cmd.chain_id = SIMPLEPF_CHAIN_INPUT;
	memset(&cmd.rule, 0, sizeof cmd.rule);

	cmd.rule.action = SIMPLEPF_ACTION_DROP;
	cmd.rule.filter_proto = true;
	cmd.rule.ip_protocol = IPPROTO_ICMP;
	if (write(fd, &cmd, sizeof cmd) == -1) {
		perror("write()");
		return 1;
	}

	memset(&cmd.rule, 0, sizeof cmd.rule);
	cmd.rule.action = SIMPLEPF_ACTION_DROP;
	cmd.rule.filter_proto = true;
	cmd.rule.ip_protocol = IPPROTO_ICMP;
	if (write(fd, &cmd, sizeof cmd) == -1) {
		perror("write()");
		return 1;
	}

	memset(&cmd.rule, 0, sizeof cmd.rule);
	cmd.rule.action = SIMPLEPF_ACTION_DROP;
	cmd.rule.filter_proto = true;
	cmd.rule.ip_protocol = IPPROTO_TCP;
	cmd.rule.filter_dport = htons(443);
	cmd.rule.transport_dport = htons(443);
	if (write(fd, &cmd, sizeof cmd) == -1) {
		perror("write()");
		return 1;
	}

	return 0;
}

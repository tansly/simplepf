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
#include <cerrno>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <stdexcept>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

/* Auxiliary functions for checking input for validity. */

/* Function used to check that 'opt1' and 'opt2' are not specified
   at the same time. */
void conflicting_options(const po::variables_map& vm,
		const char* opt1, const char* opt2)
{
	if (vm.count(opt1) && !vm[opt1].defaulted()
			&& vm.count(opt2) && !vm[opt2].defaulted())
		throw std::logic_error(std::string("Conflicting options '")
				+ opt1 + "' and '" + opt2 + "'.");
}

/* Function used to check that of 'for_what' is specified, then
   'required_option' is specified too. */
void option_dependency(const po::variables_map& vm,
		const char* for_what, const char* required_option)
{
	if (vm.count(for_what) && !vm[for_what].defaulted())
		if (vm.count(required_option) == 0 || vm[required_option].defaulted())
			throw std::logic_error(std::string("Option '") + for_what
					+ "' requires option '" + required_option + "'.");
}

int main(int argc, char **argv)
{
	po::options_description options_desc("Options");
	options_desc.add_options()
	("help", "print this help message")
	("add", po::value<std::string>(), "add a rule to the specified chain")
	("src", po::value<std::string>(), "source IP address (dotted decimal)")
	("dest", po::value<std::string>(), "destination IP address (dotted decimal)")
	("proto", po::value<std::string>(), "protocol; one of ICMP, TCP or UDP")
	("icmp_type", po::value<std::uint8_t>(), "ICMP type (for ICMP)")
	("sport", po::value<std::uint16_t>(), "source port number (for TCP or UDP)")
	("dport", po::value<std::uint16_t>(), "destination port number (for TCP or UDP)")
	("flush", po::value<std::string>(), "flush the specified chain")
	;

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, options_desc), vm);

	conflicting_options(vm, "flush", "add");

	option_dependency(vm, "src", "add");
	option_dependency(vm, "dest", "add");
	option_dependency(vm, "protocol", "add");
	option_dependency(vm, "icmp_type", "add");
	option_dependency(vm, "sport", "add");
	option_dependency(vm, "dport", "add");

	if (vm.count("help")) {
		std::cout << options_desc << '\n';
		return 0;
	}

	int fd;
	fd = open("/proc/simplepf/rules", O_WRONLY);
	if (fd == -1) {
		perror("open()");
		std::cerr << "Unable to open simplepf proc file\n";
		return 1;
	}

	struct simplepf_cmd cmd;
	std::memset(&cmd, 0, sizeof cmd);

	if (vm.count("flush")) {
		cmd.type = SIMPLEPF_CMD_FLUSH;

		auto chain_name {vm["flush"].as<std::string>()};
		if (chain_name == "input") {
			cmd.chain_id = SIMPLEPF_CHAIN_INPUT;
		} else if (chain_name == "output") {
			cmd.chain_id = SIMPLEPF_CHAIN_OUTPUT;
		} else {
			std::cerr << "Chain name invalid. Must be input or output.\n";
			return 1;
		}

		if (write(fd, &cmd, sizeof cmd) == -1) {
			perror("write()");
			return 1;
		}

		return 0;
	}

	if (vm.count("add")) {
		cmd.type = SIMPLEPF_CMD_ADD;

		cmd.rule.action = SIMPLEPF_ACTION_DROP;

		auto chain_name {vm["add"].as<std::string>()};
		if (chain_name == "input") {
			cmd.chain_id = SIMPLEPF_CHAIN_INPUT;
		} else if (chain_name == "output") {
			cmd.chain_id = SIMPLEPF_CHAIN_OUTPUT;
		} else {
			std::cerr << "Chain name invalid. Must be input or output.\n";
			return 1;
		}

		if (vm.count("src")) {
			cmd.rule.filter_saddr = true;

			struct in_addr inaddr;
			/*
			 * inet_pton() returns 1 on success.
			 * It's a crying shame, innit?
			 */
			if (inet_pton(AF_INET, vm["src"].as<std::string>().c_str(), &inaddr) == 0) {
				perror("inet_pton");
				return 1;
			}

			cmd.rule.ip_saddr = inaddr.s_addr;
		}

		if (vm.count("dest")) {
			cmd.rule.filter_daddr = true;

			struct in_addr inaddr;
			/*
			 * inet_pton() returns 1 on success.
			 * It's a crying shame, innit?
			 */
			if (inet_pton(AF_INET, vm["dest"].as<std::string>().c_str(), &inaddr) == 0) {
				perror("inet_pton");
				return 1;
			}

			cmd.rule.ip_daddr = inaddr.s_addr;
		}

		if (vm.count("proto")) {
			cmd.rule.filter_proto = true;

			auto proto = vm["proto"].as<std::string>();
			if (proto == "icmp") {
				cmd.rule.ip_protocol = IPPROTO_ICMP;
			} else if (proto == "tcp") {
				cmd.rule.ip_protocol = IPPROTO_TCP;
			} else if (proto == "udp") {
				cmd.rule.ip_protocol = IPPROTO_UDP;
			} else {
				std::cerr << "Invalid or unsupported protocol.\n";
				return 1;
			}
		}

		if (vm.count("sport")) {
			cmd.rule.filter_sport = true;

			cmd.rule.transport_sport = htons(vm["sport"].as<std::uint16_t>());
		}

		if (vm.count("dport")) {
			cmd.rule.filter_sport = true;

			cmd.rule.transport_sport = htons(vm["dport"].as<std::uint16_t>());
		}

		if (vm.count("icmp_type")) {
			cmd.rule.filter_icmp_type = true;

			cmd.rule.icmp_type = vm["icmp_type"].as<std::uint8_t>();
		}

		/*
		 * Ready to fire the command.
		 */
		if (write(fd, &cmd, sizeof cmd) == -1) {
			perror("write()");
			return 1;
		}
	}

	return 0;
}

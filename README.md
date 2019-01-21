# simplepf
simplepf is a simple packet filtering firewall module for the Linux kernel,
written using the netfilter framework.

It started as the third homework of CENG489 (Introduction to Computer Security)
that I took in 2018 Fall at METU, but it turned out to be an introduction
to Linux kernel programming for me.

## Configuration interface
When loaded, the module exposes a file in `procfs`, `/proc/simplepf/rules`.
Rules can be configured by writing `struct simplepf_cmd` structures to this file.
See the header file `./src/uapi/simplepf.h` for a detailed explanation of the API.

## Userspace helper
There is a userspace helper program (in `./src/tools/) that constructs a
`struct simplepf_cmd` according to its command line arguments and writes it
to the proc file. It is written in C++ and uses Boost's program options library,
so Boost is required to build and run it. (tested with Boost 1.66)

Its `--help` option summarizes its usage. It is not very user friendly and does
not try to do much input checking etc. but should still work.

## What can be improved
* Make the default action configurable. However, in this kind of a stateless
packet filter, a default deny action would require lots of open ports to operate
properly. So, for this to be practical, there needs to be a way of matching
a range of ports and IP addresses in rules.
* Dump the rule list in effect to userspace.
* Add a way to remove a specific rule.
* Filter traffic only in specified interfaces.
* Log matched packets, of course without giving an attacker too much opportunities
for a DoS attack.

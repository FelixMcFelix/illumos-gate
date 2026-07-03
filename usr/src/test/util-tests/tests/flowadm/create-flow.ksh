#! /usr/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2026 Oxide Computer Company
#

# These tests assert that flow priorties and other properties configured on a
# flow during creation are accurately reflected in MAC itself.
#
# Since these rely on mdb output, these tests will need to be revisited if
# any of the darastructures are modified, enums renumbered, etc. If these tests
# are significantly expanded in future it would be worth pulling these internal
# checks to a ktest(8) module.

unalias -a
set -o pipefail
export LANG=C.UTF-8

fl_exit=0
fl_stub="UTILtest_stub$$"
fl_vnic="UTILtest_vnic$$"
fl_flow="UTILtest_flow$$"

typeset -A fl_prio_opts
fl_prio_opts["none"]=""
fl_prio_opts["low"]="-ppriority=low"
fl_prio_opts["medium"]="-ppriority=medium"
fl_prio_opts["high"]="-ppriority=high"

typeset -A fl_prios
fl_prios["none"]=""
fl_prios["low"]="MPL_LOW"
fl_prios["medium"]="MPL_MEDIUM"
fl_prios["high"]="MPL_HIGH"

function fatal
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	exit 1
}

function warn
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	fl_exit=1
}

function cleanup
{
	dladm delete-vnic ${fl_vnic} 2> /dev/null
	dladm delete-etherstub ${fl_stub} 2>/dev/null
}

function setup
{
	typeset ret
	dladm create-etherstub ${fl_stub} || \
		fatal "failed to create stub ${fl_stub}"

	dladm create-vnic -l ${fl_stub} ${fl_vnic}
	ret=$?

	if (( ret != 0 )); then
		cleanup
		fatal "failed to create vnic ${fl_vnic}"
	fi
}

function test_create_with_priority_inner
{
	typeset kdb_prio="${fl_prios[$2]}"

	typeset flow_addr=$(mdb -ke "::mac_flow" | \
		awk -v fname="${fl_flow}" '$2 == fname { print $1 }')

	if [[ -z $flow_addr ]]; then
		warn "$1($2) -- could not find flow ${fl_flow} in mdb"
		return
	fi

	typeset flow_flags=$(mdb -ke \
		"${flow_addr}::print flow_entry_t fe_effective_props.mrp_mask" \
		| awk '{ print $3 }')
	typeset flow_prio=$(mdb -ke \
		"${flow_addr}::print flow_entry_t fe_effective_props.mrp_priority" \
		| awk '{ print $4 }' | tr -d '()')

	typeset expt_prio="MPL_MEDIUM"
	if [[ $2 != "none" ]]; then
		expt_prio="${fl_prios[$2]}"
	fi

	if [[ $flow_flags != "0x8" ]] || [[ $flow_prio != $expt_prio ]]; then
		warn "$1($2) -- prio/flags are ${flow_prio}/${flow_flags}, " \
			"wanted ${expt_prio}/0x8"
	fi
}

function test_create_with_priority
{
	typeset ret=0

	typeset flags="${fl_prio_opts[$1]}"

	flowadm add-flow -l ${fl_vnic} -a transport=udp,local_port=2020 \
		${flags} ${fl_flow} || fatal "$0($1) -- failed to create flow"
	test_create_with_priority_inner $0 $1
	flowadm remove-flow ${fl_flow} || fatal "$0($1) -- failed to delete flow"
}

trap cleanup EXIT

setup
for c in "${!fl_prio_opts[@]}"; do
	test_create_with_priority $c
done
cleanup

if (( fl_exit == 0 )); then
	printf "All tests passed successfully\n"
fi
exit $fl_exit

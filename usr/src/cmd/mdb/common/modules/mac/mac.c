/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2026 Oxide COmputer Company
 */

#include <sys/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/types.h>
#include <inet/ip.h>
#include <inet/ip6.h>

#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_client.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_flow_impl.h>
#include <sys/mac_soft_ring.h>
#include <sys/mac_stat.h>

#define	STRSIZE	64
#define	MAC_RX_SRS_SIZE	 (MAX_RINGS_PER_GROUP * sizeof (uintptr_t))

#define	LAYERED_WALKER_FOR_FLOW	"flow_entry_cache"
#define	LAYERED_WALKER_FOR_SRS	"mac_srs_cache"
#define	LAYERED_WALKER_FOR_RING	"mac_ring_cache"
#define	LAYERED_WALKER_FOR_GROUP	"mac_impl_cache"

/* arguments passed to mac_flow dee-command */
#define	MAC_FLOW_NONE	0x01
#define	MAC_FLOW_ATTR	0x02
#define	MAC_FLOW_PROP	0x04
#define	MAC_FLOW_RX	0x08
#define	MAC_FLOW_TX	0x10
#define	MAC_FLOW_USER	0x20
#define	MAC_FLOW_STATS	0x40
#define	MAC_FLOW_MISC	0x80

/* arguments passed to mac_srs dee-command */
#define	MAC_SRS_NONE		0x00
#define	MAC_SRS_RX		0x01
#define	MAC_SRS_TX		0x02
#define	MAC_SRS_STAT		0x04
#define	MAC_SRS_CPU		0x08
#define	MAC_SRS_VERBOSE		0x10
#define	MAC_SRS_INTR		0x20
#define	MAC_SRS_RXSTAT		(MAC_SRS_RX|MAC_SRS_STAT)
#define	MAC_SRS_TXSTAT		(MAC_SRS_TX|MAC_SRS_STAT)
#define	MAC_SRS_RXCPU		(MAC_SRS_RX|MAC_SRS_CPU)
#define	MAC_SRS_TXCPU		(MAC_SRS_TX|MAC_SRS_CPU)
#define	MAC_SRS_RXCPUVERBOSE	(MAC_SRS_RXCPU|MAC_SRS_VERBOSE)
#define	MAC_SRS_TXCPUVERBOSE	(MAC_SRS_TXCPU|MAC_SRS_VERBOSE)
#define	MAC_SRS_RXINTR		(MAC_SRS_RX|MAC_SRS_INTR)
#define	MAC_SRS_TXINTR		(MAC_SRS_TX|MAC_SRS_INTR)

/* arguments passed to mac_group dcmd */
#define	MAC_GROUP_NONE		0x00
#define	MAC_GROUP_RX		0x01
#define	MAC_GROUP_TX		0x02
#define	MAC_GROUP_UNINIT	0x04

static char *
mac_flow_proto2str(uint8_t protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return ("tcp");
	case IPPROTO_UDP:
		return ("udp");
	case IPPROTO_SCTP:
		return ("sctp");
	case IPPROTO_ICMP:
		return ("icmp");
	case IPPROTO_ICMPV6:
		return ("icmpv6");
	default:
		return ("--");
	}
}

static char *
mac_flow_priority2str(mac_priority_level_t prio)
{
	switch (prio) {
	case MPL_LOW:
		return ("low");
	case MPL_MEDIUM:
		return ("medium");
	case MPL_HIGH:
		return ("high");
	case MPL_RESET:
		return ("reset");
	default:
		return ("--");
	}
}

/*
 *  Convert bandwidth in bps to a string in Mbps.
 */
static char *
mac_flow_bw2str(uint64_t bw, char *buf, ssize_t len)
{
	int kbps, mbps;

	kbps = (bw % 1000000)/1000;
	mbps = bw/1000000;
	if ((mbps == 0) && (kbps != 0))
		mdb_snprintf(buf, len, "0.%03u", kbps);
	else
		mdb_snprintf(buf, len, "%5u", mbps);
	return (buf);
}

static void
mac_flow_print_header(uint_t args)
{
	switch (args) {
	case MAC_FLOW_NONE:
		mdb_printf("%?s %-20s %4s %?s %?s %-16s\n",
		    "", "", "LINK", "", "", "MIP");
		mdb_printf("%<u>%?s %-20s %4s %?s %?s %-16s%</u>\n",
		    "ADDR", "FLOW NAME", "ID", "MCIP", "MIP", "NAME");
		break;
	case MAC_FLOW_ATTR:
		mdb_printf("%<u>%?s %-32s %-7s %6s "
		    "%-9s %s%</u>\n",
		    "ADDR", "FLOW NAME", "PROTO", "PORT",
		    "DSFLD:MSK", "IPADDR");
		break;
	case MAC_FLOW_PROP:
		mdb_printf("%<u>%?s %-32s %8s %9s%</u>\n",
		    "ADDR", "FLOW NAME", "MAXBW(M)", "PRIORITY");
		break;
	case MAC_FLOW_MISC:
		mdb_printf("%<u>%?s %-24s %10s %10s "
		    "%20s %4s%</u>\n",
		    "ADDR", "FLOW NAME", "TYPE", "FLAGS",
		    "MATCH_FN", "ZONE");
		break;
	case MAC_FLOW_RX:
		mdb_printf("%?s %-24s %3s %s\n", "", "", "SRS", "RX");
		mdb_printf("%<u>%?s %-24s %3s %s%</u>\n",
		    "ADDR", "FLOW NAME", "CNT", "SRS");
		break;
	case MAC_FLOW_TX:
		mdb_printf("%<u>%?s %-32s %?s %</u>\n",
		    "ADDR", "FLOW NAME", "TX_SRS");
		break;
	case MAC_FLOW_STATS:
		mdb_printf("%<u>%?s %-32s %16s %16s%</u>\n",
		    "ADDR", "FLOW NAME", "RBYTES", "OBYTES");
		break;
	}
}

typedef struct mdb_mac_impl {
	char		mi_name[MAXNAMELEN];
	uintptr_t	mi_rx_groups;
	uintptr_t	mi_tx_groups;
} mdb_mac_impl_t;

typedef struct mdb_mac_client_impl {
	char		mci_name[MAXNAMELEN];
	uintptr_t	mci_mip;
} mdb_mac_client_impl_t;

typedef struct mdb_mac_soft_ring_set {
	/*
	 * mdb_ctf_vread cannot handle flagset-type enums.
	 * The corresponding types are mac_soft_ring_set_type_t and
	 * mac_soft_ring_set_state_t.
	 */
	uint32_t	srs_type;
	uint32_t	srs_state;

	uintptr_t	srs_mcip;
	uintptr_t	srs_flent;
	size_t		srs_size;
	uint32_t	srs_count;
	int		srs_soft_ring_count;
	uintptr_t	srs_soft_ring_head;
	int		srs_tx_ring_count;
	uintptr_t	srs_ring;

	struct {
		mac_tx_srs_mode_t	st_mode;
		uintptr_t		st_arg2;
		struct {
			uint64_t	mts_obytes;
			uint64_t	mts_sdrops;
			uint64_t	mts_blockcnt;
			uint64_t	mts_unblockcnt;
		} st_stat;
	} srs_tx;

	struct {
		struct {
			uint64_t	mrs_intrbytes;
			uint64_t	mrs_pollbytes;
			uint64_t	mrs_lclbytes;
			uint64_t	mrs_intrcnt;
			uint64_t	mrs_pollcnt;
			uint64_t	mrs_lclcnt;
			uint64_t	mrs_chaincntundr10;
			uint64_t	mrs_chaincnt10to50;
			uint64_t	mrs_chaincntover50;
		} sr_stat;
	} srs_rx;

	struct {
		uint32_t	mc_ncpus;
		uint32_t	mc_cpus[MRP_NCPUS];
		uint32_t	mc_rx_pollid;
		uint32_t	mc_rx_workerid;
		uint32_t	mc_rx_fanout_cnt;
		uint32_t	mc_rx_fanout_cpus[MRP_NCPUS];
		int32_t		mc_rx_intr_cpu;
		int32_t		mc_tx_fanout_cpus[MRP_NCPUS];
		struct {
			int32_t		mtc_intr_cpu[MRP_NCPUS];
			int32_t		mtc_retargeted_cpu[MRP_NCPUS];
		} mc_tx_intr_cpus;
	} srs_cpu;
} mdb_mac_soft_ring_set_t;

typedef struct mdb_mac_ring {
	struct {
		struct {
			boolean_t	mi_ddi_shared;
		} mri_intr;
	} mr_info;
	uintptr_t		mr_srs;
	mac_ring_type_t 	mr_type;
	mac_ring_state_t	mr_state;
	uint_t			mr_flag;
	uintptr_t		mr_gh;
	mac_classify_type_t	mr_classify_type;
} mdb_mac_ring_t;

typedef struct mdb_mac_soft_ring {
	uintptr_t	s_ring_next;
	uintptr_t	s_ring_tx_arg2;

	struct {
		uint64_t	mts_sdrops;
		uint64_t	mts_blockcnt;
		uint64_t	mts_unblockcnt;
	} s_st_stat;
} mdb_mac_soft_ring_t;

typedef struct mdb_flow_entry {
	/*
	 * mdb_ctf_vread cannot handle flagset-type enums.
	 * The corresponding types are flow_entry_type_t and
	 * flow_entry_flags_t.
	 */
	uint32_t	fe_type;
	uint32_t	fe_flags;

	char		fe_flow_name[MAXFLOWNAMELEN];
	uint32_t	fe_rx_srs_cnt;
	uintptr_t	fe_rx_srs[MAX_RINGS_PER_GROUP];
	uintptr_t	fe_tx_srs;
	uintptr_t	fe_mcip;
	uintptr_t	fe_match;
	datalink_id_t	fe_link_id;
	struct {
		uint64_t		mrp_maxbw;
		mac_priority_level_t	mrp_priority;
	} fe_resource_props;
	// flow_desc_t		fe_flow_desc
} mdb_flow_entry_t;

typedef struct mdb_mac_group {
	mac_ring_type_t		mrg_type;
	mac_group_state_t	mrg_state;
	uintptr_t		mrg_mh;
	uintptr_t		mrg_next;
	uintptr_t		mrg_clients;
	uint_t			mrg_cur_count;
	uintptr_t		mrg_rings;
} mdb_mac_group_t;

typedef struct mdb_mac_grp_client {
	uintptr_t	mgc_next;
} mdb_mac_grp_client_t;

/*
 * Display selected fields of the flow_entry_t structure
 */
static int
mac_flow_dcmd_output(uintptr_t addr, uint_t flags, uint_t args)
{
	static const mdb_bitmask_t flow_type_bits[] = {
		{"P", FLOW_PRIMARY_MAC, FLOW_PRIMARY_MAC},
		{"V", FLOW_VNIC_MAC, FLOW_VNIC_MAC},
		{"M", FLOW_MCAST, FLOW_MCAST},
		{"O", FLOW_OTHER, FLOW_OTHER},
		{"U", FLOW_USER, FLOW_USER},
		{"V", FLOW_VNIC, FLOW_VNIC},
		{"NS", FLOW_NO_STATS, FLOW_NO_STATS},
		{ NULL, 0, 0 }
	};
#define	FLOW_MAX_TYPE	(sizeof (flow_type_bits) / sizeof (mdb_bitmask_t))

	static const mdb_bitmask_t flow_flag_bits[] = {
		{"Q", FE_QUIESCE, FE_QUIESCE},
		{"W", FE_WAITER, FE_WAITER},
		{"T", FE_FLOW_TAB, FE_FLOW_TAB},
		{"G", FE_G_FLOW_HASH, FE_G_FLOW_HASH},
		{"I", FE_INCIPIENT, FE_INCIPIENT},
		{"C", FE_CONDEMNED, FE_CONDEMNED},
		{"NU", FE_UF_NO_DATAPATH, FE_UF_NO_DATAPATH},
		{"NC", FE_MC_NO_DATAPATH, FE_MC_NO_DATAPATH},
		{ NULL, 0, 0 }
	};
#define	FLOW_MAX_FLAGS	(sizeof (flow_flag_bits) / sizeof (mdb_bitmask_t))
	mdb_flow_entry_t	fe;
	mdb_mac_client_impl_t	mcip;
	mdb_mac_impl_t		mip;

	if (mdb_ctf_vread(&fe, "flow_entry_t",
	    "mdb_flow_entry_t", addr, 0) == -1) {
		mdb_warn("failed to read struct flow_entry_s at %p",
		    addr);
		return (DCMD_ERR);
	}
	if (args & MAC_FLOW_USER) {
		args &= ~MAC_FLOW_USER;
		if (fe.fe_type & FLOW_MCAST) {
			if (DCMD_HDRSPEC(flags))
				mac_flow_print_header(args);
			return (DCMD_OK);
		}
	}
	if (DCMD_HDRSPEC(flags))
		mac_flow_print_header(args);
	bzero(&mcip, sizeof (mcip));
	bzero(&mip, sizeof (mip));
	if (fe.fe_mcip != (uintptr_t)NULL && mdb_ctf_vread(&mcip,
	   "mac_client_impl_t", "mdb_mac_client_impl_t", fe.fe_mcip, 0) != -1) {
		(void) mdb_ctf_vread(&mip, "mac_impl_t", "mdb_mac_impl_t",
		    mcip.mci_mip, 0);
	}
	switch (args) {
	case MAC_FLOW_NONE: {
		mdb_printf("%?p %-20s %4d %?p "
		    "%?p %-16s\n",
		    addr, fe.fe_flow_name, fe.fe_link_id, fe.fe_mcip,
		    mcip.mci_mip, mip.mi_name);
		break;
	}
	case MAC_FLOW_ATTR: {
		struct	in_addr	in4;
		uintptr_t	desc_addr;
		flow_desc_t	fdesc;

		// TODO(ky)
		desc_addr = addr + OFFSETOF(flow_entry_t, fe_flow_desc);
		if (mdb_vread(&fdesc, sizeof (fdesc), desc_addr) == -1) {
			mdb_warn("failed to read struct flow_description at %p",
			    desc_addr);
			return (DCMD_ERR);
		}
		mdb_printf("%?p %-32s "
		    "%-7s %6d "
		    "%4d:%-4d ",
		    addr, fe.fe_flow_name,
		    mac_flow_proto2str(fdesc.fd_protocol), fdesc.fd_local_port,
		    fdesc.fd_dsfield, fdesc.fd_dsfield_mask);
		if (fdesc.fd_ipversion == IPV4_VERSION) {
			IN6_V4MAPPED_TO_INADDR(&fdesc.fd_local_addr, &in4);
			mdb_printf("%I", in4.s_addr);
		} else if (fdesc.fd_ipversion == IPV6_VERSION) {
			mdb_printf("%N", &fdesc.fd_local_addr);
		} else {
			mdb_printf("%s", "--");
		}
		mdb_printf("\n");
		break;
	}
	case MAC_FLOW_PROP: {
		char		bwstr[STRSIZE];
		mdb_printf("%?p %-32s "
		    "%8s %9s\n",
		    addr, fe.fe_flow_name,
		    mac_flow_bw2str(fe.fe_resource_props.mrp_maxbw, bwstr,
		    STRSIZE),
		    mac_flow_priority2str(fe.fe_resource_props.mrp_priority));
		break;
	}
	case MAC_FLOW_MISC: {
		char		flow_flags[2 * FLOW_MAX_FLAGS];
		char		flow_type[2 * FLOW_MAX_TYPE];
		GElf_Sym	sym;
		char		func_name[MDB_SYM_NAMLEN] = "";

		(void) mdb_lookup_by_addr(fe.fe_match, MDB_SYM_EXACT, func_name,
		    MDB_SYM_NAMLEN, &sym);
		mdb_snprintf(flow_flags, 2 * FLOW_MAX_FLAGS, "%hb",
		    fe.fe_flags, flow_flag_bits);
		mdb_snprintf(flow_type, 2 * FLOW_MAX_TYPE, "%hb",
		    fe.fe_type, flow_type_bits);
		mdb_printf("%?p %-24s %10s %10s %20s\n",
		    addr, fe.fe_flow_name, flow_type, flow_flags, func_name);
		break;
	}
	case MAC_FLOW_RX: {
		mdb_printf("%?p %-24s %3d ",
		    addr, fe.fe_flow_name, fe.fe_rx_srs_cnt);
		for (int i = 0; i < MAX_RINGS_PER_GROUP; i++) {
			if (fe.fe_rx_srs[i] == (uintptr_t)NULL)
				continue;
			mdb_printf("%p ", fe.fe_rx_srs[i]);
		}
		mdb_printf("\n");
		break;
	}
	case MAC_FLOW_TX: {
		mdb_printf("%?p %-32s %?p\n",
		    addr, fe.fe_flow_name, fe.fe_tx_srs);
		break;
	}
	case MAC_FLOW_STATS: {
		uint64_t		totibytes = 0;
		uint64_t		totobytes = 0;
		mdb_mac_soft_ring_set_t	srs;
		int			i;

		/*
		 * Sum bytes for all Rx SRS.
		 */
		for (i = 0; i < fe.fe_rx_srs_cnt; i++) {
			if (mdb_ctf_vread(&srs, "mac_soft_ring_set_t",
			    "mdb_mac_soft_ring_set_t", fe.fe_rx_srs[i],
			    0) == -1) {
				mdb_warn("failed to read mac_rx_stats_t at %p",
				    fe.fe_rx_srs[i]);
				return (DCMD_ERR);
			}

			totibytes += srs.srs_rx.sr_stat.mrs_intrbytes +
			    srs.srs_rx.sr_stat.mrs_pollbytes +
			    srs.srs_rx.sr_stat.mrs_lclbytes;
		}

		/*
		 * Sum bytes for Tx SRS.
		 */
		if (fe.fe_tx_srs != (uintptr_t)NULL) {
			if (mdb_ctf_vread(&srs, "mac_soft_ring_set_t",
			    "mdb_mac_soft_ring_set_t", fe.fe_tx_srs,
			    0) == -1) {
				mdb_warn("failed to read mac_rx_stats_t at %p",
				    fe.fe_tx_srs);
				return (DCMD_ERR);
			}

			totobytes = srs.srs_tx.st_stat.mts_obytes;
		}

		mdb_printf("%?p %-32s %16llu %16llu\n",
		    addr, fe.fe_flow_name, totibytes, totobytes);

		break;
	}
	}
	return (DCMD_OK);
}

/*
 * Parse the arguments passed to the dcmd and print all or one flow_entry_t
 * structures
 */
static int
mac_flow_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t	args = 0;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("mac_flow", "mac_flow", argc, argv) == -1) {
			mdb_warn("failed to walk 'mac_flow'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if ((mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, MAC_FLOW_ATTR, &args,
	    'p', MDB_OPT_SETBITS, MAC_FLOW_PROP, &args,
	    'm', MDB_OPT_SETBITS, MAC_FLOW_MISC, &args,
	    'r', MDB_OPT_SETBITS, MAC_FLOW_RX, &args,
	    't', MDB_OPT_SETBITS, MAC_FLOW_TX, &args,
	    's', MDB_OPT_SETBITS, MAC_FLOW_STATS, &args,
	    'u', MDB_OPT_SETBITS, MAC_FLOW_USER, &args,
	    NULL) != argc)) {
		return (DCMD_USAGE);
	}
	if (argc > 2 || (argc == 2 && !(args & MAC_FLOW_USER)))
		return (DCMD_USAGE);
	/*
	 * If no arguments was specified or just "-u" was specified then
	 * we default to printing basic information of flows.
	 */
	if (args == 0 || args == MAC_FLOW_USER)
		args |= MAC_FLOW_NONE;

	return (mac_flow_dcmd_output(addr, flags, args));
}

static void
mac_flow_help(void)
{
	mdb_printf("If an address is specified, then flow_entry structure at "
	    "that address is printed. Otherwise all the flows in the system "
	    "are printed.\n");
	mdb_printf("Options:\n"
	    "\t-u\tdisplay user defined link & vnic flows.\n"
	    "\t-a\tdisplay flow attributes\n"
	    "\t-p\tdisplay flow properties\n"
	    "\t-r\tdisplay rx side information\n"
	    "\t-t\tdisplay tx side information\n"
	    "\t-s\tdisplay flow statistics\n"
	    "\t-m\tdisplay miscellaneous flow information\n\n");
	mdb_printf("%<u>Interpreting Flow type and Flow flags output.%</u>\n");
	mdb_printf("Flow Types:\n");
	mdb_printf("\t  P --> FLOW_PRIMARY_MAC\n");
	mdb_printf("\t  V --> FLOW_VNIC_MAC\n");
	mdb_printf("\t  M --> FLOW_MCAST\n");
	mdb_printf("\t  O --> FLOW_OTHER\n");
	mdb_printf("\t  U --> FLOW_USER\n");
	mdb_printf("\t NS --> FLOW_NO_STATS\n\n");
	mdb_printf("Flow Flags:\n");
	mdb_printf("\t  Q --> FE_QUIESCE\n");
	mdb_printf("\t  W --> FE_WAITER\n");
	mdb_printf("\t  T --> FE_FLOW_TAB\n");
	mdb_printf("\t  G --> FE_G_FLOW_HASH\n");
	mdb_printf("\t  I --> FE_INCIPIENT\n");
	mdb_printf("\t  C --> FE_CONDEMNED\n");
	mdb_printf("\t NU --> FE_UF_NO_DATAPATH\n");
	mdb_printf("\t NC --> FE_MC_NO_DATAPATH\n");
}

/*
 * called once by the debugger when the mac_flow walk begins.
 */
static int
mac_flow_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk(LAYERED_WALKER_FOR_FLOW, wsp) == -1) {
		mdb_warn("failed to walk 'mac_flow'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

/*
 * Common walker step funciton for flow_entry_t, mac_soft_ring_set_t and
 * mac_ring_t.
 *
 * Steps through each flow_entry_t and calls the callback function. If the
 * user executed ::walk mac_flow, it just prints the address or if the user
 * executed ::mac_flow it displays selected fields of flow_entry_t structure
 * by calling "mac_flow_dcmd"
 */
static int
mac_common_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	return (status);
}

static char *
mac_srs_txmode2str(mac_tx_srs_mode_t mode)
{
	switch (mode) {
	case SRS_TX_DEFAULT:
		return ("DEF");
	case SRS_TX_SERIALIZE:
		return ("SER");
	case SRS_TX_FANOUT:
		return ("FO");
	case SRS_TX_BW:
		return ("BW");
	case SRS_TX_BW_FANOUT:
		return ("BWFO");
	case SRS_TX_AGGR:
		return ("AG");
	case SRS_TX_BW_AGGR:
		return ("BWAG");
	}
	return ("--");
}

static void
mac_srs_help(void)
{
	mdb_printf("If an address is specified, then mac_soft_ring_set "
	    "structure at that address is printed. Otherwise all the "
	    "SRS in the system are printed.\n");
	mdb_printf("Options:\n"
	    "\t-r\tdisplay recieve side SRS structures\n"
	    "\t-t\tdisplay transmit side SRS structures\n"
	    "\t-s\tdisplay statistics for RX or TX side\n"
	    "\t-c\tdisplay CPU binding for RX or TX side\n"
	    "\t-v\tverbose flag for CPU binding to list cpus\n"
	    "\t-i\tdisplay mac_ring_t and interrupt information\n"
	    "Note: use -r or -t (to specify RX or TX side respectively) along "
	    "with -c or -s\n");
	mdb_printf("\n%<u>Interpreting TX Modes%</u>\n");
	mdb_printf("\t DEF --> Default\n");
	mdb_printf("\t SER --> Serialize\n");
	mdb_printf("\t  FO --> Fanout\n");
	mdb_printf("\t  BW --> Bandwidth\n");
	mdb_printf("\tBWFO --> Bandwidth Fanout\n");
	mdb_printf("\t  AG --> Aggr\n");
	mdb_printf("\tBWAG --> Bandwidth Aggr\n");
}

/*
 * In verbose mode "::mac_srs -rcv or ::mac_srs -tcv", we print the CPUs
 * assigned to a link and CPUS assigned to the soft rings.
 * 'len' is used for formatting the output and represents the number of
 * spaces between CPU list and Fanout CPU list in the output.
 */
static boolean_t
mac_srs_print_cpu(int *i, uint32_t cnt, uint32_t *cpu_list, int *len)
{
	int		num = 0;

	if (*i == 0)
		mdb_printf("(");
	else
		mdb_printf(" ");
	while (*i < cnt) {
		/* We print 6 CPU's at a time to keep display within 80 cols */
		if (((num + 1) % 7) == 0) {
			if (len != NULL)
				*len = 2;
			return (B_FALSE);
		}
		mdb_printf("%02x%c", cpu_list[*i], ((*i == cnt - 1)?')':','));
		++*i;
		++num;
	}
	if (len != NULL)
		*len = (7 - num) * 3;
	return (B_TRUE);
}

static int
mac_srs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t			args = MAC_SRS_NONE;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("mac_srs", "mac_srs", argc, argv) == -1) {
			mdb_warn("failed to walk 'mac_srs'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (mdb_getopts(argc, argv,
	    'r', MDB_OPT_SETBITS, MAC_SRS_RX, &args,
	    't', MDB_OPT_SETBITS, MAC_SRS_TX, &args,
	    'c', MDB_OPT_SETBITS, MAC_SRS_CPU, &args,
	    'v', MDB_OPT_SETBITS, MAC_SRS_VERBOSE, &args,
	    'i', MDB_OPT_SETBITS, MAC_SRS_INTR, &args,
	    's', MDB_OPT_SETBITS, MAC_SRS_STAT, &args,
	    NULL) != argc) {
		return (DCMD_USAGE);
	}

	if (argc > 2)
		return (DCMD_USAGE);

	mdb_mac_soft_ring_set_t srs;
	if (mdb_ctf_vread(&srs, "mac_soft_ring_set_t",
	    "mdb_mac_soft_ring_set_t", addr, 0) == -1) {
		mdb_warn("failed to read struct mac_soft_ring_set_s at %p",
		    addr);
		return (DCMD_ERR);
	}

	mdb_mac_client_impl_t mci;
	if (mdb_ctf_vread(&srs, "mac_client_impl_t",
	    "mdb_mac_client_impl_t", srs.srs_mcip, 0) == -1) {
		mdb_warn("failed to read struct mac_client_impl_t at %p "
		    "for SRS %p", srs.srs_mcip, addr);
		return (DCMD_ERR);
	}

	switch (args) {
	case MAC_SRS_RX: {
		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%?s %-20s %-8s %-8s %8s "
			    "%8s %3s\n",
			    "", "", "", "", "MBLK",
			    "Q", "SR");
			mdb_printf("%<u>%?s %-20s %-8s %-8s %8s "
			    "%8s %3s%</u>\n",
			    "ADDR", "LINK_NAME", "STATE", "TYPE", "CNT",
			    "BYTES", "CNT");
		}
		if (srs.srs_type & SRST_TX)
			return (DCMD_OK);
		mdb_printf("%?p %-20s %08x %08x "
		    "%8d %8d %3d\n",
		    addr, mci.mci_name, srs.srs_state, srs.srs_type,
		    srs.srs_count, srs.srs_size, srs.srs_soft_ring_count);
		break;
	}
	case MAC_SRS_TX: {
		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%?s %-16s %-4s %-8s "
			    "%-8s %8s %8s %3s\n",
			    "", "", "TX", "",
			    "", "MBLK", "Q", "SR");
			mdb_printf("%<u>%?s %-16s %-4s %-8s "
			    "%-8s %8s %8s %3s%</u>\n",
			    "ADDR", "LINK_NAME", "MODE", "STATE",
			    "TYPE", "CNT", "BYTES", "CNT");
		}
		if (!(srs.srs_type & SRST_TX))
			return (DCMD_OK);

		mdb_printf("%?p %-16s %-4s "
		    "%08x %08x %8d %8d %3d\n",
		    addr, mci.mci_name, mac_srs_txmode2str(srs.srs_tx.st_mode),
		    srs.srs_state, srs.srs_type, srs.srs_count, srs.srs_size,
		    srs.srs_tx_ring_count);
		break;
	}
	case MAC_SRS_RXCPU: {
		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%?s %-20s %-4s %-4s "
			    "%-6s %-4s %-7s\n",
			    "", "", "NUM", "POLL",
			    "WORKER", "INTR", "FANOUT");
			mdb_printf("%<u>%?s %-20s %-4s %-4s "
			    "%-6s %-4s %-7s%</u>\n",
			    "ADDR", "LINK_NAME", "CPUS", "CPU",
			    "CPU", "CPU", "CPU_CNT");
		}
		if ((args & MAC_SRS_RX) && (srs.srs_type & SRST_TX))
			return (DCMD_OK);
		mdb_printf("%?p %-20s %-4d %-4d "
		    "%-6d %-4d %-7d\n",
		    addr, mci.mci_name, srs.srs_cpu.mc_ncpus,
		    srs.srs_cpu.mc_rx_pollid, srs.srs_cpu.mc_rx_workerid,
		    srs.srs_cpu.mc_rx_intr_cpu, srs.srs_cpu.mc_rx_fanout_cnt);
		break;

	}
	case MAC_SRS_TXCPU: {
		uintptr_t		s_ringp;
		mdb_mac_soft_ring_t	s_ring;
		boolean_t	first = B_TRUE;
		int		i;

		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%?s %-12s %?s %8s %8s %8s\n",
			    "", "", "SOFT", "WORKER", "INTR", "RETARGETED");
			mdb_printf("%<u>%?s %-12s %?s %8s %8s %8s%</u>\n",
			    "ADDR", "LINK_NAME", "RING", "CPU", "CPU", "CPU");
		}
		if (!(srs.srs_type & SRST_TX))
			return (DCMD_OK);

		mdb_printf("%?p %-12s ", addr, mci.mci_name);

		/*
		 * Case of no soft rings, print the info from
		 * mac_srs_tx_t.
		 */
		if (srs.srs_tx_ring_count == 0) {
			mdb_printf("%?p %8d %8d %8d\n",
			    0, srs.srs_cpu.mc_tx_fanout_cpus[0],
			    srs.srs_cpu.mc_tx_intr_cpus.mtc_intr_cpu[0],
			    srs.srs_cpu.mc_tx_intr_cpus.mtc_retargeted_cpu[0]);
			break;
		}

		for (s_ringp = srs.srs_soft_ring_head, i = 0; s_ringp != (uintptr_t)NULL;
		    s_ringp = s_ring.s_ring_next, i++) {
			(void) mdb_ctf_vread(&s_ring, "mac_soft_ring_t",
			    "mdb_mac_soft_ring_t", s_ringp, 0);
			if (first) {
				mdb_printf("%?p %8d %8d %8d\n",
				    s_ringp, srs.srs_cpu.mc_tx_fanout_cpus[i],
				    srs.srs_cpu.mc_tx_intr_cpus.mtc_intr_cpu[i],
				    srs.srs_cpu.mc_tx_intr_cpus.mtc_retargeted_cpu[i]);
				first = B_FALSE;
				continue;
			}
			mdb_printf("%?s %-12s %?p %8d %8d %8d\n",
			    "", "", s_ringp, srs.srs_cpu.mc_tx_fanout_cpus[i],
			    srs.srs_cpu.mc_tx_intr_cpus.mtc_intr_cpu[i],
			    srs.srs_cpu.mc_tx_intr_cpus.mtc_retargeted_cpu[i]);
		}
		break;
	}
	case MAC_SRS_TXINTR: {
		uintptr_t	s_ringp, m_ringp;
		mdb_mac_soft_ring_t	s_ring;
		mdb_mac_ring_t		m_ring;
		boolean_t	first = B_TRUE;
		int		i;

		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%?s %-12s %?s %8s %?s %6s %6s\n",
			    "", "", "SOFT", "WORKER", "MAC", "", "INTR");
			mdb_printf("%<u>%?s %-12s %?s %8s %?s %6s %6s%</u>\n",
			    "ADDR", "LINK_NAME", "RING", "CPU", "RING",
			    "SHARED", "CPU");
		}
		if (!(srs.srs_type & SRST_TX))
			return (DCMD_OK);

		mdb_printf("%?p %-12s ", addr, mci.mci_name);

		/*
		 * Case of no soft rings, print the info from
		 * mac_srs_tx_t.
		 */
		if (srs.srs_tx_ring_count == 0) {
			m_ringp = srs.srs_tx.st_arg2;
			if (m_ringp != (uintptr_t)NULL) {
				(void) mdb_ctf_vread(&m_ring, "mac_ring_t",
				    "mdb_mac_ring_t", m_ringp, 0);
				mdb_printf("%?p %8d %?p %6d %6d\n",
				    0, srs.srs_cpu.mc_tx_fanout_cpus[0],
				    m_ringp,
				    m_ring.mr_info.mri_intr.mi_ddi_shared,
				    srs.srs_cpu.mc_tx_intr_cpus.mtc_retargeted_cpu[0]);
			} else {
				mdb_printf("%?p %8d %?p %6d %6d\n",
				    0, srs.srs_cpu.mc_tx_fanout_cpus[0], 0,
				    0, srs.srs_cpu.mc_tx_intr_cpus.mtc_retargeted_cpu[0]);
			}
			break;
		}

		for (s_ringp = srs.srs_soft_ring_head, i = 0;
		    s_ringp != (uintptr_t)NULL; s_ringp = s_ring.s_ring_next, i++) {
			(void) mdb_ctf_vread(&s_ring, "mac_soft_ring_t",
			    "mdb_mac_soft_ring_t", s_ringp, 0);
			m_ringp = s_ring.s_ring_tx_arg2;
			(void) mdb_ctf_vread(&m_ring, "mac_ring_t",
			    "mdb_mac_ring_t", m_ringp, 0);
			if (first) {
				mdb_printf("%?p %8d %?p %6d %6d\n",
				    s_ringp, srs.srs_cpu.mc_tx_fanout_cpus[i],
				    m_ringp,
				    m_ring.mr_info.mri_intr.mi_ddi_shared,
				    srs.srs_cpu.mc_tx_intr_cpus.mtc_retargeted_cpu[i]);
				first = B_FALSE;
				continue;
			}
			mdb_printf("%?s %-12s %?p %8d %?p %6d %6d\n",
			    "", "", s_ringp, srs.srs_cpu.mc_tx_fanout_cpus[i],
			    m_ringp, m_ring.mr_info.mri_intr.mi_ddi_shared,
			    srs.srs_cpu.mc_tx_intr_cpus.mtc_retargeted_cpu[i]);
		}
		break;
	}
	case MAC_SRS_RXINTR: {
		uintptr_t	m_ringp;
		mac_ring_t	m_ring;

		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%?s %-12s %?s %8s %6s %6s\n",
			    "", "", "MAC", "", "POLL", "INTR");
			mdb_printf("%<u>%?s %-12s %?s %8s %6s %6s%</u>\n",
			    "ADDR", "LINK_NAME", "RING", "SHARED", "CPU",
			    "CPU");
		}
		if ((args & MAC_SRS_RX) && (srs.srs_type & SRST_TX))
			return (DCMD_OK);

		mdb_printf("%?p %-12s ", addr, mci.mci_name);

		m_ringp = srs.srs_ring;
		if (m_ringp != (uintptr_t)NULL) {
			(void) mdb_ctf_vread(&m_ring, "mac_ring_t",
			    "mdb_mac_ring_t", m_ringp, 0);
			mdb_printf("%?p %8d %6d %6d\n",
			    m_ringp, m_ring.mr_info.mri_intr.mi_ddi_shared,
			    srs.srs_cpu.mc_rx_pollid, srs.srs_cpu.mc_rx_intr_cpu);
		} else {
			mdb_printf("%?p %8d %6d %6d\n",
			    0, 0, srs.srs_cpu.mc_rx_pollid,
			    srs.srs_cpu.mc_rx_intr_cpu);
		}
		break;
	}
	case MAC_SRS_RXCPUVERBOSE:
	case MAC_SRS_TXCPUVERBOSE: {
		int		cpu_index = 0, fanout_index = 0, len = 0;
		boolean_t	cpu_done = B_FALSE, fanout_done = B_FALSE;

		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%?s %-20s %-20s %-20s\n",
			    "", "", "CPU_COUNT", "FANOUT_CPU_COUNT");
			mdb_printf("%<u>%?s %-20s "
			    "%-20s %-20s%</u>\n",
			    "ADDR", "LINK_NAME",
			    "(CPU_LIST)", "(CPU_LIST)");
		}
		if (((args & MAC_SRS_TX) && !(srs.srs_type & SRST_TX)) ||
		    ((args & MAC_SRS_RX) && (srs.srs_type & SRST_TX)))
			return (DCMD_OK);
		mdb_printf("%?p %-20s %-20d %-20d\n", addr, mci.mci_name,
		    srs.srs_cpu.mc_ncpus, srs.srs_cpu.mc_rx_fanout_cnt);
		if (srs.srs_cpu.mc_ncpus == 0 &&
		    srs.srs_cpu.mc_rx_fanout_cnt == 0) {
			break;
		}
		/* print all cpus and cpus for soft rings */
		while (!cpu_done || !fanout_done) {
			boolean_t old_value = cpu_done;

			if (!cpu_done) {
				mdb_printf("%?s %20s ", "", "");
				cpu_done = mac_srs_print_cpu(&cpu_index,
				    srs.srs_cpu.mc_ncpus, srs.srs_cpu.mc_cpus,
				    &len);
			}
			if (!fanout_done) {
				if (old_value)
					mdb_printf("%?s %-40s", "", "");
				else
					mdb_printf("%*s", len, "");
				fanout_done = mac_srs_print_cpu(&fanout_index,
				    srs.srs_cpu.mc_rx_fanout_cnt,
				    srs.srs_cpu.mc_rx_fanout_cpus, NULL);
			}
			mdb_printf("\n");
		}
		break;
	}
	case MAC_SRS_RXSTAT: {
		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%?s %-16s %8s %8s "
			    "%8s %8s %8s\n",
			    "", "", "INTR", "POLL",
			    "CHAIN", "CHAIN", "CHAIN");
			mdb_printf("%<u>%?s %-16s %8s %8s "
			    "%8s %8s %8s%</u>\n",
			    "ADDR", "LINK_NAME", "COUNT", "COUNT",
			    "<10", "10-50", ">50");
		}
		if (srs.srs_type & SRST_TX)
			return (DCMD_OK);
		mdb_printf("%?p %-16s %8d "
		    "%8d %8d "
		    "%8d %8d\n",
		    addr, mci.mci_name, srs.srs_rx.sr_stat.mrs_intrcnt,
		    srs.srs_rx.sr_stat.mrs_pollcnt, srs.srs_rx.sr_stat.mrs_chaincntundr10,
		    srs.srs_rx.sr_stat.mrs_chaincnt10to50,
		    srs.srs_rx.sr_stat.mrs_chaincntover50);
		break;
	}
	case MAC_SRS_TXSTAT: {
		uintptr_t		s_ringp;
		mdb_mac_soft_ring_t	s_ring;
		boolean_t		first = B_TRUE;

		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%?s %-20s %?s %8s %8s %8s\n",
			    "", "", "SOFT", "DROP", "BLOCK", "UNBLOCK");
			mdb_printf("%<u>%?s %-20s %?s %8s %8s %8s%</u>\n",
			    "ADDR", "LINK_NAME", "RING", "COUNT", "COUNT",
			    "COUNT");
		}
		if (!(srs.srs_type & SRST_TX))
			return (DCMD_OK);

		mdb_printf("%?p %-20s ", addr, mci.mci_name);

		/*
		 * Case of no soft rings, print the info from
		 * mac_srs_tx_t.
		 */
		if (srs.srs_tx_ring_count == 0) {
			mdb_printf("%?p %8d %8d %8d\n",
			    0, srs.srs_tx.st_stat.mts_sdrops,
			    srs.srs_tx.st_stat.mts_blockcnt,
			    srs.srs_tx.st_stat.mts_unblockcnt);
			break;
		}

		for (s_ringp = srs.srs_soft_ring_head;
		    s_ringp != (uintptr_t)NULL; s_ringp = s_ring.s_ring_next) {
			(void) mdb_ctf_vread(&s_ring, "mac_soft_ring_t",
			    "mdb_mac_soft_ring_t", s_ringp, 0);
			if (first) {
				mdb_printf("%?p %8d %8d %8d\n",
				    s_ringp, s_ring.s_st_stat.mts_sdrops,
				    s_ring.s_st_stat.mts_blockcnt,
				    s_ring.s_st_stat.mts_unblockcnt);
				first = B_FALSE;
				continue;
			}
			mdb_printf("%?s %-20s %?p %8d %8d %8d\n",
			    "", "", s_ringp, s_ring.s_st_stat.mts_sdrops,
			    s_ring.s_st_stat.mts_blockcnt,
			    s_ring.s_st_stat.mts_unblockcnt);
		}
		break;
	}
	case MAC_SRS_NONE: {
		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%<u>%?s %-20s %?s %?s %-3s%</u>\n",
			    "ADDR", "LINK_NAME", "FLENT", "HW RING", "DIR");
		}
		mdb_printf("%?p %-20s %?p %?p "
		    "%-3s ",
		    addr, mci.mci_name, srs.srs_flent, srs.srs_ring,
		    (srs.srs_type & SRST_TX ? "TX" : "RX"));
		break;
	}
	default:
		return (DCMD_USAGE);
	}
	return (DCMD_OK);
}

static int
mac_srs_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk(LAYERED_WALKER_FOR_SRS, wsp) == -1) {
		mdb_warn("failed to walk 'mac_srs'");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static char *
mac_ring_state2str(mac_ring_state_t state)
{
	switch (state) {
	case MR_FREE:
		return ("free");
	case MR_NEWLY_ADDED:
		return ("new");
	case MR_INUSE:
		return ("inuse");
	}
	return ("--");
}

static char *
mac_ring_classify2str(mac_classify_type_t classify)
{
	switch (classify) {
	case MAC_NO_CLASSIFIER:
		return ("no");
	case MAC_SW_CLASSIFIER:
		return ("sw");
	case MAC_HW_CLASSIFIER:
		return ("hw");
	case MAC_PASSTHRU_CLASSIFIER:
		return ("pass");
	}
	return ("--");
}

static int
mac_ring_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_mac_ring_t		ring;
	mdb_mac_group_t		group;
	mdb_flow_entry_t	flent;
	mdb_mac_soft_ring_set_t	srs;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("mac_ring", "mac_ring", argc, argv) == -1) {
			mdb_warn("failed to walk 'mac_ring'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}
	if (mdb_ctf_vread(&ring, "mac_ring_t", "mac_mac_ring_t", addr, 0) == -1) {
		mdb_warn("failed to read struct mac_ring_s at %p", addr);
		return (DCMD_ERR);
	}
	bzero(&flent, sizeof (flent));
	if (mdb_ctf_vread(&srs, "mac_soft_ring_set_t",
	    "mdb_mac_soft_ring_set_t", ring.mr_srs, 0) != -1) {
		(void) mdb_ctf_vread(&srs, "flow_entry_t", "mac_flow_entry_t",
		    srs.srs_flent, 0);
	}
	(void) mdb_ctf_vread(&group, "mac_group_t", "mdb_mac_group_t",
	    ring.mr_gh, 0);
	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %4s %5s %4s %?s "
		    "%5s %?s %?s %s %</u>\n",
		    "ADDR", "TYPE", "STATE", "FLAG", "GROUP",
		    "CLASS", "MIP", "SRS", "FLOW NAME");
	}
	mdb_printf("%?p %-4s "
	    "%5s %04x "
	    "%?p %-5s "
	    "%?p %?p %s\n",
	    addr, ((ring.mr_type == 1)? "RX" : "TX"),
	    mac_ring_state2str(ring.mr_state), ring.mr_flag,
	    ring.mr_gh, mac_ring_classify2str(ring.mr_classify_type),
	    group.mrg_mh, ring.mr_srs, flent.fe_flow_name);
	return (DCMD_OK);
}

static int
mac_ring_walk_init(mdb_walk_state_t *wsp)
{
	if (mdb_layered_walk(LAYERED_WALKER_FOR_RING, wsp) == -1) {
		mdb_warn("failed to walk `mac_ring`");
		return (WALK_ERR);
	}
	return (WALK_NEXT);
}

static void
mac_ring_help(void)
{
	mdb_printf("If an address is specified, then mac_ring_t "
	    "structure at that address is printed. Otherwise all the "
	    "hardware rings in the system are printed.\n");
}

/*
 * To walk groups we have to have our own somewhat-complicated state machine. We
 * basically start by walking the mac_impl_t walker as all groups are stored off
 * of the various mac_impl_t in the system. The tx and rx rings are kept
 * separately. So we'll need to walk through all the rx rings and then all of
 * the tx rings.
 */
static int
mac_group_walk_init(mdb_walk_state_t *wsp)
{
	int ret;

	if (wsp->walk_addr != 0) {
		mdb_warn("non-global walks are not supported\n");
		return (WALK_ERR);
	}

	if ((ret = mdb_layered_walk(LAYERED_WALKER_FOR_GROUP, wsp)) == -1) {
		mdb_warn("couldn't walk '%s'", LAYERED_WALKER_FOR_GROUP);
		return (ret);
	}

	return (WALK_NEXT);
}

static int
mac_group_walk_step(mdb_walk_state_t *wsp)
{
	int ret;
	mdb_mac_impl_t mi;
	mdb_mac_group_t mg;
	uintptr_t mgp;

	/*
	 * Nothing to do if we can't find the layer above us. But the kmem
	 * walkers are a bit unsporting, they don't actually read in the data
	 * for us.
	 */
	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_ctf_vread(&mi, "mac_impl_t", "mdb_mac_impl_t", wsp->walk_addr,
	    0) == -1) {
		mdb_warn("failed to read mac_impl_t at %p", wsp->walk_addr);
		return (DCMD_ERR);
	}

	/*
	 * First go for rx groups, then tx groups.
	 */
	mgp = (uintptr_t)mi.mi_rx_groups;
	while (mgp != 0) {
		if (mdb_ctf_vread(&mg, "mac_group_t", "mdb_mac_group_t", mgp,
		    0) == -1) {
			mdb_warn("failed to read mac_group_t at %p", mgp);
			return (DCMD_ERR);
		}

		ret = wsp->walk_callback(mgp, &mg, wsp->walk_cbdata);
		if (ret != WALK_NEXT)
			return (ret);
		mgp = (uintptr_t)mg.mrg_next;
	}

	mgp = (uintptr_t)mi.mi_tx_groups;
	while (mgp != 0) {
		if (mdb_ctf_vread(&mg, "mac_group_t", "mdb_mac_group_t", mgp,
		    0) == -1) {
			mdb_warn("failed to read mac_group_t at %p", mgp);
			return (DCMD_ERR);
		}

		ret = wsp->walk_callback(mgp, &mg, wsp->walk_cbdata);
		if (ret != WALK_NEXT)
			return (ret);
		mgp = (uintptr_t)mg.mrg_next;
	}

	return (WALK_NEXT);
}

static int
mac_group_count_clients(mdb_mac_group_t *mgp)
{
	int clients = 0;
	uintptr_t mcp = (uintptr_t)mgp->mrg_clients;

	while (mcp != 0) {
		mdb_mac_grp_client_t c;

		if (mdb_ctf_vread(&c, "mac_grp_client_t",
		    "mdb_mac_grp_client_t", mcp, 0) == -1) {
			mdb_warn("failed to read mac_grp_client_t at %p", mcp);
			return (-1);
		}
		clients++;
		mcp = (uintptr_t)c.mgc_next;
	}

	return (clients);
}

static const char *
mac_group_type(mdb_mac_group_t *mgp)
{
	const char *ret;

	switch (mgp->mrg_type) {
	case MAC_RING_TYPE_RX:
		ret = "RECEIVE";
		break;
	case MAC_RING_TYPE_TX:
		ret = "TRANSMIT";
		break;
	default:
		ret = "UNKNOWN";
		break;
	}

	return (ret);
}

static const char *
mac_group_state(mdb_mac_group_t *mgp)
{
	const char *ret;

	switch (mgp->mrg_state) {
	case MAC_GROUP_STATE_UNINIT:
		ret = "UNINT";
		break;
	case MAC_GROUP_STATE_REGISTERED:
		ret = "REGISTERED";
		break;
	case MAC_GROUP_STATE_RESERVED:
		ret = "RESERVED";
		break;
	case MAC_GROUP_STATE_SHARED:
		ret = "SHARED";
		break;
	default:
		ret = "UNKNOWN";
		break;
	}

	return (ret);
}

static int
mac_group_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t		args = MAC_SRS_NONE;
	mdb_mac_group_t	mg;
	int		clients;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("mac_group", "mac_group", argc, argv) == -1) {
			mdb_warn("failed to walk 'mac_group'");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'r', MDB_OPT_SETBITS, MAC_GROUP_RX, &args,
	    't', MDB_OPT_SETBITS, MAC_GROUP_TX, &args,
	    'u', MDB_OPT_SETBITS, MAC_GROUP_UNINIT, &args,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_ctf_vread(&mg, "mac_group_t", "mdb_mac_group_t", addr,
	    0) == -1) {
		mdb_warn("failed to read mac_group_t at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags) && !(flags & DCMD_PIPE_OUT)) {
		mdb_printf("%<u>%-?s %-8s %-10s %6s %8s %-?s%</u>\n",
		    "ADDR", "TYPE", "STATE", "NRINGS", "NCLIENTS", "RINGS");
	}

	if ((args & MAC_GROUP_RX) != 0 && mg.mrg_type != MAC_RING_TYPE_RX)
		return (DCMD_OK);
	if ((args & MAC_GROUP_TX) != 0 && mg.mrg_type != MAC_RING_TYPE_TX)
		return (DCMD_OK);

	/*
	 * By default, don't show uninitialized groups. They're not very
	 * interesting. They have no rings and no clients.
	 */
	if (mg.mrg_state == MAC_GROUP_STATE_UNINIT &&
	    (args & MAC_GROUP_UNINIT) == 0)
		return (DCMD_OK);

	if (flags & DCMD_PIPE_OUT) {
		mdb_printf("%lr\n", addr);
		return (DCMD_OK);
	}

	clients = mac_group_count_clients(&mg);
	mdb_printf("%?p %-8s %-10s %6d %8d %?p\n", addr, mac_group_type(&mg),
	    mac_group_state(&mg), mg.mrg_cur_count, clients, mg.mrg_rings);

	return (DCMD_OK);
}

/* Supported dee-commands */
static const mdb_dcmd_t dcmds[] = {
	{"mac_flow", "?[-u] [-aprtsm]", "display Flow Entry structures",
	    mac_flow_dcmd, mac_flow_help},
	{"mac_group", "?[-rtu]", "display MAC Ring Groups", mac_group_dcmd,
	    NULL },
	{"mac_srs", "?[ -r[i|s|c[v]] | -t[i|s|c[v]] ]",
	    "display MAC Soft Ring Set" " structures", mac_srs_dcmd,
	    mac_srs_help},
	{"mac_ring", "?", "display MAC ring (hardware) structures",
	    mac_ring_dcmd, mac_ring_help},
	{ NULL }
};

/* Supported walkers */
static const mdb_walker_t walkers[] = {
	{"mac_flow", "walk list of flow entry structures", mac_flow_walk_init,
	    mac_common_walk_step, NULL, NULL},
	{"mac_group", "walk list of ring group structures", mac_group_walk_init,
	    mac_group_walk_step, NULL, NULL},
	{"mac_srs", "walk list of mac soft ring set structures",
	    mac_srs_walk_init, mac_common_walk_step, NULL, NULL},
	{"mac_ring", "walk list of mac ring structures", mac_ring_walk_init,
	    mac_common_walk_step, NULL, NULL},
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}

/* Shared library add-on to iptables for PRIO
 *
 * (C) 2000- 2002 by Matthew G. Marsh <mgm@paktronix.com>,
 * 		     Harald Welte <laforge@gnumonks.org>
 *
 * This program is distributed under the terms of GNU GPL v2, 1991
 *
 * libipt_PRIO.c
 *
 */
#include <stdio.h>
#include <string.h>
#include <xtables.h>
//#include <linux/netfilter/xt_PRIO.h>

#define XT_PRIO_MAX 0xFFFFFFFF

/* target info */
struct xt_PRIO_info {
	__u32 prio;
};

enum {
	O_SET_prio = 0,
	O_SET_PRIO_CLASS,
	F_SET_prio       = 1 << O_SET_prio,
	F_SET_PRIO_CLASS = 1 << O_SET_PRIO_CLASS,
};

static void PRIO_help(void)
{
	printf(
"prio target options\n"
"  --set-prio value		Set prio field in packet header to value\n"
"  		                This value can be in decimal (ex: 32)\n"
"               		or in hex (ex: 0x20)\n"
"  --set-prio-class class	Set the prio field in packet header to the\n"
"				value represented by the DiffServ class value.\n"
"				This class may be EF,BE or any of the CSxx\n"
"				or AFxx classes.\n"
"\n"
"				These two options are mutually exclusive !\n"
);
}

static const struct xt_option_entry PRIO_opts[] = {
	{
		.name = "set-prio",
		.id = O_SET_prio,
		.excl = F_SET_PRIO_CLASS,
		.type = XTTYPE_UINT32,
		.min = 0,
		.max = XT_PRIO_MAX,
		.flags = XTOPT_PUT,
		XTOPT_POINTER(struct xt_PRIO_info, prio)
	},
	XTOPT_TABLEEND,
};

static void PRIO_parse(struct xt_option_call *cb)
{
	xtables_option_parse(cb);
}

static void PRIO_check(struct xt_fcheck_call *cb)
{
	if (cb->xflags == 0)
		xtables_error(PARAMETER_PROBLEM,
		           "prio target: Parameter --set-prio is required");
}

static void
print_prio(uint32_t prio, int numeric)
{
	printf(" 0x%08x", prio);
}

static void PRIO_print(const void *ip, const struct xt_entry_target *target,
                       int numeric)
{
	const struct xt_PRIO_info *dinfo =
		(const struct xt_PRIO_info *)target->data;
	printf(" prio set");
	print_prio(dinfo->prio, numeric);
}

static void PRIO_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_PRIO_info *dinfo =
		(const struct xt_PRIO_info *)target->data;

	printf(" --set-prio 0x%08x", dinfo->prio);
}

static struct xtables_target PRIO_target = {
	.family		= NFPROTO_UNSPEC,
	.name		= "PRIO",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_PRIO_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_PRIO_info)),
	.help		= PRIO_help,
	.print		= PRIO_print,
	.save		= PRIO_save,
	.x6_parse	= PRIO_parse,
	.x6_fcheck	= PRIO_check,
	.x6_options	= PRIO_opts,
};

void _init(void)
{
	xtables_register_target(&PRIO_target);
}

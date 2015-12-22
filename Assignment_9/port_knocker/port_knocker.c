
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 9                                                             */
/*                                                                             */
/*   Filename: port_knocker.c                                                  */
/*                                                                             */
/*   Authors:                                                                  */
/*       Name: Matei Pavaluca                                                  */
/*       Email: mateipavaluca@yahoo.com                                        */
/*                                                                             */
/*       Name: Nedko Stefanov Nedkov                                           */
/*       Email: nedko.stefanov.nedkov@gmail.com                                */
/*                                                                             */
/*   Date: December 2015                                                       */
/*                                                                             */
/*   Usage: ...                                                                */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>					/* Needed by all kernel modules */
#include <linux/inet.h>						/* Needed for in4_pton */
#include <linux/netfilter_ipv4.h>			/* Needed for NF_IP_PRI_FIRST */
#include <net/netfilter/ipv4/nf_reject.h>	/* Needed for nf_send_reset */


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A port knocker :)");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Matei<mateipavaluca@yahoo.com>");
MODULE_AUTHOR("Nedko<nedko.stefanov.nedkov@gmail.com>");


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define DEBUG_MODE_IS_ON 1
#define LOCALHOST "127.0.0.1"
#define PRINT(str) printk(KERN_INFO "port_knocker: %s\n", (str))
#define DEBUG_PRINT(str) if (DEBUG_MODE_IS_ON) PRINT(str)


/* Definition of global variables */
static char *ip_addr = LOCALHOST;   /* The IPv4 address which is allowed to connect */
static int port = -1;

static __u32 ip;   /* The binary representation of the IPv4 address which is allowed to connect */


/* Declaration of data structs */
static struct nf_hook_ops hook;


/* Declaration of functions */
static int load_port_knocking(void);
static unsigned int knocking_hook (const struct nf_hook_ops *, struct sk_buff *,
	const struct net_device *, const struct net_device *, int (*okfn)(struct sk_buff *));
static int should_block_packet(struct sk_buff *);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


module_param(ip_addr, charp, 0000);
MODULE_PARM_DESC(ip_addr, "The IPv4 address which is allowed to connect");
module_param(port, int, 0);


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces ... */
static int __init packet_masker_start(void)
{
	u8 ipv4_bin_repr[4];
	int ret;

	/* Verify that given IPv4 address is valid */
	if (!in4_pton(ip_addr, -1, ipv4_bin_repr, -1, NULL)) {
		DEBUG_PRINT("missing or invalid IP address given as argument "
					"(try: insmod socket_masker.ko ip_addr=x.x.x.x)");

		return -EINVAL;
	}

	if (port < 0 || 65535 < port) {
		DEBUG_PRINT("missing or invalid port number given as argument ");

		return -EINVAL;
	}

	ret = load_port_knocking();
	if (ret < 0)
		return ret;

	DEBUG_PRINT("successfully inserted");

	/* A non 0 return value means init_module failed; module can't be loaded */
	return 0;
}


/* Cleanup function which is called just before module
   is rmmoded. It restores the original... */
static void __exit packet_masker_end(void)
{
	nf_unregister_hook(&hook);

	DEBUG_PRINT("successfully removed");

	return;
}


/* Enable the port knocking mechanism */
static int load_port_knocking(void)
{
	int ret;
	u8 tmp[4];

	/* Convert the IPv4 address from literal to binary representation */
	in4_pton(ip_addr, -1, tmp, -1, NULL);
	ip = 0;

	/* Convert byte array to __u32 */
	ip |= tmp[0] & 0xFF;
	ip <<= 8;
	ip |= tmp[1] & 0xFF;
	ip <<= 8;
	ip |= tmp[2] & 0xFF;
	ip <<= 8;
	ip |= tmp[3] & 0xFF;

	/* Setup everything for the netfilter hook */
	hook.hook = knocking_hook;			/* our function */
	hook.hooknum = NF_INET_LOCAL_IN;	/* grab everything that comes in */
	hook.pf = PF_INET;					/* we only care about ipv4 */
	hook.priority = NF_IP_PRI_FIRST;	/* respect my priority */

	ret = nf_register_hook(&hook);

	if (ret < 0) {
		printk(KERN_INFO "port_knocker: error occured while loading port knocking (nf_register_hook return value = %d)\n", ret);

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


module_init(packet_masker_start);
module_exit(packet_masker_end);

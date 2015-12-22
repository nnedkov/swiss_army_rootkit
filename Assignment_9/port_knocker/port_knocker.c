
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

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/inet.h>
#include <net/ip.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/netfilter/ipv4/nf_reject.h>

#include "sysmap.h"				/* Needed for ROOTKIT_SYS_CALL_TABLE */


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

#define PROTO_TCP 6
#define PROTO_UDP 17


/* Definition of global variables */
static char *ip_addr = LOCALHOST;   /* The IPv4 address whose packet traffic is being masked */

static int port = -1;
static char protocol[4] = "tcp";
static int protoc;

static struct nf_hook_ops hook;

/* the ip address which is allowed to connect */
static __u32 ip;


/* Declaration of functions */
int load_port_knocking (char *, unsigned int);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


module_param(ip_addr, charp, 0000);
MODULE_PARM_DESC(ip_addr, "The IPv4 address where port knocking is being enabled");
module_param(port, int, 0);
module_param_string(protocol, protocol, 4, 0);


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces ... */
static int __init packet_masker_start(void)
{
	u8 ipv4_bin_repr[4];
	int ret;

	if (!strcmp(ip_addr, LOCALHOST) ||
			!in4_pton(ip_addr, -1, ipv4_bin_repr, -1, NULL)) {   /* Convert the IPv4 address from literal to binary representation */
		DEBUG_PRINT("missing or invalid IP address given as argument "
					"(try: insmod socket_masker.ko ip_addr=x.x.x.x)");

		return -EINVAL;
	}

	/* ensure the input contains a valid port */
	if (port < 0 || 65535 < port) {
		DEBUG_PRINT("missing or invalid port number given as argument ");
		return -EINVAL;
	}

	/* ensure a supported transport layer protocol is selected in the input */
	if(strcmp(protocol, "tcp") == 0) {
		protoc = PROTO_TCP ;
	} else if(strcmp(protocol, "udp") == 0) {
		protoc = PROTO_UDP ;
	} else {
		DEBUG_PRINT("Unsupported transport layer protocol.\n");
		return -EINVAL;
	}

	ret = load_port_knocking(ip_addr, (unsigned) port);
	if(ret < 0) {
		DEBUG_PRINT("Error while loading port knocking");
		return ret;
	}

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


/*static int packet_should_be_masked(struct sk_buff *skb)
{
	struct iphdr *ip_header;

	// Check if this frame contains an IPv4 packet
	if (skb->protocol == htons(ETH_P_IP)) {
		// Extract the IP header
		ip_header = (struct iphdr *) skb_network_header(skb);

		// Check if the masked IPv4 address is in the sender or the receiver field
		if (ip_header->saddr == masked_ip_addr || ip_header->daddr == masked_ip_addr) {
			DEBUG_PRINT("packet with masked IP address detected");

			return 1;
		}
	}

	return 0;
}*/

/*
 * This function does all the checking.
 * First it checks if the packet is on one of the blocked ports. If this is
 * the case, it further checks whether the packet received is from the allowed ip.
 * If this is the case (or it belongs to an unblocked port), then it returns
 * false (let through), otherwise it returns true (drop and reject).
 */
static int
is_port_blocked (struct sk_buff *skb) {

	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	/* check tree for TCP */
	if (protoc == PROTO_TCP
		&& ip_header->protocol == 6) {

		/* get the tcp header */
		tcp_header = (struct tcphdr *) skb_transport_header(skb);

		/* check if the port matches */
		if(ntohs(tcp_header->dest) == port) {
			printk(KERN_INFO "Received packet on filtered tcp port %u from IP %pI4.\n",
				port, &ip_header->saddr);

			/* check if the ip matches */
			if(ntohl(ip_header->saddr) == ip) {

				return 0;	/* allow it */

			} else {

				return 1;	/* reject it */

			}

		}
	}

	/* check tree for UDP */
	if (protoc == PROTO_UDP
		&& ip_header->protocol == 17) {

		/* get the udp header */
		udp_header = (struct udphdr *) skb_transport_header(skb);

		/* check if the port matches */
		if(ntohs(udp_header->dest) == port) {
			printk(KERN_INFO "Received packet on filtered udp port %u from IP %pI4.\n",
				port, &ip_header->saddr);

			/* check if the ip matches */
			if(ntohl(ip_header->saddr) == ip) {

				return 0;	/* allow it */

			} else {

				return 1;	/* reject it */

			}

		}
	}

	return 0;	/* allow it */
}

/*
 * The Netfilter hook function.
 * It is of type nf_hookfn (see netfilter.h).
 *
 *
 */
unsigned int
knocking_hook (const struct nf_hook_ops *ops,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);

	/* check if we need to block this packet */
	if(is_port_blocked(skb)) {

		/*
		 * craft an appropriate REJECT response
		 */
		if(ip_header->protocol == 6) {	/* tcp */
			nf_send_reset(skb, ops->hooknum);	/* send TCP RST */
		}

		if(ip_header->protocol == 17) {	/* udp */
/* enum nf_inet_hooks {
		NF_INET_PRE_ROUTING,
		NF_INET_LOCAL_IN,
		NF_INET_FORWARD,
		NF_INET_LOCAL_OUT,
		NF_INET_POST_ROUTING,
		NF_INET_NUMHOOKS };
*/
			nf_send_unreach(skb, 3, NF_INET_PRE_ROUTING);		/* send icmp port unreachable */
		}

		/* we can now safely drop the packet */
		DEBUG_PRINT("Dropped a packet due to port knocking.\n");
		return NF_DROP;

	} else {

		/* let the packet through */
		return NF_ACCEPT;

	}

}

/* enable port knocking */
int
load_port_knocking (char *ipv4_addr, unsigned int port_number)
{
	int ret;
	u8 tmp[4];

	DEBUG_PRINT("Starting to load the port knocking...\n");

	/* convert ip string to an int array */
	in4_pton(ipv4_addr, -1, tmp, -1, NULL);
	ip = 0;

	/* hack to convert byte array to __u32 */
	ip |= tmp[0] & 0xFF;
	ip <<= 8;
	ip |= tmp[1] & 0xFF;
	ip <<= 8;
	ip |= tmp[2] & 0xFF;
	ip <<= 8;
	ip |= tmp[3] & 0xFF;

	/* copy the port number */
	port = port_number;

	/* setup everything for the netfilter hook */
	hook.hook = knocking_hook;		/* our function */
	hook.hooknum = NF_INET_LOCAL_IN;	/* grab everything that comes in */
	hook.pf = PF_INET; 			/* we only care about ipv4 */
	hook.priority = NF_IP_PRI_FIRST;	/* respect my prioritah */

	/* actually do the hook */
	ret = nf_register_hook(&hook);

	if(ret < 0) {
		printk(KERN_INFO "Error enabling port knocking. Return of nf_register_hook = %d\n", ret);
		return ret;
	}

	/* log our success */
	DEBUG_PRINT("Done.\n");
	return 0;
}




module_init(packet_masker_start);
module_exit(packet_masker_end);

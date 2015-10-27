#!/bin/bash

###############################################################################
#                                                                             #
#   Course: Rootkit Programming                                               #
#   Semester: WS 2015/16                                                      #
#   Team: 105                                                                 #
#   Assignment: 1                                                             #
#                                                                             #
#   Filename: sysmap.sh                                                       #
#                                                                             #
#   Authors:                                                                  #
#       Name: Matei Pavaluca                                                  #
#       Email: mateipavaluca@yahoo.com                                        #
#                                                                             #
#       Name: Nedko Stefanov Nedkov                                           #
#       Email: nedko.stefanov.nedkov@gmail.com                                #
#                                                                             #
#   Date: October 2015                                                        #
#                                                                             #
#   Usage: This script will create a header file named `sysmap.h` that maps   #
#          the kernel symbol names to their addresses in memory. Only         #
#          symbols of type D (initialized writable data), R (read-only        #
#          data) and T (code) are being considered.                           #
#                                                                             #
###############################################################################



###################################################################################################
# auxiliary definitions/functions

declare -A colors
colors["red"]="\e[0;31m"
colors["blue"]="\e[00;36m"
colors["dark_green"]="\e[00;32m"
colors["yellow"]="\e[01;33m"

function print() {
	if (( $# == 2 )); then
		echo -e "${colors[$1]}$2\e[00m"
	else
		echo -e $1
	fi
}

function print_and_exit() {
	echo -e "${colors[$1]}$2\e[00m"
	exit $3
}

###################################################################################################
# create sysmap header file

function create_sysmap_header_file() {
	print "blue" "\n*** Creating sysmap header file ***"

	print "dark_green" "(1/2) Locating system map file..."
	SYSTEM_MAP_FILE=/boot/System.map-$(uname -r)
	if [ ! -f  "$SYSTEM_MAP_FILE" ]; then
		print_and_exit "red" "error: could not find system map file in /boot" 1
	fi
	print "dark_green" "[DONE] - found under path: $SYSTEM_MAP_FILE"

	print "dark_green" "(2/2) Creating header file 'sysmap.h'..."
	HEADER_FILE=./sysmap.h
	cat > $HEADER_FILE <<- EOM
	#ifndef SYSMAP_H
	#define SYSMAP_H

	EOM
	# collect only symbols of interest and dump them within macro definitions in the header file
	cat $SYSTEM_MAP_FILE | grep -v "\." | awk '($2=="D" || $2=="R" || $2=="T" || $2=="d" || $2=="r" || $2=="t") { printf("#define ROOTKIT_%s 0x%s\n", toupper($3), $1) }' >> $HEADER_FILE
	cat >> $HEADER_FILE <<- EOM

	#endif

	EOM
	print "dark_green" "[DONE] - find under path: $HEADER_FILE\n"
}

###################################################################################################

create_sysmap_header_file


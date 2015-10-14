#!/bin/bash

##################################################
#   Filename: sysmap.sh                          #
#                                                #
#   Team: 105                                    #
#                                                #
#   Authors:                                     #
#		Name: Matei Pavaluca                     #
#		Email: mateipavaluca@yahoo.com           #
#                                                #
#       Name: Nedko Stefanov Nedkov              #
#       Email: nedko.stefanov.nedkov@gmail.com   #
#                                                #
#   Date: October 2015	                         #
##################################################

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
	cat $SYSTEM_MAP_FILE | awk '($2=="D" || $2=="R" || $2=="T") {
									printf("#ifndef %s\n#define %s 0x%s\n#endif\n\n",
									toupper($3),
									toupper($3),
									$1) }' > ./sysmap.h
	print "dark_green" "[DONE] - find under path: ./sysmap.h"
	echo
}

###################################################################################################

create_sysmap_header_file


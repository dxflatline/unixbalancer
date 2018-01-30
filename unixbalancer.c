/// unixbalancer v0.1
/// Reads from a stream AF_UNIX socket and balances towards TCP/UDP. Applies regex. Fast (C).
/// https://github.com/dxflatline/unixbalancer
///
/// Copyright (C) 2017  Dixie Flatline (dc.flatline@gmail.com)
///
/// This program is free software: you can redistribute it and/or modify
/// it under the terms of the GNU General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// any later version.
/// This program is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
/// GNU General Public License for more details.
/// You should have received a copy of the GNU General Public License
/// along with this program.If not, see<http://www.gnu.org/licenses/>.
///
/// Major Changelog:
///   v0.1a - First release (incomplete)
///   v0.1b - 2nd release (working version)
///   v0.1c - Fixed memory allocation issues with regexes
///
/// Todo:
///   Correct signal to send stats and re-connect to destination
///   Implement the LB on destinations (now it is single)
///   Command line args instead of some defines
  
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/un.h>
#include <syslog.h>
#include <regex.h>
#include <sys/stat.h>  
#include <signal.h>
#include <sys/resource.h>
#include <fcntl.h>

#define PROGNAME "unixbalancer"
#define VERSION "0.1c"
#define REFRESH_INTERVAL 10

// Syslog server for logging
#define SYSLOG_PORT 514
#define SYSLOG_HOST "127.0.0.1"

// The number of bytes to read on every unix socket read
#define UNIX_SOCKET_READMAX 1024

// The maximum number of bytes that a single message can be
#define MAX_BUFFER 400000

// The maximum unix socket clients
#define MAX_CLIENTS 100

// Regex to work with
#define REGEX1 ",\"cookie\":\"[^\"]*\""
#define REGEX2 ",\"auth\":\"[^\"]*\""

// TEMP 
#define SERVER "127.0.0.1"
#define SERVPORT 5514
#define PROTOCOL "UDP"


// Global Variables
char ubname[255] = "testlb";
char ubpath[255] = "/var/run/unix_testlb";

typedef struct type_csocket {
  int fd;
  int buffer_size;
  int trimmed;
  char *buffer;
} inst_csocket;


/*
 * Function:  sendlogs
 * --------------------
 * Sends syslog and prints msg to screen
 *
 *  level: the syslog severity
 *  msgarg: pointer to the message
 *
 *  returns: nothing
 */
void sendlogs(int level, char *msgarg) {
   char message[255];
   snprintf(message, 250, "LB [%s] - %s", ubname, msgarg);
   syslog(level, message);
   fflush(stdout);
}


/*
 * Function:  getTotalSystemMemory
 * -------------------------------
 * Returns the total system memory
 *
 *  returns: size_t with memory
 */
size_t getTotalSystemMemory()
{
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    return pages * page_size;
}


/*
 * Function:  refresh
 * ------------------
 * Called on itimer to send status to syslog
 *
 *  returns: none
 */
void refresh(int signum){
   if (signum == SIGUSR1) {
      char counter_message[200];
      // Report memory usage
      struct rusage r_usage;
      getrusage(RUSAGE_SELF,&r_usage);
      sprintf(counter_message, "MEM Used:%ld / Total:%zu", r_usage.ru_maxrss, getTotalSystemMemory());
      sendlogs(LOG_INFO,counter_message);
   }
}


/*
 * Function:  regex_replace
 * ------------------------
 * Replace the part of src that matches the regex
 *  with ""
 *
 *  src: Ptr to the char buffer (changed in placE)
 *  regex: ansi c regex definition
 *
 *  returns: strlen of modified string
 */
int regex_replace(char *src, int len, regex_t re)
{
    char dest[MAX_BUFFER];
    int newsize=0;
    regmatch_t pmatch[10];

    // Do the regex matching up until one match
    if (regexec (&re, src, 1, pmatch, 0)) {
       return len;
    }
    if (pmatch[0].rm_so == -1) {
       return len;
    }       
    // DEBUG printf("Found match between index %d and %d\n", pmatch[0].rm_so, pmatch[0].rm_eo);

    // Move into target, everything except the data between the regex match
    // End with null byte
    memcpy(dest, src, pmatch[0].rm_so);
    memcpy(&dest[pmatch[0].rm_so], &src[pmatch[0].rm_eo], len - pmatch[0].rm_eo);
    newsize = len - (pmatch[0].rm_eo - pmatch[0].rm_so);
    dest[newsize]='\0';
    // DEBUG printf("Previous string length: %d\n",strlen(src));
    // DEBUG printf("New string length: %d\n",strlen(dest));
    // Move back to the source
    memcpy(src, dest, newsize);
    src[newsize]='\0';
    // Return the length
    return newsize;
}


int destination_connect() {
    struct sockaddr_in dest_socket;
    char dest_servername[255];
    int dest_rc, dest_sd;
    if ( strcmp(PROTOCOL,"TCP")==0 )
    {
       if((dest_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
       {
          perror("socket error");
          return -1;
       }
       dest_socket.sin_family = AF_INET;
       dest_socket.sin_port = htons(SERVPORT);
       if (inet_aton(SERVER , &dest_socket.sin_addr) == 0)
       {
          perror("inet_aton error");
          return -1;
       }
       if((dest_rc = connect(dest_sd, (struct sockaddr *)&dest_socket, sizeof(dest_socket))) < 0) {
          perror("connect error");
          close(dest_sd);
          return -1;
       }
    }
    else if ( strcmp(PROTOCOL,"UDP")==0 ) 
    {
      if ( (dest_sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      {
          perror("socket error");
          return -1;
      }
    }
    else 
    {
      return -1; 
    }

    sendlogs(LOG_INFO, "Connected to destination.");
    return dest_sd;
}


int destination_send(int sd, char *data, int len) {
    int rc;
    char temp;
    int length = sizeof(int);

    struct sockaddr_in dest_socket; // For UDP sendto


    if ( strcmp(PROTOCOL,"UDP") == 0 )
    {
       //strcpy(dest_servername, SERVER);
       memset(&dest_socket, 0x00, sizeof(struct sockaddr_in));
       dest_socket.sin_family = AF_INET;
       dest_socket.sin_port = htons(SERVPORT);
       if (inet_aton(SERVER , &dest_socket.sin_addr) == 0) 
       {
          perror("inet_aton error");
          return -1;
       }
       rc = sendto(sd, data, len, MSG_NOSIGNAL, (struct sockaddr *)&dest_socket, sizeof(struct sockaddr));
       if (rc < 0)
       {
          perror("write udp error");
          return 0; // Do not block the UDP
       }       
    }
    else if ( strcmp(PROTOCOL,"TCP") == 0 )   //already created socket
    {
       rc = send(sd, data, len, MSG_NOSIGNAL);
       if (rc < 0)
       { 
          perror("write tcp error");
          sendlogs(LOG_WARNING, "Error writing to destination. Closing descriptor.");
          close(sd);
          return -1;
       }
    }
    else {
       return 0;
    }

    // DEBUG printf("[D] TRANSMITTED %d bytes in socket\n", rc);
    return rc;
}


 
int main(int argc , char *argv[])
{
    // Vars - Listener socket
    int master_socket, addrlen, len, opt = 1;
    struct sockaddr_un address;

    // Vars - Destination socket
    int dest_sd;
    int dest_status = 0;

    // Vars - Clients & select
    inst_csocket csocket[MAX_CLIENTS];
    fd_set readfds;
    int new_socket, max_sd, activity, i;

    // Vars - Read & process
    int valread, temp_buffersize;
    char unix_sock_readbuffer[UNIX_SOCKET_READMAX];

    int forkme = 1, pid;
    //Fork the Parent Process if requested
    if (forkme==1) {
      // Redirect stds
      close(0); close(1); close(2);
      open("/dev/null",O_RDWR); dup(0); dup(0);
      // Do the forking
      pid = fork();
      if (pid < 0) { exit(EXIT_FAILURE); }
      if (pid > 0) { exit(EXIT_SUCCESS); }
    }
  
    /*
     *
     * Signal handling
     *
     * */ 
    //signal(SIGUSR1, refresh);


    /* 
     *
     * Create AF_UNIX listener
     *
     * */
    umask(0);
    if( (master_socket = socket(AF_UNIX , SOCK_STREAM , 0)) == 0) 
    {
        perror("socket error");
        sendlogs(LOG_ERR, "Error while listening on af_unix socket");
        exit(EXIT_FAILURE);
    }
    if( setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0 )
    {
        perror("setsockopt");
        sendlogs(LOG_ERR, "Error while listening on af_unix socket");
        exit(EXIT_FAILURE);
    }  
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, ubpath);
    unlink(address.sun_path);
    len = strlen(address.sun_path) + sizeof(address.sun_family);
    if (bind(master_socket, (struct sockaddr *)&address, len)<0) 
    {
        perror("bind error");
        sendlogs(LOG_ERR, "Error while listening on af_unix socket");
        exit(EXIT_FAILURE);
    }
    sendlogs(LOG_INFO, "Listening on unix socket\n");     
    if (listen(master_socket, 3) < 0)
    {
        perror("listen error");
        sendlogs(LOG_ERR, "Error while listening on af_unix socket");
        exit(EXIT_FAILURE);
    }      
    addrlen = sizeof(address);
    sendlogs(LOG_INFO, "Waiting for connection");
    umask(022);

    printf("[*] Waiting for connections...\n");


    /*
     *
     * Create sender socket
     *
     * */
    if ( (dest_sd = destination_connect()) > 0 )
        dest_status = 1;
    else 
        sendlogs(LOG_WARNING, "Error connecting to destination. Logs will drop until reconnect...");


    /*
     *
     * Compile regexes for pattern matching
     *
     * */
    regex_t re1, re2;
    if ( regcomp (&re1, REGEX1, 0)==0 && regcomp (&re2, REGEX2, 0)==0 ) {
        printf("[*] Successfully compiled regexes...\n");
        sendlogs(LOG_INFO, "Successfully compiled regexes");
    }
    else {
        perror("regcomp error");
        sendlogs(LOG_ERR, "Error compiling regexes");
        exit(EXIT_FAILURE);
    }


    /*
     *                 
     * IO Loop
     *
     * */
    // Initialise all client_socket[] to 0 so not checked
    for (i = 0; i < MAX_CLIENTS; i++)
    {
        csocket[i].fd = 0;
        csocket[i].buffer = (char *)malloc(MAX_BUFFER * sizeof(char));
        memset(csocket[i].buffer, 0, MAX_BUFFER);
        csocket[i].buffer_size = 0;
        csocket[i].trimmed = 0;
    }
    while (1) 
    {
        // Prepare sockets for select (add them to FDSET)
        FD_ZERO(&readfds);
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;
        for ( i = 0 ; i < MAX_CLIENTS ; i++) 
        {
            //if valid socket descriptor then add to read list
            if(csocket[i].fd > 0)
                FD_SET( csocket[i].fd , &readfds);
            //highest file descriptor number, need it for the select function
            if(csocket[i].fd > max_sd)
                max_sd = csocket[i].fd;
        }
        
        // Select - wait for an activity on one of the sockets , timeout is NULL , so wait indefinitely
        activity = select( max_sd + 1 , &readfds , NULL , NULL , NULL);
    
        if ((activity < 0) && (errno!=EINTR)) 
        {
            printf("select error");
            sendlogs(LOG_ERR, "select() error");
        }
        else if (errno==EINTR)
        {
            printf("interrupted by signal");
        }
          
        // Listener socket - New connection
        if (FD_ISSET(master_socket, &readfds)) 
        {
            if ((new_socket = accept(master_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
            {
                perror("accept");
                sendlogs(LOG_ERR, "Error while accepting af_unix connection from client");
                exit(EXIT_FAILURE);
            }
            // Add to array of sockets, next run will be added to FDSET
            for (i = 0; i < MAX_CLIENTS; i++) 
            {
                //if position is empty
                if( csocket[i].fd == 0 )
                {
                    csocket[i].fd = new_socket;
                    printf("[%d] New connection on %d: Adding to list of sockets as %d\n" , i, new_socket, i);
                    sendlogs(LOG_INFO, "Host connected\n");
                    break; // Back to select
                }
            }
        }

        // Else its some IO operation on some other socket
        for (i = 0; i < MAX_CLIENTS; i++) 
        {
            if (FD_ISSET( csocket[i].fd , &readfds)) 
            {
                // Check if it was for closing
                if ((valread = read( csocket[i].fd , unix_sock_readbuffer, UNIX_SOCKET_READMAX - UNIX_SOCKET_READMAX / 10 )) == 0)
                {
                    // Somebody disconnected , get his details and print
                    getpeername(csocket[i].fd , (struct sockaddr*)&address , (socklen_t*)&addrlen);
                    printf("[%d] Host disconnected\n", i);
                    sendlogs(LOG_INFO, "Host disconnected\n");

                    // Retrieve data from socket buffer, send, clear
                    // NO NEED LAST MSG - csocket[i].buffer_size = regex_replace(csocket[i].buffer, REGEX1);  
                    // NO NEED LAST MSG - csocket[i].buffer_size = regex_replace(csocket[i].buffer, REGEX2);
                    if (csocket[i].trimmed==1) {
                       // DEBUG printf("[%d] Discarding trimmed log\n", i);
                    }
                    else if ((dest_status == 1) && (destination_send(dest_sd, csocket[i].buffer, csocket[i].buffer_size) < 0)) {
                       dest_status = 0;
                       sendlogs(LOG_WARNING, "Destination disabled. Will drop until reconnect...");
                    }
                    //DEBUG printf("[%d] Emitting log of %d bytes\n", i, csocket[i].buffer_size);
                    memset(csocket[i].buffer, 0, MAX_BUFFER);
                    csocket[i].buffer_size = 0;
                      
                    // Close the socket and mark as 0 in list for reuse
                    close( csocket[i].fd );
                    csocket[i].fd = 0;
                    memset(csocket[i].buffer, 0, MAX_BUFFER);
                    csocket[i].buffer_size = 0;
                    csocket[i].trimmed = 0;
                }

                // Process message
                else
                {
                    // Append and line terminator just to be safe
                    unix_sock_readbuffer[valread] = '\0';
                    
                    //printf("[%d] AF_UNIX read (%d bytes): %s\n", i, valread, unix_sock_readbuffer);

                    // Check for newline in order to split message and keep the rest
                    char *line_start = unix_sock_readbuffer;
                    char *line_end;
                    line_end = (char*)memchr((void*)line_start, '\n', valread);

                    // Add read data to current buffer (either all or until newline found above)
                    //  Trim buffer to avoid BUS ERROR from overflow
                    if (line_end==NULL) 
                        temp_buffersize = valread;
                    else 
                        temp_buffersize = line_end - line_start;
                    if ( csocket[i].buffer_size + temp_buffersize > MAX_BUFFER )
                    {
                        // DEBUG printf("[%d] Trimming buffer!\n", i);
                        temp_buffersize = MAX_BUFFER - csocket[i].buffer_size - 1;
                        csocket[i].trimmed = 1;
                    }
                    memmove(csocket[i].buffer + csocket[i].buffer_size, line_start, temp_buffersize);
                    csocket[i].buffer_size += temp_buffersize;
                    csocket[i].buffer[csocket[i].buffer_size]='\n';

                    // If NO newline was found, BUT the read length in less than MAX -- OR
                    // If newline WAS found
                    //  --> we can send the current buffer and clear it           
                    if ( (valread < UNIX_SOCKET_READMAX - UNIX_SOCKET_READMAX / 10) || line_end  ) 
                    {
                        // Retrieve data from socket buffer, send and clear
                        csocket[i].buffer_size = regex_replace(csocket[i].buffer, csocket[i].buffer_size, re1);
                        csocket[i].buffer_size = regex_replace(csocket[i].buffer, csocket[i].buffer_size, re2);
                        csocket[i].buffer[csocket[i].buffer_size++]='\n';
                        csocket[i].buffer[csocket[i].buffer_size]='\0';
                        if (csocket[i].trimmed==1) {
                            // DEBUG printf("[%d] Discarding trimmed log\n", i);
                        }
                        else if ((dest_status == 1) && (destination_send(dest_sd, csocket[i].buffer, csocket[i].buffer_size) < 0)) {
                            dest_status = 0;
                            sendlogs(LOG_WARNING, "Destination disabled. Will drop until reconnect...");
                        }
                        //DEBUG printf("[%d] Emitting log of %d bytes\n", i, csocket[i].buffer_size);
                        memset(csocket[i].buffer, 0, MAX_BUFFER);
                        csocket[i].buffer_size = 0;
                        csocket[i].trimmed = 0;
                    }

                    // If newline was found, add the rest of split data to the buffer for next round
                    if (line_end) 
                    {
                        if (valread != line_end - line_start + 1) // Edge condition, if \n is last byte, ignore rest
                        { 
                           memcpy(csocket[i].buffer, line_end + 1, valread - 1); // +1 to account for the /n itself
                           csocket[i].buffer_size = valread - (line_end - line_start) - 1; 
                           csocket[i].buffer[csocket[i].buffer_size]='\0';
                           if ( *(line_end + 1)!=123 ) {
                              sendlogs(LOG_WARNING, "Buffer after split not starting with curly brace");
                           }
                        }
                    }

                }
            }
        }
    }
    printf("Ended\n");      
    return 0;
} 

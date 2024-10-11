// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

using namespace std;
using namespace google::protobuf::io;

#define MAX_IPADDR_LEN 256

google::protobuf::uint32 readHdr(char *buf)
{
  google::protobuf::uint32 size;
  google::protobuf::io::ArrayInputStream ais(buf,4);
  CodedInputStream coded_input(&ais);
  coded_input.ReadVarint32(&size);
#ifdef VERBOSE
  cout<<"size of payload is "<<size<<endl;
#endif //VERBOSE
  return size;
}

int readMessage(int sock, google::protobuf::uint32 size, char **buf, int *buflen)
{
        int bytecount = 0;
        char *payload = (char*) malloc(sizeof(char) * (size+4));
        bytecount = recv(sock, (void*)payload, size+4, MSG_WAITALL);
        if (bytecount < 0) {
                cout << "Error reading further payload bytes" << std::endl;
		close(sock);
                return -1;
        }
	*buf = payload;
	*buflen = bytecount;
	close(sock);
	return 0;
}

static char *
fetchDefaultGateway(bool refetch)
{
    static char gateway[MAX_IPADDR_LEN] = {0x0};
    static bool cached = false;
    char line[MAX_IPADDR_LEN] = {0x0};

    if (cached && !refetch) {
	    return gateway;
    }

    FILE* fp = popen("route -n | grep 'UG[ \t]' | grep '[ \t]0.0.0.0[ \t]' | awk '{printf \"%s\", $2}'", "r");

    if(fgets(line, sizeof(line), fp) != NULL) {
	strncpy(gateway, line, MAX_IPADDR_LEN);
	cached = true;
    }

    pclose(fp);
    return gateway;
}

int sendrecv(const char *data_to_send, int data_len, int *length, char **resp) {
	//TBD: Move these to #defines or arguments
	const char* server_name = fetchDefaultGateway(false);
	const int server_port = 8877;

#ifdef VERBOSE
	cout << "Sending " << data_len << "bytes" << std::endl;
	cout << "server_name is " << server_name << std::endl;
#endif //VERBOSE

	if (server_name == NULL) {
		cout << "Unable to fetch default gateway IP address" << std::endl;
		return -1;
	}

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;

	inet_pton(AF_INET, server_name, &server_address.sin_addr);

	// htons: port in network order format
	server_address.sin_port = htons(server_port);

	// open a stream socket
	int sock;
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		cout << "Could not create socket" << std::endl;
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&server_address,
	            sizeof(server_address)) < 0) {
		cout << "Could not connect to server" << std::endl;
		fetchDefaultGateway(true);
		return -1;
	}

	// send
	if (send(sock, data_to_send, data_len, 0) < 0) {
		cout << "Sending to server failed" << std::endl;
		return -1;
	}

	// receive
	int bytecount = 0;
	int hdrlen = 4;
        char hdr_buffer[4];
        char *pbuffer = hdr_buffer;
        bytecount = recv(sock, pbuffer, hdrlen, MSG_PEEK);
        if (bytecount > 0) {
#ifdef VERBOSE
             cout << "Received new response, and parsed the hdr" << std::endl;
#endif //VERBOSE
             return readMessage(sock, readHdr(hdr_buffer), resp, length);
        }

	return 0;
}

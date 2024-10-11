// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include "api.pb.h"
#include <string.h>
#include <list>
#include <algorithm>
#include <string>
#include <fstream>
#include <sstream>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include "sendrecv.h"

using namespace std;
using namespace google::protobuf::io;
extern int sendrecv(const char *data_to_send, int data_len, int *length, char **resp);

//Denote if a cmdline arg needs to be evaluated to be a filename
enum opt_check_type {
   FILENAME = 1,
   DONTCARE = 2,
};

//Denote if a cmdline arg is input file or output file
enum opt_file_direction {
    IN = 1,
    OUT =2,
};

//Putting it all together: for every command that handles files in
//it arguments, have an entry here, with name of the command, the 
//option flag to parse for the filename, its direction etc.
typedef struct file_mapping {
    const char *cmd;
    const char *opt;
    enum opt_check_type check_type;
    enum opt_file_direction dir;
}file_mapping;

std::list<string> cmds_w_file_operands = {
"tpm2_sign",
"tpm2_hash",
"tpm2_hmac",
};

//The holder for various commands we support.
//TBD, read this data from a yaml file instead?
static file_mapping file_mappings[] = { 
{ "tpm2_sign",     "-t", DONTCARE, IN  },
{ "tpm2_sign",     "-o", DONTCARE, OUT },
{ "tpm2_sign",     "-c", FILENAME, IN },
{ "tpm2_hash",     "-t", DONTCARE, OUT },
{ "tpm2_hash",     "-o", DONTCARE, OUT },
{ "tpm2_createprimary",     "-c", DONTCARE, OUT },
{ "tpm2_readpublic",     "-c", FILENAME, IN },
{ "tpm2_readpublic",     "-o", DONTCARE, OUT},
{ "tpm2_startauthsession",     "-S", DONTCARE, OUT},
{ "tpm2_policysecret",     "-S", DONTCARE, IN},
{ "tpm2_policysecret",     "-L", DONTCARE, OUT},
{ "tpm2_policysecret",     "-c", FILENAME, IN},
{ "tpm2_activatecredential",     "-c", FILENAME, IN},
{ "tpm2_activatecredential",     "-C", FILENAME, IN},
{ "tpm2_activatecredential",     "-i", DONTCARE, IN},
{ "tpm2_activatecredential",     "-o", DONTCARE, OUT},
{ "tpm2_import",     "-C", FILENAME, IN},
{ "tpm2_import",     "-k", DONTCARE, IN},
{ "tpm2_import",     "-u", DONTCARE, IN},
{ "tpm2_import",     "-i", DONTCARE, IN},
{ "tpm2_import",     "-s", DONTCARE, IN},
{ "tpm2_import",     "-L", DONTCARE, IN},
{ "tpm2_import",     "-r", DONTCARE, OUT},
{ "tpm2_load",     "-C", FILENAME, IN},
{ "tpm2_load",     "-c", DONTCARE, OUT},
{ "tpm2_load",     "-u", DONTCARE, IN},
{ "tpm2_load",     "-r", DONTCARE, IN},
{ "tpm2_hmac",     "-c", FILENAME, IN},
{ "tpm2_hmac",     "-o", DONTCARE, OUT},
};


//Helper function to check if a given string is a 
//hex number: 0xABCD/0xabcd/0Xabcd/0XABCD all are valid hex
bool isStringHex(std::string const& s)
{
  return (s.compare(0, 2, "0x") == 0 || s.compare(0, 2, "0X") == 0)
          && s.size() > 2
          && s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
}


//We have got an argument that can either have a hex or a filename
//Check if arg is hex or filename; if filename, then check if it is
//an input file or an outpufile, and pack the protobuf accordingly.
int populateFileEntries (int argc, const char *argv[],
                           eve_tools::EveTPMRequest &request,
                           file_mapping &cmd, int opt_index)
{
    if (cmd.check_type == FILENAME && opt_index < (argc-1)) {
#ifdef VERBOSE
	cout << "Checking if " << argv[opt_index+1] << " is a filename" << std::endl;
#endif //VERBOSE
        if (!isStringHex(string(argv[opt_index+1]))) {
            if (cmd.dir == OUT) {
                request.add_expectedfiles(argv[opt_index+1]);
            } else {
                fstream file;
                file.open(argv[opt_index+1], ios::in|ios::binary);
                if (!file) {
                    cout << "File not found: " << argv[opt_index+1] << std::endl;
                    return -1;
                }
                ostringstream ostrm;
                ostrm << file.rdbuf();
                eve_tools::File *input_file = request.add_inputfiles();
                input_file->set_name(argv[opt_index+1]);
                input_file->set_content(ostrm.str());
                file.close();
            }
        }
    } else {
        if (cmd.dir == OUT) {
            request.add_expectedfiles(argv[opt_index+1]);
        } else {
            fstream file;
            file.open(argv[opt_index+1], ios::in|ios::binary);
            if (!file) {
                cout << "File not found: " << argv[opt_index+1] << std::endl;
                return -1;
            }
            ostringstream ostrm;
            ostrm << file.rdbuf();
            eve_tools::File *input_file = request.add_inputfiles();
            input_file->set_name(argv[opt_index+1]);
            input_file->set_content(ostrm.str()); 
            file.close();
        }
    }
    return 0;
}

int processSpecialCmds(int argc, const char *argv[],
                   eve_tools::EveTPMRequest &request)
{
  std::string command(argv[1]);
  if (argc < 2) {
	  //Nothing to parse, no args for the command.
	  return 0;
  }
  auto it = find(cmds_w_file_operands.begin(), cmds_w_file_operands.end(), command);
  if (it != cmds_w_file_operands.end()) {
            fstream file;
            ostringstream ostrm;
            file.open(argv[argc-1], ios::in|ios::binary);
            if (!file) {
                cout << "File not found: " << argv[argc-1] << std::endl;
                return -1;
            }
            ostrm << file.rdbuf();
            eve_tools::File *input_file = request.add_inputfiles();
            input_file->set_name(argv[argc-1]);
            input_file->set_content(ostrm.str()); 
            file.close();
  }
  return 0;
}

//We've received a command which can have filename as args
//Check if we have actually received any filename args
int processCmdOpts(int argc, const char *argv[],
                   eve_tools::EveTPMRequest &request,
                   file_mapping &cmd)
{
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], cmd.opt)) {
            return populateFileEntries(argc, argv, request, cmd, i);
        }
    }
    return 0;
}

int prepareFileMappings(int argc, const char *argv[],
                        eve_tools::EveTPMRequest &request)
{
    for (int i = 0; i < sizeof(file_mappings)/sizeof(file_mapping); i++) {
        if (!strcmp(argv[1], file_mappings[i].cmd)) {
           processCmdOpts(argc, argv, request, file_mappings[i]);
        }
    }
    processSpecialCmds(argc, argv, request);
    return 0;
}

static int doUnitTest()
{
    int argc = 3;
    const char *argv[] = {"tpm2_createek", "-t", "test.jpg" };
    eve_tools::EveTPMRequest request;
    prepareFileMappings(argc, argv, request);
    std::string output; 
    request.SerializeToString(&output);
    eve_tools::EveTPMRequest target;
    target.ParseFromString(output);
    for (int i=0; i < target.inputfiles_size(); i++) {
        const eve_tools::File& file = target.inputfiles(i);
#ifdef VERBOSE
        cout << "Processing file: " << file.name() << std::endl;
#endif //VERBOSE
        ofstream target_file;
        target_file.open("test1.jpg", ios::out|ios::binary);
        if (!target_file) {
            cout << "Unable to open test file for writing" << std::endl;
            return -1;
        }
        target_file << file.content();
        target_file.close();
    }
    return 0;
        
}

int main (int argc, char *argv[])
{
#ifdef UNIT_TEST
    //TBD: Have a better way of running UT. Google GTEST?
    //for now, a poor man's unit test.
    doUnitTest();
#else
    if (argc < 2) {
	    cout << "Usage: eve_run tpm_command [args]" << std::endl;
	    return 0;
    }
    eve_tools::EveTPMRequest request;
    prepareFileMappings(argc, (const char **) argv, request);
    std::string output; 
    ostringstream command;
    for (int i=1; i < argc; i++) {
        command <<" " << argv[i];
    }
    request.set_command(command.str());
    int siz = request.ByteSize() + 4;
    char *pkt = new char [siz];
    google::protobuf::io::ArrayOutputStream aos(pkt,siz);
    CodedOutputStream *coded_output = new CodedOutputStream(&aos);
    coded_output->WriteVarint32(request.ByteSize());
    request.SerializeToCodedStream(coded_output);
    //request.SerializeToString(&output);
    int resp_length;
    char *resp_buf;
    int rc = sendrecv(pkt, siz, &resp_length, &resp_buf);
    if (rc != 0) {
        cout << "Failed to send request: " << rc << std::endl;
    }
    eve_tools::EveTPMResponse response;
        google::protobuf::io::ArrayInputStream ais(resp_buf, resp_length);
        CodedInputStream coded_input(&ais);
    google::protobuf::uint32 size;
        coded_input.ReadVarint32(&size);
        google::protobuf::io::CodedInputStream::Limit msgLimit = coded_input.PushLimit(size);
        response.ParseFromCodedStream(&coded_input);
        coded_input.PopLimit(msgLimit);
    //response.ParseFromString(resp_buf);
    for (int i=0; i < response.outputfiles_size(); i++) {
        const eve_tools::File& file = response.outputfiles(i);
        ofstream output_file;
        output_file.open(file.name(), ios::out|ios::binary);
        if (!output_file) {
            cout << "Unable to open file for writing: "
                << file.name() << std::endl;
            return -1;
        }
        output_file << file.content();
        output_file.close();
    }
    cout << response.response() << std::endl;
#endif
    return 0;
}





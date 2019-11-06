#include <iostream>
#include "api.pb.h"
#include <string.h>
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

//The holder for various commands we support.
//TBD, read this data from a yaml file instead?
static file_mapping file_mappings[] = { 
{ "tpm2_createek", "-c", FILENAME, OUT },
{ "tpm2_createek", "-u", DONTCARE, OUT },
{ "tpm2_createek", "-t", DONTCARE, IN  },
{ "tpm2_createak", "-c", FILENAME, OUT },
{ "tpm2_createak", "-u", DONTCARE, OUT },
{ "tpm2_createak", "-n", DONTCARE, OUT },
{ "tpm2_createak", "-r", DONTCARE, OUT },
{ "tpm2_sign",     "-c", FILENAME, IN  },
{ "tpm2_sign",     "-d", DONTCARE, IN  },
{ "tpm2_sign",     "-t", DONTCARE, IN  },
{ "tpm2_sign",     "-o", DONTCARE, OUT },
};


//Helper function to check if a given string is a 
//hex number: 0xABCD or 0XABCD, both are valid hex
bool is_hex_notation(std::string const& s)
{
  return (s.compare(0, 2, "0x") == 0 || s.compare(0, 2, "0X") == 0)
      && s.size() > 2
      && s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
}

int populate_file_entries (int argc, const char *argv[], eve_tools::EveTPMRequest &request, file_mapping &cmd, int opt_index)
{
    if (cmd.check_type == FILENAME && opt_index < (argc-1)) {
        if (!is_hex_notation(string(argv[opt_index+1]))) {
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


int process_cmd_opts(int argc, const char *argv[], eve_tools::EveTPMRequest &request, file_mapping &cmd)
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], cmd.opt)) {
            return populate_file_entries(argc, argv, request, cmd, i);
        }
    }
    return 0;
}

int prepare_file_mappings(int argc, const char *argv[], eve_tools::EveTPMRequest &request) {
    for (int i = 0; i < sizeof(file_mappings)/sizeof(file_mapping); i++) {
        if (strstr(argv[0], file_mappings[i].cmd)) {
           return process_cmd_opts(argc, argv, request, file_mappings[i]);
        }
    }
    return 0;
}

static int unit_test() {
    int argc = 3;
    const char *argv[] = {"tpm2_createek", "-t", "test.jpg" };
    eve_tools::EveTPMRequest request;
    prepare_file_mappings(argc, argv, request);
    std::string output; 
    request.SerializeToString(&output);
    eve_tools::EveTPMRequest target;
    target.ParseFromString(output);
    for (int i=0; i < target.inputfiles_size(); i++) {
        const eve_tools::File& file = target.inputfiles(i);
        cout << "Processing file: " << file.name() << std::endl;
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

std::string& getBaseName(std::string& str) 
{
    const size_t last_slash_idx = str.find_last_of("\\/");
    if (std::string::npos != last_slash_idx)
    {
        str.erase(0, last_slash_idx + 1);
    }
    return str;
}


int main (int argc, char *argv[]) {
#ifdef UNIT_TEST
    unit_test();
#else
    eve_tools::EveTPMRequest request;
    prepare_file_mappings(argc, (const char **) argv, request);
    std::string toolName(argv[0]);
    std::string output; 
    std::string& trimmedToolName = getBaseName(toolName);
    trimmedToolName.erase(0,1);
    ostringstream command;
    command << trimmedToolName;
    for (int i=1; i <argc; i++) {
        command <<" " << argv[i];
    }
    request.set_command(command.str());
    //cout << "Size of the payload before CodedStream is " << request.ByteSize() << std::endl;
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
    //cout << "Payload byte count is " << resp_length;
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
        //cout << "Processing file: " << file.name() << std::endl;
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




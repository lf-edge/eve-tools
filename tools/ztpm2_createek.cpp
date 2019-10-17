#include <iostream>
#include "api.pb.h"
#include <string.h>
#include <string>
#include <fstream>
#include <sstream>

using namespace std;
extern "C" {
extern int sendrecv(const char *data_to_send, int maxlen, int *length, char **resp);
}

enum opt_check_type {
   FILENAME = 1,
   DONTCARE = 2,
};

enum opt_file_direction {
	IN = 1,
	OUT =2,
};

typedef struct file_mapping {
	const char *cmd;
	const char *opt;
	enum opt_check_type check_type;
	enum opt_file_direction dir;
}file_mapping;


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

bool is_hex_notation(std::string const& s)
{
  return (s.compare(0, 2, "0x") == 0 || s.compare(0, 2, "0X") == 0)
      && s.size() > 2
      && s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
}

int prepare_file_mappings(int argc, const char *argv[], eve_tools::EveTPMRequest &request) {
	cout << "Preparing arguments" << std::endl;
	for (int i = 0; i < sizeof(file_mappings)/sizeof(file_mapping); i++) {
		if (strstr(argv[0], file_mappings[i].cmd)) {
			for (int j = 1; j < argc; j++) {
				if (!strcmp(argv[j], file_mappings[i].opt)) {
					cout << "Found a file mapping at " << argv[0] <<", " <<  argv[j] << std::endl;
					if (file_mappings[i].check_type == FILENAME && j < (argc-1)) {
						if (!is_hex_notation(string(argv[j+1]))) {
							cout << "Filename detected in the argument " << argv[j+1] << std::endl;
							if (file_mappings[i].dir == OUT) {
								request.add_expectedfiles(argv[j+1]);
							} else {
								fstream file;
								file.open(argv[j+1], ios::in|ios::binary);
								if (!file) {
								     cout << "File not found: " << argv[j+1] << std::endl;
								     return -1;
								}
								ostringstream ostrm;
								ostrm << file.rdbuf();
								eve_tools::File *input_file = request.add_inputfiles();
								input_file->set_name(argv[j+1]);
								input_file->set_content(ostrm.str());
								file.close();
							}
						}
					} else {
						cout << "Filename detected in the argument " << argv[j+1] << std::endl;
						if (file_mappings[i].dir == OUT) {
							request.add_expectedfiles(argv[j+1]);
						} else {
							fstream file;
							file.open(argv[j+1], ios::in|ios::binary);
							if (!file) {
							     cout << "File not found: " << argv[j+1] << std::endl;
							     return -1;
							}
							ostringstream ostrm;
							ostrm << file.rdbuf();
							eve_tools::File *input_file = request.add_inputfiles();
							input_file->set_name(argv[j+1]);
							input_file->set_content(ostrm.str()); 
							file.close();
						}
					}
				}
			}
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
int main (int argc, char *argv[]) {
#ifdef UNIT_TEST
	unit_test();
#else
	eve_tools::EveTPMRequest request;
	prepare_file_mappings(argc, argv, request);
	std::string output; 
	request.SerializeToString(&output);
	int resp_length;
	char *resp_buf;
	int rc = sendrecv(output.c_str(), output.length(), &resp_length, &resp_buf);
	if (rc != 0) {
		cout << "Failed to send request: " << rc << std::endl;
	}
#endif
	return 0;
}




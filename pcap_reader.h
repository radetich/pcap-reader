#ifndef PCAP_READER_H
#define PCAP_READER_H


#include <string>
#include <iostream>
#include <pcap.h>

//UPDATE THE FOLLOWING TWO INCLUDES FOR YOUR OPERATING SYSTEM (Currently configured for: Ubuntu 18.04)
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>

using namespace boost::filesystem;
using namespace std;

vector <string> get_pcaps(string folder_path);

#endif
#ifndef PCAP_READER_H
#define PCAP_READER_H


#include <string>
#include <iostream>
#include <pcap.h>
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>

using namespace boost::filesystem;
using namespace std;

vector <string> get_pcaps(string folder_path);

#endif
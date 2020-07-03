#ifndef PCAP_READER_HPP
#define PCAP_READER_HPP


#include <string>
#include <iostream>
#include <pcap.h>
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>

using namespace boost::filesystem;
using namespace std;

vector <string> get_pcaps(string folder_path);

int process();

#endif
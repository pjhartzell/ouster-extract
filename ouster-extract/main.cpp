#pragma once
#include "ouster-pcap-reader.h"

// argument order:
//	1. PCAP filepath.
//	2. Intrinsic angle filepath (JSON format file).
//	3. Number of data packets to process at a time (chunk size). A value
//	   less than 1 will attempt to load and process the entire file in one go.

int main(int argc, char* argv[]) {
	
	// open pcap file
	OusterPCAP pcap;
	if (!pcap.Open(argv[1])) {
		std::cout << "Failure opening PCAP file. Aborting." << std::endl;
		return -1;
	}

	// import beam angles
	if (!pcap.ImportAngles(argv[2])) {
		std::cout << "Failure importing JSON file of angles. Aborting." << std::endl;
		return -1;
	}

	// cycle through chunks of udp data packets
	std::cout << "Converting Ouster PCAP file to LAS...";
	int num_packets = std::stoi(argv[3]);
	int chunk_num = 1;
	while (!pcap.eof_flag) {		
		pcap.ReadChunk(num_packets);
		pcap.ConvertChunk();
		pcap.SaveChunk(chunk_num, argv[1]);
		chunk_num++;
	}
	std::cout << "done." << std::endl;
}
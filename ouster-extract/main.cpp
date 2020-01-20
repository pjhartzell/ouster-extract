#pragma once
#include "ouster-pcap-reader.h"

// argument order:
//	1. PCAP filepath
//	2. Intrinsic angle filepath (JSON format file)
//	3. Number of data packets in a chunk (careful, a vector is
//     preallocated, so a large value will cause memory problems. 
//     A value of 100,000 should keep you out of trouble.)

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
	uint32_t chunk_size = std::stoul(argv[3]);
	int chunk_num = 1;
	//while (!pcap.eof_flag) {
		
		pcap.ReadChunk(chunk_size);
		pcap.ConvertChunk();
		pcap.SaveChunk(chunk_num, argv[1]);

		chunk_num++;
	//}
	std::cout << "done." << std::endl;
}
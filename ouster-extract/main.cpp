#pragma once
#include "ouster-pcap-reader.h"

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

	// cycle through chunks of records
	int chunk_size = 3;
	while (!pcap.eof_flag) {
		
		pcap.ReadChunk(chunk_size);
		//p.ConvertChunk();

	}
	   
	std::cout << "here" << std::endl;

}
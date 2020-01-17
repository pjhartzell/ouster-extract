#pragma once
#include <vector>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>

#include "pcap.h"
#include <json.hpp>


// 4 byte IP address
struct IpAddress {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

// IPv4 header
struct IpHeader {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	IpAddress  saddr;		// Source address
	IpAddress  daddr;		// Destination address
	u_int   op_pad;         // Option + Padding
};

// UDP header
struct UdpHeader {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
};

#pragma pack(push,1)
struct DataBlock
{
	uint32_t 	range;			// millimeters, discretized to nearest 3 mm
	uint16_t	intensity;
	uint16_t	reflectance;
	uint16_t	ambient_light;
	uint16_t	unused;
};
#pragma pack(pop)

#pragma pack(push,1)
struct AzimuthBlock
{
	uint64_t	timestamp;		// nanoseconds
	uint16_t 	measurement_id;	// azimuth based index
	uint16_t 	frame_id;		// scan rotation count
	uint32_t 	encoder_count;	// azimuth in [0,90111]
	DataBlock	data_block[64];
	int32_t		status;			// status of azimuth block
};

#pragma pack(push,1)
struct LidarDataPacket
{
	AzimuthBlock	azimuth_block[16];
};
#pragma pack(pop)

#pragma pack(push,1)
struct LidarMeasurement
{
	uint64_t	time;				// nanoseconds
	double		azimuth_angle;		// degrees
	double		altitude_angle;		// degrees
	uint32_t	range;				// meters
	uint16_t	intensity;			
	uint16_t	reflectance;
	uint16_t	ambient_light;
	double		x_lidar, y_lidar, z_lidar;		// meters; coordinate in lidar frame
	double		x_sensor, y_sensor, z_sensor;	// meters; coordinate in sensor frame
};
#pragma pack(pop)


class OusterPCAP {
private:
	// some winpcap stuff
	pcap_t*	fp;
	char	errbuff[PCAP_ERRBUF_SIZE];

public:
	bool	Open(std::string pcap_file);
	bool	ImportAngles(std::string angle_file);
	bool	ReadChunk(int num_packets);
	bool	ConvertChunk();

	bool							eof_flag = false;
	double							beam_altitudes[64];
	double							beam_azimuths[64];
	std::vector<LidarDataPacket>	raw_lidar;
	std::vector<LidarMeasurement>	converted_lidar;

};


bool OusterPCAP::Open(std::string pcap_file) {

	fp = pcap_open_offline(pcap_file.c_str(), errbuff);

	if (fp == NULL)
		return false;

	return true;
}


bool OusterPCAP::ImportAngles(std::string angle_file) {
	
	std::ifstream json_file(angle_file);
	if (!json_file)
		return false;

	nlohmann::json angles;
	json_file >> angles;
	nlohmann::json altitudes = angles["beam_altitude_angles"];
	nlohmann::json azimuths = angles["beam_azimuth_angles"];
	for (int i = 0; i < 64; i++) {
		beam_altitudes[i] = altitudes[i];
		beam_azimuths[i] = azimuths[i];
	}

	return true;
}


bool OusterPCAP::ReadChunk(int num_packets) {

	int returnVal;
	struct pcap_pkthdr* udp_header;
	const u_char* udp_data;
	int packet_count = 0;
	
	raw_lidar.resize(num_packets);
	while (((returnVal = pcap_next_ex(fp, &udp_header, &udp_data)) >= 0) && packet_count < num_packets) {

		// Destination port and packet length
		UdpHeader* udp_header = (UdpHeader*)((u_char*)udp_data + 34); // skip the ethernet header (14 bytes) and IP header (20 bytes)
		u_short destination_port = ntohs(udp_header->dport);
		u_short packet_length = ntohs(udp_header->len);

		// Ouster lidar data packet
		if ((destination_port == 7502) && (packet_length == 12616)) {

			// store raw data
			LidarDataPacket* raw_packet = (LidarDataPacket*)((u_char*)udp_data + 42);
			raw_lidar[packet_count] = *raw_packet;			
						
			/*std::cout << "Time=" << raw_lidar[packet_count].azimuth_block[1].timestamp << ", Encoder Count=" << raw_lidar[packet_count].azimuth_block[1].encoder_count << std::endl;
			int b = 0;
			std::cout << "Time=" << packet->azimuth_block[b].timestamp << ", Encoder Count=" << packet->azimuth_block[b].encoder_count << std::endl;
			std::cout << "Meas ID=" << packet->azimuth_block[b].measurement_id << ", Frame ID=" << packet->azimuth_block[b].frame_id << std::endl;
			std::cout << "Range=" << packet->azimuth_block[b].data_block[0].range << ", Intensity=" << packet->azimuth_block[b].data_block[0].intensity << std::endl;
			std::cout << "Reflectance=" << packet->azimuth_block[b].data_block[0].reflectance << ", Ambient=" << packet->azimuth_block[b].data_block[0].ambient_light << std::endl;
			std::cout << "Unused=" << packet->azimuth_block[b].data_block[0].unused << std::endl << std::endl;
			
			std::cout << "Time=" << packet->azimuth_block[b].timestamp << ", Encoder Count=" << packet->azimuth_block[b].encoder_count << std::endl;
			std::cout << "Meas ID=" << packet->azimuth_block[b].measurement_id << ", Frame ID=" << packet->azimuth_block[b].frame_id << std::endl;
			std::cout << "Range=" << packet->azimuth_block[b].data_block[1].range << ", Intensity=" << packet->azimuth_block[b].data_block[1].intensity << std::endl;
			std::cout << "Reflectance=" << packet->azimuth_block[b].data_block[1].reflectance << ", Ambient=" << packet->azimuth_block[b].data_block[1].ambient_light << std::endl;
			std::cout << "Unused=" << packet->azimuth_block[b].data_block[1].unused << std::endl << std::endl;

			b = 1;
			std::cout << "Time=" << packet->azimuth_block[b].timestamp << ", Encoder Count=" << packet->azimuth_block[b].encoder_count << std::endl;
			std::cout << "Meas ID=" << packet->azimuth_block[b].measurement_id << ", Frame ID=" << packet->azimuth_block[b].frame_id << std::endl;
			std::cout << "Range=" << packet->azimuth_block[b].data_block[0].range << ", Intensity=" << packet->azimuth_block[b].data_block[0].intensity << std::endl;
			std::cout << "Reflectance=" << packet->azimuth_block[b].data_block[0].reflectance << ", Ambient=" << packet->azimuth_block[b].data_block[0].ambient_light << std::endl;
			std::cout << "Unused=" << packet->azimuth_block[b].data_block[0].unused << std::endl << std::endl;

			std::cout << "Time=" << packet->azimuth_block[b].timestamp << ", Encoder Count=" << packet->azimuth_block[b].encoder_count << std::endl;
			std::cout << "Meas ID=" << packet->azimuth_block[b].measurement_id << ", Frame ID=" << packet->azimuth_block[b].frame_id << std::endl;
			std::cout << "Range=" << packet->azimuth_block[b].data_block[1].range << ", Intensity=" << packet->azimuth_block[b].data_block[1].intensity << std::endl;
			std::cout << "Reflectance=" << packet->azimuth_block[b].data_block[1].reflectance << ", Ambient=" << packet->azimuth_block[b].data_block[1].ambient_light << std::endl;
			std::cout << "Unused=" << packet->azimuth_block[b].data_block[1].unused << std::endl << std::endl;*/

			packet_count++;
		}		
	}

	if (returnVal == -2) { // reached end of file
		eof_flag = true;
	}

	// resize chunk vector
	raw_lidar.resize(packet_count);

	return true;
}


bool OusterPCAP::ConvertChunk() {




	return true;
}

//void ExtractPcap::ExtractOuster(LidarDataPacket* packet, int packet_count) {
//
//	// hex to decimal conversions: 
//	u_char strongestReturn = 55;	// 37->55 strongest return
//	u_char lastReturn = 56;			// 38->56 last return
//	u_char dualReturn = 57;			// 39->57 dual return
//
//	// nominal vlp16 vertical angles
//	int va[16] = { -15, 1, -13, -3, -11, 5, -9, 7, -7, 9, -5, 11, -3, 13, -1, 15 };
//
//	// compute seconds of the week (for compatibility with trajectory timestamps) while checking for a hour rollover in the velodyne time
//	double secOfWeek;
//	double veloSecOfHour = ((double)packet->timestamp) / 1000000;
//	int dayOfWeek = dow(currentNMEA.day, currentNMEA.month, currentNMEA.year);
//	if ((veloSecOfHour < 10) && (currentNMEA.minute > 55))
//		secOfWeek = dayOfWeek * 86400 + (currentNMEA.hour + 1) * 3600 + veloSecOfHour; // we have an hour rollover not yet picked up by the NMEA pps
//	else
//		secOfWeek = dayOfWeek * 86400 + (currentNMEA.hour) * 3600 + veloSecOfHour;
//
//	// interpolate and store observations for single returns	
//	if ((packet->returnType == strongestReturn) || (packet->returnType == lastReturn)) {
//
//		double azCurrent, azNext, az1, az2, azStart, azDelta;
//		lidarObs packetLidarObs[32 * 12];
//
//		// loop through each laser fire (two in each data block) and uniquely interpolate store azimuths and time for each return.
//		// store range, intensity, and time status while looping
//		// start with loop through each laser firing
//		for (int i = 0; i < 24; i++) {
//
//			int dataBlockNum = i / 2;
//
//			// get the start azimuth for current Laser Firing and the change in azimuth between the current and next Laser Firing
//			if ((i % 2 == 0) && (dataBlockNum < 11)) { // interpolate
//				azCurrent = (double)packet->dataBlock[dataBlockNum].azimuth;
//				az1 = azCurrent;
//				azNext = (double)packet->dataBlock[dataBlockNum + 1].azimuth;
//				if (azNext < azCurrent)
//					azNext += 360 * 100; // encoder stored in hundredths of a degree
//				az2 = az1 + (azNext - azCurrent) / 2;
//				azStart = az1;
//				azDelta = az2 - az1;
//			}
//			else if ((i % 2 == 1) && (dataBlockNum < 11)) {
//				azStart = az2;
//			}
//			else if ((i % 2 == 0) && (dataBlockNum == 11)) { // extrapolate last start azimuth
//
//				azCurrent = (double)packet->dataBlock[dataBlockNum - 1].azimuth;
//				azNext = (double)packet->dataBlock[dataBlockNum].azimuth;
//				if (azNext < azCurrent)
//					azNext += 360 * 100; // encoder stored in hundredths of a degree
//				az1 = azNext;
//				az2 = az1 + (azNext - azCurrent) / 2;
//				azStart = az1;
//				azDelta = az2 - az1;
//			}
//			else if ((i % 2 == 1) && (dataBlockNum == 11)) {
//				azStart = az2;
//			}
//
//			// looping through each channel return
//			for (int j = 0; j < 16; j++) {
//
//				// interpolate time
//				double timeOffset = (i * 55.296 + j * 2.304) / 1000000; // convert from microseconds to seconds
//				packetLidarObs[i * 16 + j].sow = secOfWeek + timeOffset;
//
//				// interpolate azimuth
//				double azOffset = azDelta * (j * 2.304) / 55.296;
//				double currAz = azStart + azOffset;
//				if (currAz > (360 * 100))
//					currAz -= (360 * 100);
//				packetLidarObs[i * 16 + j].az = currAz * 0.01; // convert from hundredths of degree to degrees
//
//				// range, intensity, channel, vertical angle				
//				packetLidarObs[i * 16 + j].range = ((double)packet->dataBlock[dataBlockNum].channelData[j].distance) * 0.002; // convert from 2mm increments to meters
//				packetLidarObs[i * 16 + j].intensity = (u_short)packet->dataBlock[dataBlockNum].channelData[j].intensity; // 0-255
//				packetLidarObs[i * 16 + j].channel = j + 1;
//				packetLidarObs[i * 16 + j].va = va[j];
//
//				// time status
//				if (!haveNMEA)
//					packetLidarObs[i * 16 + j].timeStatus = 2;
//				else if ((haveNMEA) && (!currentNMEA.valid))
//					packetLidarObs[i * 16 + j].timeStatus = 1;
//				else if ((haveNMEA) && (currentNMEA.valid))
//					packetLidarObs[i * 16 + j].timeStatus = 0;
//
//				// return number
//				packetLidarObs[i * 16 + j].returnNum = 1; // only single return
//			}
//		}
//
//		// copy the data packet lidar obervations into our chunk vector
//		for (int i = 0; i < 32 * 12; i++)
//			chunkLidarObs[packet_count * 32 * 12 + i] = packetLidarObs[i];
//	}
//
//}
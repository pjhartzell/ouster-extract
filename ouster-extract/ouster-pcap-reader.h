#pragma once

#define NOMINMAX
#define PI (2.0*asin(1.0))

#include <vector>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>

#include "pcap.h"
#include <json.hpp>
#include <pdal\io\LasWriter.hpp>
#include <pdal\io\BufferReader.hpp>


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
	uint32_t	status;			// status of azimuth block
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
	uint16_t	measurement_id;		// azimuth based index
	uint16_t 	frame_id;			// scan rotation count
	double		horizontal_angle;	// degrees
	double		vertical_angle;		// degrees
	double		range;				// meters
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
	void	ReadChunk(uint32_t num_packets);
	void	ConvertChunk();
	void	SaveChunk(int chunk_num, std::string pcap_file);

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


void OusterPCAP::ReadChunk(uint32_t num_packets) {

	int returnVal;
	struct pcap_pkthdr* udp_header;
	const u_char* udp_data;
	uint64_t packet_count = 0;
	
	raw_lidar.clear();
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
			
			//for (int i = 0; i < 16; i++) {
			//	for (int j = 0; j < 64; j++) {
			//		std::cout << "Time=" << raw_lidar[packet_count].azimuth_block[i].timestamp << ", Encoder Count=" << raw_lidar[packet_count].azimuth_block[i].encoder_count << std::endl;
			//		std::cout << "Meas ID=" << raw_lidar[packet_count].azimuth_block[i].measurement_id << ", Frame ID=" << raw_lidar[packet_count].azimuth_block[i].frame_id << std::endl;
			//		std::cout << "Range=" << raw_lidar[packet_count].azimuth_block[i].data_block[j].range << ", Intensity=" << raw_lidar[packet_count].azimuth_block[i].data_block[j].intensity << std::endl;
			//		std::cout << "Reflectance=" << raw_lidar[packet_count].azimuth_block[i].data_block[j].reflectance << ", Ambient=" << raw_lidar[packet_count].azimuth_block[i].data_block[j].ambient_light << std::endl;
			//		std::cout << "Unused=" << raw_lidar[packet_count].azimuth_block[i].data_block[j].unused << std::endl << std::endl;
			//	}
			//}
			
			packet_count++;
		}		
	}

	if (returnVal == -2) { // reached end of file
		eof_flag = true;
	}

	// resize chunk vector
	raw_lidar.resize(packet_count);
}


void OusterPCAP::ConvertChunk() {

	converted_lidar.clear();
	converted_lidar.resize(raw_lidar.size() * 16 * 64);

	int count = 0;
	double range, horizontal_angle, vertical_angle;

	// Iterate over data packets
	for (auto it = std::begin(raw_lidar); it != std::end(raw_lidar); ++it) {

		// Iterate over azimuth blocks
		for (int i = 0; i < 16; i++) {

			// Check for valid data in azimuth block
			if (it->azimuth_block[i].status > 0) {

				// Iterate over lasers
				for (int j = 0; j < 64; j++) {

					// only store ranges in (0,100]
					if ((it->azimuth_block[i].data_block[j].range > 0) && (it->azimuth_block[i].data_block[j].range <= 100000)) {

						// Convert range from millimeters to meters
						range = double(it->azimuth_block[i].data_block[j].range) / 1000;
						// Convert horizontal angle from ticks to radians and adjust for intrinsic beam azimuths 
						horizontal_angle = 2 * PI * (double(it->azimuth_block[i].encoder_count)/90112 + beam_azimuths[j]/360);
						// Convert intrinsic beam altitude angle to radians
						vertical_angle = 2 * PI * (beam_altitudes[j] / 360);

						// lidar frame coordinates
						converted_lidar[count].x_lidar = range * cos(horizontal_angle) * cos(vertical_angle);
						converted_lidar[count].y_lidar = -range * sin(horizontal_angle) * cos(vertical_angle);
						converted_lidar[count].z_lidar = range * sin(vertical_angle);

						// sensor frame coordinates
						converted_lidar[count].x_sensor = -converted_lidar[count].x_lidar;
						converted_lidar[count].y_sensor = -converted_lidar[count].y_lidar;
						converted_lidar[count].z_sensor = converted_lidar[count].z_lidar + 36.18/1000;

						converted_lidar[count].time = it->azimuth_block[i].timestamp;
						converted_lidar[count].measurement_id = it->azimuth_block[i].measurement_id;
						converted_lidar[count].frame_id = it->azimuth_block[i].frame_id;
						converted_lidar[count].horizontal_angle = horizontal_angle * 180/PI;
						converted_lidar[count].vertical_angle = vertical_angle * 180/PI;
						converted_lidar[count].range = range;
						converted_lidar[count].intensity = it->azimuth_block[i].data_block[j].intensity;
						converted_lidar[count].reflectance = it->azimuth_block[i].data_block[j].reflectance;
						converted_lidar[count].ambient_light = it->azimuth_block[i].data_block[j].ambient_light;

						count++;
					}	
				}
			}
		}
	}

	converted_lidar.resize(count);
}


void OusterPCAP::SaveChunk(int chunk_num, std::string pcap_file) {

	// Modify pcap file name for output file
	pcap_file.replace(pcap_file.find_last_of("."), std::string::npos, "_" + std::to_string(chunk_num) + ".las");

	pdal::PointTable table;
	pdal::BufferReader bufferReader;

	table.layout()->registerDims({	pdal::Dimension::Id::GpsTime,
									pdal::Dimension::Id::X,
									pdal::Dimension::Id::Y,
									pdal::Dimension::Id::Z,
									pdal::Dimension::Id::Intensity,
									pdal::Dimension::Id::PointSourceId,
									pdal::Dimension::Id::Red,
									pdal::Dimension::Id::Green,
									pdal::Dimension::Id::Blue});

	pdal::PointViewPtr view(new pdal::PointView(table));
	for (auto i = 0; i < converted_lidar.size(); i++) {
		//std::cout << converted_lidar[i].x_lidar << ", " << converted_lidar[i].y_lidar << ", " << converted_lidar[i].z_lidar << std::endl;
		view->setField(pdal::Dimension::Id::GpsTime, i, converted_lidar[i].time);
		view->setField(pdal::Dimension::Id::X, i, converted_lidar[i].x_lidar);
		view->setField(pdal::Dimension::Id::Y, i, converted_lidar[i].y_lidar);
		view->setField(pdal::Dimension::Id::Z, i, converted_lidar[i].z_lidar);
		view->setField(pdal::Dimension::Id::Intensity, i, converted_lidar[i].intensity);
		view->setField(pdal::Dimension::Id::PointSourceId, i, converted_lidar[i].measurement_id);
		view->setField(pdal::Dimension::Id::Red, i, converted_lidar[i].frame_id);
		view->setField(pdal::Dimension::Id::Green, i, converted_lidar[i].reflectance);
		view->setField(pdal::Dimension::Id::Blue, i, converted_lidar[i].ambient_light);
	}
	bufferReader.addView(view);
	pdal::Options writerOptions;
	writerOptions.add("filename", pcap_file);

	pdal::LasWriter writer;
	writer.setOptions(writerOptions);
	writer.setInput(bufferReader);
	writer.prepare(table);
	writer.execute(table);
}
#pragma comment(lib,"dnsapi.lib")
#pragma comment(lib,"ws2_32.lib") 
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <windns.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <future> // For std::async and std::future
#include <iostream>

bool query_dns(const char* dns_server, const char* nodename, PDNS_RECORD* query_result) {
	IP4_ARRAY srvlist = { 0 };

	if (1 != InetPton(AF_INET,
		dns_server, // dns server ip
		&srvlist.AddrArray[0])) {

		std::cerr << "InetPton failed, GLE = " << GetLastError() << std::endl;
		return false;
	}

	srvlist.AddrCount = 1;

	DNS_STATUS dns_status = DnsQuery(nodename,
		DNS_TYPE_A, //DNS_TYPE_AAAA,
		DNS_QUERY_WIRE_ONLY,
		&srvlist,
		query_result,
		nullptr); // Reserved

	if (0 != dns_status) {
		std::cerr << "DnsQuery failed returned " << dns_status << " GLE = " << GetLastError() << std::endl;
		return false;

	}

	return true;
}

bool getaddrinfo_check(const char* nodename)
{
	// Setup the hints address info structure
	struct addrinfo hints;
	SecureZeroMemory(&hints, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo* result = nullptr;
	const int ret_val = getaddrinfo(nodename, nullptr, &hints, &result);
	if (ret_val != 0) {
		std::cerr << "getaddrinfo failed with error: " << ret_val << std::endl;
		return false;
	}

	int index = 0;
	char ipaddr[INET6_ADDRSTRLEN]; // Large enough for IPv4 or IPv6

	for (auto ptr = result; ptr; ptr = ptr->ai_next) {
		index++;
		std::cout << "Record #" << index << std::endl;

		switch (ptr->ai_family)
		{
		case AF_INET:
		{
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)ptr->ai_addr;
			if (InetNtop(AF_INET, &ipv4->sin_addr, ipaddr, sizeof(ipaddr))) {
				std::cout << "IPv4 address: " << ipaddr << std::endl;
			}
			else {
				std::cerr << "InetNtop failed: " << GetLastError() << std::endl;
			}
		}
		break;
		case AF_INET6:
		{
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)ptr->ai_addr;
			if (InetNtop(AF_INET6, &ipv6->sin6_addr, ipaddr, sizeof(ipaddr))) {
				std::cout << "IPv6 address: " << ipaddr << std::endl;
			}
			else {
				std::cerr << "InetNtop failed: " << GetLastError() << std::endl;
			}
		}
		break;
		default:
			std::cout << "Unknown address family: " << ptr->ai_family << std::endl;
			break;
		}
	}

	freeaddrinfo(result);

	return true;
}

int main(int argc, char** argv)
{
	WSADATA wsaData;
	// Initialize Winsock
	const int error_code = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (error_code != 0) {
		std::cerr << "WSAStartup failed: " << error_code << std::endl;
		return -1;
	}

	PDNS_RECORD query_result = nullptr;
	char ipaddr[INET6_ADDRSTRLEN]; // Large enough for IPv4 or IPv6

	if (argc != 3)
	{
		std::cout << "Usage: " << argv[0] << " hostname dns server" << std::endl;
		std::cout << "Example: " << argv[0] << " google.com 176.103.130.134" << std::endl;
		WSACleanup();
		return -3;
	}


	// Query using getaddrinfo
	auto os_dns_query = std::async(std::launch::async, getaddrinfo_check, argv[1]);
	auto dns_query_custom = std::async(std::launch::async, query_dns, argv[2], argv[1], &query_result);
	std::cout << "Performing getaddrinfo for host: " << argv[1] << std::endl;
	os_dns_query.get();

	std::cout << "Querying host: " << argv[1] << " from DNS server: " << argv[2] << std::endl;
	if (true == dns_query_custom.get()) {
		if (query_result) {
			int index = 0;
			for (auto p = query_result; p; p = p->pNext) {
				index++;
				std::cout << "Record #" << index << std::endl;

				switch (p->wType)
				{
				case DNS_TYPE_A:
				{
					if (InetNtop(AF_INET, &p->Data.A.IpAddress, ipaddr, sizeof(ipaddr))) {
						std::cout << "IPv4 address: " << ipaddr << std::endl;
						std::cout << "TTL: " << p->dwTtl << " (secs)" << std::endl;
					}
					else {
						std::cerr << "InetNtop failed: " << GetLastError() << std::endl;
					}
				}
				break;
				case DNS_TYPE_AAAA:
				{
					if (InetNtop(AF_INET6, &p->Data.AAAA.Ip6Address, ipaddr, sizeof(ipaddr))) {
						std::cout << "IPv6 address: " << ipaddr << std::endl;
						std::cout << "TTL: " << p->dwTtl << " (secs)" << std::endl;
					}
					else {
						std::cerr << "InetNtop failed: " << GetLastError() << std::endl;
					}
				}
				break;
				default:
					std::cout << "Skipping non-A record (type: " << p->wType << ")" << std::endl;
					continue; // Skip TTL for non-A records
				}


			}
			DnsRecordListFree(query_result, DnsFreeRecordList);
		}
		else {
			std::cout << "No records returned" << std::endl;
		}
	}

	WSACleanup();
	return 0;
}
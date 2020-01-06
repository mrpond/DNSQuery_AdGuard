#pragma comment(lib,"dnsapi.lib")
#pragma comment(lib,"ws2_32.lib") 
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <windns.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include "stdio.h"

bool adguard_dnsblock (const char* nodename) {
	DNS_STATUS dnsStatus;
	PDNS_RECORD QueryResult;
	PIP4_ARRAY pSrvList = NULL;
	bool isBlock = false;
	char resolvedIP[INET6_ADDRSTRLEN]{};
	pSrvList = (PIP4_ARRAY)LocalAlloc (LPTR, sizeof (IP4_ARRAY));

	if (pSrvList) {
		printf ("pSrvList Alloc success\n");
		if (1 == InetPton (AF_INET,
							"176.103.130.134", // dns server ip
							&pSrvList->AddrArray[0])) {
			// "Family protection"
			// adguard.com/en/adguard-dns/overview.html 
			pSrvList->AddrCount = 1;
			printf ("InetPton success \n");
			dnsStatus = DnsQuery (nodename,
									DNS_TYPE_A,
									DNS_QUERY_WIRE_ONLY,
									pSrvList,
									&QueryResult,
									NULL); // Reserved
			if (0 == dnsStatus) {
				printf ("dnsStatus == 0 success\n");
				if (QueryResult) {
					printf ("QueryResult\n");
					for (auto p = QueryResult; p; p = p->pNext) {
						// 0.0.0.0
						InetNtop (AF_INET,
								   &p->Data.A.IpAddress,
								   resolvedIP,
								   sizeof (resolvedIP));
						if (_stricmp (resolvedIP, "0.0.0.0") == 0)
							isBlock = true; // AdGuard Block		
						//printf ("isBlock\n");
					}
					DnsRecordListFree (QueryResult, DnsFreeRecordList);
					printf ("DnsRecordListFree\n");
				} // QueryResult
			} // dnsStatus
		} // inet_pton

		LocalFree (pSrvList);
	} // pSrvList
	return isBlock;
}

bool getaddrinfo_check (const char* nodename) {
	WSADATA wsaData;
	int iResult;
	DWORD dwRetval;

	struct addrinfo* result = NULL;
	//struct addrinfo* ptr = NULL;
	struct addrinfo hints;

	// Initialize Winsock
	iResult = WSAStartup (MAKEWORD (2, 2), &wsaData);
	if (iResult != 0) {
		printf ("WSAStartup failed: %d\n", iResult);
		return false;
	}

	// Setup the hints address info structure
	SecureZeroMemory (&hints, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;


	dwRetval = getaddrinfo (nodename, nullptr, &hints, &result);
	if (dwRetval != 0) {
		printf ("getaddrinfo failed with error: %d\n", dwRetval);
		WSACleanup ();
		return 1;
	}

	printf ("getaddrinfo returned success\n");

	struct addrinfo *ptr = result;
	int i = 1;


	char ipaddr2[INET6_ADDRSTRLEN];


	while (ptr) {
		printf ("getaddrinfo response %d\n", i++);
		printf ("\tFlags: 0x%x\n", ptr->ai_flags);
		printf ("\tIP Addr: ");
		struct sockaddr_in* ipv4 = (struct sockaddr_in*)ptr->ai_addr;
		InetNtop (ptr->ai_family, &(ipv4->sin_addr), ipaddr2, sizeof (ipaddr2));
		printf ("\tIPv4 address %s\n", ipaddr2);
		printf ("\tTest change\n");
		InetPton (AF_INET, "0.0.0.0", &(ipv4->sin_addr));

		InetNtop (ptr->ai_family, &(ipv4->sin_addr), ipaddr2, sizeof (ipaddr2));
		printf ("\tIPv4 address %s\n", ipaddr2);
		printf ("\tSocket type: ");
		switch (ptr->ai_socktype) {
		case 0:
			printf ("Unspecified\n");
			break;
		case SOCK_STREAM:
			printf ("SOCK_STREAM (stream)\n");
			break;
		case SOCK_DGRAM:
			printf ("SOCK_DGRAM (datagram) \n");
			break;
		case SOCK_RAW:
			printf ("SOCK_RAW (raw) \n");
			break;
		case SOCK_RDM:
			printf ("SOCK_RDM (reliable message datagram)\n");
			break;
		case SOCK_SEQPACKET:
			printf ("SOCK_SEQPACKET (pseudo-stream packet)\n");
			break;
		default:
			printf ("Other %ld\n", ptr->ai_socktype);
			break;
		}
		printf ("\tProtocol: ");
		switch (ptr->ai_protocol) {
		case 0:
			printf ("Unspecified\n");
			break;
		case IPPROTO_TCP:
			printf ("IPPROTO_TCP (TCP)\n");
			break;
		case IPPROTO_UDP:
			printf ("IPPROTO_UDP (UDP) \n");
			break;
		default:
			printf ("Other %ld\n", ptr->ai_protocol);
			break;
		}
		printf ("\tLength of this sockaddr: %d\n", ptr->ai_addrlen);
		printf ("\tCanonical name: %s\n", ptr->ai_canonname);

		ptr = ptr->ai_next;
	}


	freeaddrinfo (result);
	WSACleanup ();
	return true;
}

int main (int argc, char** argv)
{
	DNS_STATUS dnsStatus;
	PDNS_RECORD ppQueryResultsSet, p;
	PIP4_ARRAY pSrvList = NULL;
	int iRecord = 0;
	const char* dns_server = "176.103.130.134"; // "Family protection"
	if (argc != 2)
	{
		printf ("Usage: %s hostname\n\n", argv[0]);
		return -2;
	}

	printf ("Querying for host: %s\n", argv[1]);

	if (argc == 2) // Get the IP address of the DNS server to query
	{
		pSrvList = (PIP4_ARRAY)LocalAlloc (LPTR, sizeof (IP4_ARRAY));
		if (!pSrvList)
		{
			printf ("PIP4_ARRAY allocation failed \n");
			return -3;
		}

		
		InetPton (AF_INET, "176.103.130.134", &pSrvList->AddrArray[0]);
		pSrvList->AddrCount = 1;

		printf ("Querying DNS Server: 176.103.130.134\n");
	}

	dnsStatus = DnsQuery (argv[1],
		DNS_TYPE_A,
		DNS_QUERY_DNSSEC_OK,
		pSrvList, // Documented as reserved, but can take a PIP4_ARRAY for the DNS server
		&ppQueryResultsSet,
		NULL); // Reserved

	if (dnsStatus)
	{

		printf ("\nDNSQuery failed and returned %d, GLE = %d\n\n", dnsStatus, GetLastError ());
		return -1;
	}

	p = ppQueryResultsSet;

	while (p) // Loop through the returned addresses
	{

		iRecord++;
		printf ("\nRecord #%d\n", iRecord);
		char ipaddr2[INET6_ADDRSTRLEN];
		InetNtop (AF_INET, &p->Data.A.IpAddress, ipaddr2, sizeof (ipaddr2));
		printf ("The IP address of %s is %s \n", p->pName, ipaddr2);
		//printf ("Type %d Host %s \n", p->wType, &p->Data.CNAME.pNameHost);;
		printf ("TTL: %d (secs)\n", p->dwTtl);

		p = p->pNext;
	}

	if (pSrvList) LocalFree (pSrvList);

	DnsRecordListFree (ppQueryResultsSet, DnsFreeRecordList);

	getaddrinfo_check (argv[1]);

	if (adguard_dnsblock (argv[1])) {
		printf ("Blocked\n");
	}
}
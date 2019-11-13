#pragma comment(lib,"dnsapi.lib")
#pragma comment(lib,"ws2_32.lib") 
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <windns.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include "stdio.h"


int wmain (int argc, WCHAR** argv)
{
	DNS_STATUS dnsStatus;
	PDNS_RECORD ppQueryResultsSet, p;
	PIP4_ARRAY pSrvList = NULL;
	int iRecord = 0;
	const char* dns_server = "176.103.130.134"; // "Family protection"
	if (argc != 2)
	{
		wprintf (L"Usage: %s hostname\n\n", argv[0]);
		return -2;
	}

	wprintf (L"Querying for host: %s\n", argv[1]);

	if (argc == 2) // Get the IP address of the DNS server to query
	{
		pSrvList = (PIP4_ARRAY)LocalAlloc (LPTR, sizeof (IP4_ARRAY));
		if (!pSrvList)
		{
			wprintf (L"PIP4_ARRAY allocation failed \n");
			return -3;
		}

		
		inet_pton (AF_INET, "176.103.130.134", &pSrvList->AddrArray[0]);
		pSrvList->AddrCount = 1;

		wprintf (L"Querying DNS Server: 176.103.130.134\n");
	}

	dnsStatus = DnsQuery (argv[1],
		DNS_TYPE_A,
		DNS_QUERY_WIRE_ONLY,
		pSrvList, // Documented as reserved, but can take a PIP4_ARRAY for the DNS server
		&ppQueryResultsSet,
		NULL); // Reserved

	if (dnsStatus)
	{

		wprintf (L"\nDNSQuery failed and returned %d, GLE = %d\n\n", dnsStatus, GetLastError ());
		return -1;
	}

	p = ppQueryResultsSet;

	while (p) // Loop through the returned addresses
	{

		iRecord++;
		wprintf (L"\nRecord #%d\n", iRecord);
		char ipaddr2[INET6_ADDRSTRLEN];
		inet_ntop (AF_INET, &p->Data.A.IpAddress, ipaddr2, sizeof (ipaddr2));
		wprintf (L"The IP address of %s is %S \n", p->pName, ipaddr2);
		wprintf (L"TTL: %d (secs)\n", p->dwTtl);

		p = p->pNext;
	}

	if (pSrvList) LocalFree (pSrvList);

	DnsRecordListFree (ppQueryResultsSet, DnsFreeRecordList);

}
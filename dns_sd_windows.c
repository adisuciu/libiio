// Based on the example provided here: https://github.com/mjansson/mdns

#ifdef _WIN32
#  define _CRT_SECURE_NO_WARNINGS 1
#endif

#include <stdio.h>
#include <errno.h>
#include "iio-private.h"
#include "mdns.h"
#include "network.h"
#include "debug.h"

#ifdef _WIN32
#  include <iphlpapi.h>
#else
#  include <netdb.h>
#endif


static mdns_string_t
ipv6_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in6* addr,
	size_t addrlen) {
	char host[NI_MAXHOST] = { 0 };
	char service[NI_MAXSERV] = { 0 };
	int ret = getnameinfo((const struct sockaddr*)addr, addrlen, host, NI_MAXHOST, service,
		NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	if (ret == 0) {
		if (addr->sin6_port != 0)
			len = snprintf(buffer, capacity, "[%s]:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= (int)capacity)
		len = (int)capacity - 1;
	mdns_string_t str = { buffer, len };
	return str;
}

static mdns_string_t
ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr,
	size_t addrlen) {
	char host[NI_MAXHOST] = { 0 };
	char service[NI_MAXSERV] = { 0 };
	int ret = getnameinfo((const struct sockaddr*)addr, addrlen, host, NI_MAXHOST, service,
		NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	if (ret == 0) {
		if (addr->sin_port != 0)
			len = snprintf(buffer, capacity, "%s:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= (int)capacity)
		len = (int)capacity - 1;
	mdns_string_t str = { buffer, len };
	return str;
}

static int new_discovery_data(struct dns_sd_discovery_data** data)
{
	struct dns_sd_discovery_data* d;

	d = zalloc(sizeof(struct dns_sd_discovery_data));
	if (!d)
		return -ENOMEM;

	*data = d;
	return 0;
}

void dnssd_free_discovery_data(struct dns_sd_discovery_data* d)
{
	free(d->hostname);
	free(d);
}

static int
open_client_sockets(int* sockets, int max_sockets) {
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family
	int num_sockets = 0;

#ifdef _WIN32
	IP_ADAPTER_ADDRESSES* adapter_address = 0;
	unsigned int address_size = 8000;
	unsigned int ret;
	unsigned int num_retries = 4;
	do {
		adapter_address = malloc(address_size);
		ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0,
			adapter_address, &address_size);
		if (ret == ERROR_BUFFER_OVERFLOW) {
			free(adapter_address);
			adapter_address = 0;
		}
		else {
			break;
		}
	} while (num_retries-- > 0);

	if (!adapter_address || (ret != NO_ERROR)) {
		free(adapter_address);
		IIO_ERROR("Failed to get network adapter addresses\n");
		return num_sockets;
	}

	/*int first_ipv4 = 1;
	int first_ipv6 = 1;*/
	for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
		if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
			continue;
		if (adapter->OperStatus != IfOperStatusUp)
			continue;

		for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast;
			unicast = unicast->Next) {
			if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
				struct sockaddr_in* saddr = (struct sockaddr_in*)unicast->Address.lpSockaddr;
				if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) ||
					(saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
					(saddr->sin_addr.S_un.S_un_b.s_b3 != 0) ||
					(saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
					/*if (first_ipv4) {
						service_address_ipv4 = saddr->sin_addr.S_un.S_addr;
						first_ipv4 = 0;
					}*/
					if (num_sockets < max_sockets) {
						int sock = mdns_socket_open_ipv4(saddr);
						if (sock >= 0) {
							char buffer[128];
							mdns_string_t addr = ipv4_address_to_string(
								buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
							IIO_DEBUG("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
							sockets[num_sockets++] = sock;
						}
					}
				}
			}
			else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
				struct sockaddr_in6* saddr = (struct sockaddr_in6*)unicast->Address.lpSockaddr;
				static const unsigned char localhost[] = { 0, 0, 0, 0, 0, 0, 0, 0,
														  0, 0, 0, 0, 0, 0, 0, 1 };
				static const unsigned char localhost_mapped[] = { 0, 0, 0,    0,    0,    0, 0, 0,
																 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1 };
				if ((unicast->DadState == NldsPreferred) &&
					memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
					memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
					/*if (first_ipv6) {
						memcpy(service_address_ipv6, &saddr->sin6_addr, 16);
						first_ipv6 = 0;
					}*/
					if (num_sockets < max_sockets) {
						int sock = mdns_socket_open_ipv6(saddr);
						if (sock >= 0) {
							char buffer[128];
							mdns_string_t addr = ipv6_address_to_string(
								buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in6));
							printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
							sockets[num_sockets++] = sock;
						}
					}
				}
			}
		}
	}

	free(adapter_address);
#endif

	for (int isock = 0; isock < num_sockets; ++isock) {
#ifdef _WIN32
		unsigned long param = 1;
		ioctlsocket(sockets[isock], FIONBIO, &param);
#else
		const int flags = fcntl(sockets[isock], F_GETFL, 0);
		fcntl(sockets[isock], F_SETFL, flags | O_NONBLOCK);
#endif
	}

	return num_sockets;
}


static int
query_callback(int sock, const struct sockaddr* from, size_t addrlen,
	mdns_entry_type_t entry, uint16_t transaction_id,
	uint16_t rtype, uint16_t rclass, uint32_t ttl,
	const void* data, size_t size, size_t offset, size_t length,
	void* user_data) {


	char addrbuffer[64];
	char servicebuffer[64];
	char namebuffer[256];

	struct dns_sd_discovery_data* dd = (struct dns_sd_discovery_data*)user_data;
	if (dd == NULL) {
		IIO_ERROR("DNS SD: Missing info structure. Stop browsing.\n");
		goto quit;
	}

	if (rtype != MDNS_RECORDTYPE_SRV)
		goto quit;

	getnameinfo((const struct sockaddr*)from, addrlen,
		addrbuffer, NI_MAXHOST, servicebuffer, NI_MAXSERV,
		NI_NUMERICSERV | NI_NUMERICHOST);

	mdns_record_srv_t srv = mdns_record_parse_srv(data, size, offset, length,
		namebuffer, sizeof(namebuffer));
	IIO_DEBUG("%s : SRV %.*s priority %d weight %d port %d\n",
		addrbuffer,
		MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);

	// Go to the last element in the list
	while (dd->next != NULL)
		dd = dd->next;

	if (srv.name.length > 1)
	{
		dd->hostname = malloc(srv.name.length);
		strncpy(dd->hostname, srv.name.str, srv.name.length);
		dd->hostname[srv.name.length - 1] = 0;
	}
	strcpy(dd->addr_str, addrbuffer);
	dd->port = srv.port;

	IIO_DEBUG("DNS SD: added %s (%s:%d)\n", dd->hostname, dd->addr_str, dd->port);
	// A list entry was filled, prepare new item on the list.
	if (new_discovery_data(&dd->next)) {
		IIO_ERROR("DNS SD mDNS Resolver : memory failure\n");
	}

quit:
	return 0;
}

int dnssd_find_hosts(struct dns_sd_discovery_data** ddata)
{
#ifdef _WIN32
	const char* hostname = "dummy-host";
	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	if (WSAStartup(versionWanted, &wsaData)) {
		printf("Failed to initialize WinSock\n");
		return -1;
	}

	char hostname_buffer[128];
	DWORD hostname_size = (DWORD)sizeof(hostname_buffer);
	if (GetComputerNameA(hostname_buffer, &hostname_size))
		hostname = hostname_buffer;
#endif

	int ret = 0;
	struct dns_sd_discovery_data* d;

	IIO_DEBUG("DNS SD: Start service discovery.\n");

	if (new_discovery_data(&d) < 0) {
		return -ENOMEM;
	}
	*ddata = d;

	size_t capacity = 2048;
	void* buffer = malloc(capacity);
	const char service[] = "_iio._tcp.local.";
	size_t records;

	IIO_DEBUG("Sending DNS-SD discovery\n");

	int port = 5353;
	int sockets[32];
	int transaction_id[32];
	int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
	if (num_sockets <= 0) {
		IIO_ERROR("Failed to open any client sockets\n");
		return -1;
	}
	IIO_DEBUG("Opened %d socket%s for mDNS query\n", num_sockets, num_sockets ? "s" : "");

	IIO_DEBUG("Sending mDNS query: %s\n", service);
	for (int isock = 0; isock < num_sockets; ++isock) {
		transaction_id[isock] = mdns_query_send(sockets[isock], MDNS_RECORDTYPE_PTR, service, strlen(service), buffer,
			capacity);
		if (transaction_id[isock] <= 0)
			IIO_ERROR("Failed to send mDNS query: %s\n", strerror(errno));
	}

	// This is a simple implementation that loops for 10 seconds or as long as we get replies
	// A real world implementation would probably use select, poll or similar syscall to wait
	// until data is available on a socket and then read it
	IIO_DEBUG("Reading mDNS query replies\n");
	for (int i = 0; i < 10; ++i) {
		size_t records;
		do {
			records = 0;
			for (int isock = 0; isock < num_sockets; ++isock) {
				if (transaction_id[isock] > 0)
				records +=
					mdns_query_recv(sockets[isock], buffer, capacity, query_callback, d, transaction_id[isock]);
			}
		} while (records);
		if (records)
			i = 0;
		Sleep(100);
	}

quit:
	free(buffer);
	for (int isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	IIO_DEBUG("Closed socket%s\n", num_sockets ? "s" : "");

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}

//////////////////////////////////////////////////////////////////////
// RasVpn.cpp : per-session L2TP/IPsec(PSK) VPN via the Windows RAS stack
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include <iphlpapi.h>
#include "RasVpn.h"

#pragma comment(lib, "rasapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

const TCHAR CRasVpn::ENTRY_PREFIX[] = _T("RLoginTmp_");

//////////////////////////////////////////////////////////////////////

CRasVpn::CRasVpn()
{
	m_hConn    = NULL;
	m_ifIndex4 = 0;
	m_ifIndex6 = 0;
	m_refCount = 0;
}

CRasVpn::~CRasVpn()
{
	HangUp();
}

CString CRasVpn::FormatRasError(DWORD code)
{
	CString str;
	TCHAR buf[512];

	if ( RasGetErrorString((UINT)code, buf, _countof(buf)) == ERROR_SUCCESS )
		str.Format(_T("%s (RAS %u)"), buf, code);
	else
		str.Format(_T("RAS error %u"), code);

	return str;
}

//////////////////////////////////////////////////////////////////////
// Create the ephemeral phonebook entry + set the pre-shared key

BOOL CRasVpn::SetupEntry(LPCTSTR server, LPCTSTR psk, int strategy, CString &errMsg)
{
	DWORD rc;

	// Build a unique, non-persistent entry name for this session.
	static LONG s_seq = 0;
	LONG seq = ::InterlockedIncrement(&s_seq);
	m_entryName.Format(_T("%s%u_%ld"), ENTRY_PREFIX, ::GetCurrentProcessId(), seq);

	RASENTRY entry;
	ZeroMemory(&entry, sizeof(entry));
	entry.dwSize = sizeof(RASENTRY);

	entry.dwfOptions       = RASEO_IpHeaderCompression | RASEO_SwCompression;
	// NOTE: RASEO_RemoteDefaultGateway is intentionally NOT set -> split
	// tunnel. The VPN must not become the default route; only the bound
	// socket (IP_UNICAST_IF) goes through it.

	entry.dwType           = RASET_Vpn;
	switch ( strategy ) {
	case 1:  entry.dwVpnStrategy = VS_L2tpOnly;  break;
	case 2:  entry.dwVpnStrategy = VS_Ikev2Only; break;
	case 3:  entry.dwVpnStrategy = VS_SstpOnly;  break;
	case 4:  entry.dwVpnStrategy = VS_PptpOnly;  break;
	default: entry.dwVpnStrategy = VS_Default;   break;
	}
	entry.dwEncryptionType = ET_Require;			// IPsec always encrypts
	entry.dwFramingProtocol = RASFP_Ppp;
	entry.dwfNetProtocols  = RASNP_Ip | RASNP_Ipv6;

	_tcsncpy_s(entry.szLocalPhoneNumber, _countof(entry.szLocalPhoneNumber),
			   server, _TRUNCATE);					// VPN server host / IP
	_tcsncpy_s(entry.szDeviceType, _countof(entry.szDeviceType),
			   RASDT_Vpn, _TRUNCATE);
	_tcsncpy_s(entry.szDeviceName, _countof(entry.szDeviceName),
			   _T("WAN Miniport (L2TP)"), _TRUNCATE);

	// Creates the entry if it does not exist (it never does - unique name).
	if ( (rc = RasSetEntryProperties(NULL, m_entryName, &entry, sizeof(entry), NULL, 0)) != ERROR_SUCCESS ) {
		errMsg.Format(_T("RasSetEntryProperties failed: %s"), (LPCTSTR)FormatRasError(rc));
		m_entryName.Empty();
		return FALSE;
	}

	// Store the IPsec pre-shared key for this entry.
	// CAUTION: writing the PSK goes through the LSA secret store and may
	// require administrator rights (see IMPLEMENTATION_NOTES.md).
	if ( psk != NULL && psk[0] != _T('\0') && (strategy == 0 || strategy == 1 || strategy == 2) ) {
		RASCREDENTIALS cred;
		ZeroMemory(&cred, sizeof(cred));
		cred.dwSize = sizeof(RASCREDENTIALS);
		cred.dwMask = RASCM_PreSharedKey;
		_tcsncpy_s(cred.szPassword, _countof(cred.szPassword), psk, _TRUNCATE);

		if ( (rc = RasSetCredentials(NULL, m_entryName, &cred, FALSE)) != ERROR_SUCCESS ) {
			SecureZeroMemory(&cred, sizeof(cred));
			errMsg.Format(_T("RasSetCredentials(PSK) failed: %s\n")
						  _T("(setting the pre-shared key may require running as administrator)"),
						  (LPCTSTR)FormatRasError(rc));
			RasDeleteEntry(NULL, m_entryName);
			m_entryName.Empty();
			return FALSE;
		}
		SecureZeroMemory(&cred, sizeof(cred));
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////

BOOL CRasVpn::Dial(LPCTSTR server, LPCTSTR user, LPCTSTR pass, LPCTSTR psk, int strategy,
				   DWORD &ifIndex4, DWORD &ifIndex6, CString &errMsg)
{
	DWORD rc;

	ifIndex4 = ifIndex6 = 0;

	if ( m_hConn != NULL ) {		// already up (shared tunnel)
		ifIndex4 = m_ifIndex4;
		ifIndex6 = m_ifIndex6;
		return TRUE;
	}

	if ( server == NULL || server[0] == _T('\0') ) {
		errMsg = _T("VPN server is empty");
		return FALSE;
	}

	if ( !SetupEntry(server, psk, strategy, errMsg) )
		return FALSE;

	RASDIALPARAMS dp;
	ZeroMemory(&dp, sizeof(dp));
	dp.dwSize = sizeof(RASDIALPARAMS);
	_tcsncpy_s(dp.szEntryName, _countof(dp.szEntryName), m_entryName, _TRUNCATE);
	if ( user != NULL )
		_tcsncpy_s(dp.szUserName, _countof(dp.szUserName), user, _TRUNCATE);
	if ( pass != NULL )
		_tcsncpy_s(dp.szPassword, _countof(dp.szPassword), pass, _TRUNCATE);

	// Blocking dial: with a NULL notifier RasDial does not return until the
	// connection is established or fails.
	rc = RasDial(NULL, NULL, &dp, 0, NULL, &m_hConn);
	SecureZeroMemory(&dp, sizeof(dp));

	if ( rc != ERROR_SUCCESS ) {
		errMsg.Format(_T("RasDial failed: %s"), (LPCTSTR)FormatRasError(rc));
		HangUp();				// drops half-open conn + deletes the entry
		return FALSE;
	}

	// Confirm we really reached the connected state.
	RASCONNSTATUS st;
	ZeroMemory(&st, sizeof(st));
	st.dwSize = sizeof(RASCONNSTATUS);
	if ( RasGetConnectStatus(m_hConn, &st) != ERROR_SUCCESS || st.rasconnstate != RASCS_Connected ) {
		errMsg.Format(_T("VPN did not reach connected state (dwError=%u)"), st.dwError);
		HangUp();
		return FALSE;
	}

	if ( !ResolveIfIndex(m_ifIndex4, m_ifIndex6) ) {
		errMsg = _T("connected, but could not resolve VPN adapter interface index");
		HangUp();
		return FALSE;
	}

	ifIndex4 = m_ifIndex4;
	ifIndex6 = m_ifIndex6;
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// Map the tunnel's assigned PPP IP to its adapter interface index.

BOOL CRasVpn::ResolveIfIndex(DWORD &ifIndex4, DWORD &ifIndex6)
{
	ifIndex4 = ifIndex6 = 0;

	// Local IP assigned to the PPP/L2TP adapter.
	RASPPPIP ip;
	ZeroMemory(&ip, sizeof(ip));
	ip.dwSize = sizeof(RASPPPIP);
	DWORD sz = sizeof(ip);
	if ( RasGetProjectionInfo(m_hConn, RASP_PppIp, &ip, &sz) != ERROR_SUCCESS )
		return FALSE;

	// ip.szIpAddress is the tunnel-local IPv4 address as text.
	IN_ADDR want;
	if ( InetPton(AF_INET, ip.szIpAddress, &want) != 1 )
		return FALSE;

	// Walk the adapter list and find the one carrying that address.
	ULONG bufLen = 16 * 1024;
	IP_ADAPTER_ADDRESSES *pAddrs = (IP_ADAPTER_ADDRESSES *)malloc(bufLen);
	if ( pAddrs == NULL )
		return FALSE;

	ULONG flags = GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST;
	ULONG ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddrs, &bufLen);
	if ( ret == ERROR_BUFFER_OVERFLOW ) {
		free(pAddrs);
		if ( (pAddrs = (IP_ADAPTER_ADDRESSES *)malloc(bufLen)) == NULL )
			return FALSE;
		ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddrs, &bufLen);
	}

	BOOL found = FALSE;
	if ( ret == ERROR_SUCCESS ) {
		for ( IP_ADAPTER_ADDRESSES *a = pAddrs ; a != NULL && !found ; a = a->Next ) {
			for ( IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress ; u != NULL ; u = u->Next ) {
				if ( u->Address.lpSockaddr->sa_family != AF_INET )
					continue;
				sockaddr_in *si = (sockaddr_in *)u->Address.lpSockaddr;
				if ( si->sin_addr.S_un.S_addr == want.S_un.S_addr ) {
					ifIndex4 = a->IfIndex;			// IPv4 index (host order)
					ifIndex6 = a->Ipv6IfIndex;		// IPv6 index, best effort
					found = TRUE;
					break;
				}
			}
		}
	}

	free(pAddrs);
	return found && ifIndex4 != 0;
}

//////////////////////////////////////////////////////////////////////

void CRasVpn::HangUp()
{
	if ( m_hConn != NULL ) {
		RasHangUp(m_hConn);

		// RasHangUp returns immediately; wait briefly for teardown so the
		// entry can be deleted cleanly.
		RASCONNSTATUS st;
		st.dwSize = sizeof(RASCONNSTATUS);
		for ( int i = 0 ; i < 30 ; i++ ) {
			if ( RasGetConnectStatus(m_hConn, &st) == ERROR_INVALID_HANDLE )
				break;
			Sleep(100);
		}
		m_hConn = NULL;
	}

	if ( !m_entryName.IsEmpty() ) {
		RasDeleteEntry(NULL, m_entryName);			// leave no trace in Windows
		m_entryName.Empty();
	}

	m_ifIndex4 = m_ifIndex6 = 0;
}

//////////////////////////////////////////////////////////////////////
// Remove ephemeral entries left behind by a previous crashed run.

void CRasVpn::CleanupOrphans()
{
	DWORD cb = sizeof(RASENTRYNAME);
	DWORD num = 0;
	RASENTRYNAME one;
	one.dwSize = sizeof(RASENTRYNAME);

	// First call just to size the buffer.
	DWORD rc = RasEnumEntries(NULL, NULL, &one, &cb, &num);
	if ( rc == ERROR_SUCCESS ) {
		// Only one (or zero) entries fit; handle the single case below.
		if ( num == 1 && _tcsncmp(one.szEntryName, ENTRY_PREFIX, _tcslen(ENTRY_PREFIX)) == 0 )
			RasDeleteEntry(NULL, one.szEntryName);
		return;
	}
	if ( rc != ERROR_BUFFER_TOO_SMALL || cb == 0 )
		return;

	RASENTRYNAME *list = (RASENTRYNAME *)malloc(cb);
	if ( list == NULL )
		return;
	list[0].dwSize = sizeof(RASENTRYNAME);

	if ( RasEnumEntries(NULL, NULL, list, &cb, &num) == ERROR_SUCCESS ) {
		size_t plen = _tcslen(ENTRY_PREFIX);
		for ( DWORD i = 0 ; i < num ; i++ ) {
			if ( _tcsncmp(list[i].szEntryName, ENTRY_PREFIX, plen) == 0 )
				RasDeleteEntry(NULL, list[i].szEntryName);
		}
	}

	free(list);
}

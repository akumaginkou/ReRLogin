//////////////////////////////////////////////////////////////////////
// RasVpn.h : per-session L2TP/IPsec(PSK) VPN via the Windows RAS stack
//
// Establishes an L2TP/IPsec tunnel for a single RLogin session using an
// *ephemeral* RAS phonebook entry (created on dial, deleted on hangup) so
// that nothing is left configured in Windows. The tunnel is brought up as
// a split tunnel (it does NOT steal the default gateway); per-session
// scoping is achieved by the caller binding only that session's socket to
// the VPN adapter via setsockopt(IP_UNICAST_IF) using the interface index
// returned here.
//
// See IMPLEMENTATION_NOTES.md for the full design and caveats (NAT-T,
// PSK/admin, DNS).
//////////////////////////////////////////////////////////////////////

#pragma once

#include <ras.h>
#include <raserror.h>

class CRasVpn
{
public:
	CRasVpn();
	~CRasVpn();

	// Bring up the L2TP/IPsec(PSK) tunnel. On success returns TRUE and fills
	// the interface indexes of the VPN adapter (ifIndex4 for IPv4 traffic in
	// host order, ifIndex6 for IPv6). Either index may be 0 if that family is
	// not present on the tunnel. On failure returns FALSE and sets errMsg.
	BOOL Dial(LPCTSTR server, LPCTSTR user, LPCTSTR pass, LPCTSTR psk, int strategy, int auth,
			  DWORD &ifIndex4, DWORD &ifIndex6, CString &errMsg);

	// Tear the tunnel down and delete the ephemeral phonebook entry.
	void HangUp();

	BOOL IsConnected() const { return m_hConn != NULL; }
	DWORD GetIfIndex4() const { return m_ifIndex4; }
	DWORD GetIfIndex6() const { return m_ifIndex6; }

	// Reference counting so several sessions can share one tunnel to the same
	// server. AddRef returns the new count; Release returns the remaining
	// count (caller hangs up + deletes when it reaches 0).
	int AddRef() { return ++m_refCount; }
	int Release() { return (m_refCount > 0 ? --m_refCount : 0); }
	int GetRefCount() const { return m_refCount; }
	LPCTSTR GetEntryName() const { return m_entryName; }

	// Delete any "RLoginTmp_*" ephemeral entries left over from a previous
	// run that crashed before HangUp(). Call once at application start.
	static void CleanupOrphans();

	static const TCHAR ENTRY_PREFIX[];	// "RLoginTmp_"

protected:
	BOOL SetupEntry(LPCTSTR server, LPCTSTR psk, int strategy, int auth, CString &errMsg);
	BOOL ResolveIfIndex(DWORD &ifIndex4, DWORD &ifIndex6);
	static CString FormatRasError(DWORD code);

	CString  m_entryName;	// "RLoginTmp_<n>" - the ephemeral entry
	HRASCONN m_hConn;		// the live connection handle (NULL = down)
	DWORD    m_ifIndex4;
	DWORD    m_ifIndex6;
	int      m_refCount;
};

//////////////////////////////////////////////////////////////////////
// VpnProvider.h : per-session VPN provider abstraction
//
// Replaces the direct CRasVpn usage in CRLoginDoc with a pluggable
// provider, so a per-session ephemeral ("throwaway") tunnel can be
// delivered by different back-ends:
//   - CVpnProviderRasCompat : existing Windows RAS L2TP/IPsec path
//                             (admin-required, IP_UNICAST_IF). Behaviour
//                             preserving wrapper of CRasVpn.
//   - CVpnProviderSsh       : SSH tunnel reusing Cssh::OpenTunnelSocket
//                             (non-admin). See VpnSsh.*.
//   - (future) userspace SSTP / IKEv2 / L2TP-IPsec over an lwIP netstack.
//
// A provider is created per session, brought up before the socket opens,
// and torn down on close. See the "ReRLogin per-session VPN replacement"
// design notes (overview / detail) kept in the Obsidian vault.
//
// Injection seam: CExtSocket::m_pVpnProvider is consulted by
// CExtSocket::FifoLinkLeft() (mirrors the existing m_pSshProxy branch).
//////////////////////////////////////////////////////////////////////

#pragma once

class CRLoginDoc;
class CExtSocket;
class CFifoBase;

enum EVpnKind {
	VPN_NONE      = 0,
	VPN_RAS_L2TP  = 1,	// Windows RAS L2TP/IPsec (admin compat, IP_UNICAST_IF)
	VPN_SSH       = 2,	// SSH tunnel (reuses Cssh::OpenTunnelSocket)
	VPN_L2TP_US   = 3,	// userspace L2TP/IPsec(PSK) (non-admin, VpnL2tpIpsec.*)
	// future: VPN_SSTP, VPN_IKEV2, VPN_SOCKS_TLS, VPN_MASQUE
};

class CVpnProvider
{
public:
	CVpnProvider();
	virtual ~CVpnProvider();

	virtual EVpnKind Kind() const = 0;

	// Bring the tunnel up. Settings are read from pDoc->m_ServerEntry.
	// Synchronous for now (async dial is the next planned step - see design).
	// On failure returns FALSE and fills errMsg; the caller then invokes
	// ShowDialError() for provider-specific UI (e.g. the RAS NAT-T prompt).
	virtual BOOL Dial(class CRLoginDoc *pDoc, CString &errMsg) = 0;

	// Tear the tunnel down. Idempotent.
	virtual void HangUp() = 0;
	virtual BOOL IsConnected() const = 0;

	// Optional: adjust the just-created socket before it opens
	// (RAS-compat sets the IP_UNICAST_IF interface index here).
	virtual void ConfigureSocket(class CExtSocket * /*pSock*/) {}

	// Optional: supply a replacement Left FIFO stage, or wire pSock so the
	// default FifoLinkLeft() path builds the right stage. Return NULL to use
	// the default socket path (RAS-compat and the SSH provider both do this;
	// the SSH provider instead sets pSock->m_pSshProxy). Packet-tier
	// providers (SSTP/IKEv2) will return a netstack-backed CFifoBase here.
	virtual CFifoBase *CreateLeftStage(class CRLoginDoc * /*pDoc*/, class CExtSocket * /*pSock*/,
									   LPCTSTR /*host*/, UINT /*port*/, int /*family*/) { return NULL; }

	// Provider-specific error UI after a failed Dial(). Base shows a generic
	// message box; RAS-compat adds the RAS 789 / NAT-T assisted fix prompt.
	virtual void ShowDialError(class CRLoginDoc *pDoc);

	// Reference counting for shared tunnels (several sessions, one gateway).
	int AddRef()  { return ++m_RefCount; }
	int Release() { return (m_RefCount > 0 ? --m_RefCount : 0); }
	int GetRefCount() const { return m_RefCount; }

	DWORD   GetLastError() const    { return m_LastError; }
	CString GetLastErrorMsg() const { return m_LastErrMsg; }

	// Factory. Returns NULL for VPN_NONE / unknown kind.
	static CVpnProvider *Create(EVpnKind kind);

protected:
	int     m_RefCount;
	DWORD   m_LastError;
	CString m_LastErrMsg;
};

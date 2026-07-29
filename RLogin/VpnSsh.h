//////////////////////////////////////////////////////////////////////
// VpnSsh.h : SSH-tunnel VPN provider (non-admin)
//
// MVP: routes the session through an *already-open* SSH session (named by
// CServerEntry::m_VpnServer), reusing the existing m_pSshProxy /
// Cssh::OpenTunnelSocket path - i.e. it packages the current "SSH Proxy"
// (proxy mode 8) as a selectable VPN provider. This needs no admin rights
// and no new connection code.
//
// Future: open a dedicated hidden backing SSH connection so the gateway
// session does not have to be opened manually (design detail notes, 7.1).
//////////////////////////////////////////////////////////////////////

#pragma once

#include "VpnProvider.h"

class CVpnProviderSsh : public CVpnProvider
{
public:
	CVpnProviderSsh() { m_pBackSsh = NULL; }
	virtual ~CVpnProviderSsh() { HangUp(); }

	virtual EVpnKind Kind() const { return VPN_SSH; }
	virtual BOOL Dial(class CRLoginDoc *pDoc, CString &errMsg);
	virtual void HangUp() { m_pBackSsh = NULL; }	// gateway session is not owned
	virtual BOOL IsConnected() const { return m_pBackSsh != NULL; }
	virtual CFifoBase *CreateLeftStage(class CRLoginDoc *pDoc, class CExtSocket *pSock,
									   LPCTSTR host, UINT port, int family);

protected:
	class CExtSocket *m_pBackSsh;	// borrowed SSH gateway socket (not owned)
};

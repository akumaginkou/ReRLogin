//////////////////////////////////////////////////////////////////////
// VpnProvider.cpp : per-session VPN provider abstraction + factory
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "RLogin.h"
#include "Data.h"
#include "RLoginDoc.h"
#include "ExtSocket.h"
#include "RasVpn.h"
#include "VpnProvider.h"
#include "VpnSsh.h"
#include "VpnL2tpIpsec.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//////////////////////////////////////////////////////////////////////
// CVpnProvider (base)

CVpnProvider::CVpnProvider()
{
	m_RefCount  = 0;
	m_LastError = 0;
}

CVpnProvider::~CVpnProvider()
{
}

void CVpnProvider::ShowDialError(CRLoginDoc *pDoc)
{
	CString msg;
	msg.Format(_T("VPN connect failed for '%s'\n%s"),
			   (LPCTSTR)(pDoc != NULL ? pDoc->m_ServerEntry.m_EntryName : _T("")),
			   (LPCTSTR)m_LastErrMsg);
	::AfxMessageBox(msg, MB_ICONERROR);
}

//////////////////////////////////////////////////////////////////////
// CVpnProviderRasCompat : behaviour-preserving wrapper of the existing
// Windows RAS L2TP/IPsec path (admin required, IP_UNICAST_IF binding).

class CVpnProviderRasCompat : public CVpnProvider
{
public:
	CVpnProviderRasCompat() { m_If4 = 0; m_If6 = 0; }
	virtual ~CVpnProviderRasCompat() { HangUp(); }

	virtual EVpnKind Kind() const { return VPN_RAS_L2TP; }
	virtual BOOL Dial(CRLoginDoc *pDoc, CString &errMsg);
	virtual void HangUp() { m_Ras.HangUp(); m_If4 = m_If6 = 0; }
	virtual BOOL IsConnected() const { return m_Ras.IsConnected(); }
	virtual void ConfigureSocket(CExtSocket *pSock)
	{
		if ( pSock != NULL ) {
			pSock->m_VpnIfIndex4 = m_If4;
			pSock->m_VpnIfIndex6 = m_If6;
		}
	}
	virtual void ShowDialError(CRLoginDoc *pDoc);

protected:
	CRasVpn m_Ras;
	DWORD   m_If4, m_If6;
};

BOOL CVpnProviderRasCompat::Dial(CRLoginDoc *pDoc, CString &errMsg)
{
	CServerEntry &se = pDoc->m_ServerEntry;
	DWORD if4 = 0, if6 = 0;

	if ( !m_Ras.Dial(se.m_VpnServer, se.m_VpnUser, se.m_VpnPass, se.m_VpnPsk,
					 se.m_VpnStrategy, se.m_VpnAuth, if4, if6, errMsg) ) {
		m_LastError  = m_Ras.GetLastRasError();
		m_LastErrMsg = errMsg;
		return FALSE;
	}

	m_If4 = if4;
	m_If6 = if6;
	return TRUE;
}

void CVpnProviderRasCompat::ShowDialError(CRLoginDoc *pDoc)
{
	// Same generic box as the base, then the RAS-specific NAT-T fix prompt
	// (preserves the original SocketOpen behaviour for RAS 789).
	CVpnProvider::ShowDialError(pDoc);

	CServerEntry &se = pDoc->m_ServerEntry;
	if ( m_LastError == 789 &&
		 (se.m_VpnStrategy == 0 || se.m_VpnStrategy == 1) &&
		 !CRasVpn::IsNatTEnabled() ) {
		if ( ::AfxMessageBox(_T("L2TP/IPsec failed with RAS 789, which usually means ")
				_T("NAT-T must be enabled (this PC is behind NAT).\n\nEnable NAT-T now? ")
				_T("Windows will ask for administrator rights, and you must REBOOT afterward."),
				MB_ICONQUESTION | MB_YESNO) == IDYES ) {
			CString nmsg;
			CRasVpn::EnableNatTElevated(nmsg);
			::AfxMessageBox(nmsg, MB_ICONINFORMATION);
		}
	}
}

//////////////////////////////////////////////////////////////////////
// Factory

CVpnProvider *CVpnProvider::Create(EVpnKind kind)
{
	switch ( kind ) {
	case VPN_RAS_L2TP: return new CVpnProviderRasCompat;
	case VPN_SSH:      return new CVpnProviderSsh;
	case VPN_L2TP_US:  return new CVpnProviderL2tpUs;
	default:           return NULL;
	}
}

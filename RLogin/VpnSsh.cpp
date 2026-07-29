//////////////////////////////////////////////////////////////////////
// VpnSsh.cpp : SSH-tunnel VPN provider (non-admin)
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "RLogin.h"
#include "Data.h"
#include "RLoginDoc.h"
#include "ExtSocket.h"
#include "VpnProvider.h"
#include "VpnSsh.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

BOOL CVpnProviderSsh::Dial(CRLoginDoc *pDoc, CString &errMsg)
{
	CRLoginApp *pApp = (CRLoginApp *)::AfxGetApp();
	CServerEntry &se = pDoc->m_ServerEntry;

	// m_VpnServer names an already-open SSH session to tunnel through.
	CRLoginDoc *pGw = pApp->GetDocFromEntryName(se.m_VpnServer, pDoc);

	if ( pGw == NULL || pGw->m_pSock == NULL || pGw->m_pSock->m_Type != ESCT_SSH_MAIN ) {
		errMsg.Format(_T("SSH gateway session '%s' is not open.\n")
					  _T("Open that SSH session first (a dedicated hidden backing ")
					  _T("connection is not implemented yet)."),
					  (LPCTSTR)se.m_VpnServer);
		m_LastErrMsg = errMsg;
		return FALSE;
	}

	m_pBackSsh = pGw->m_pSock;
	return TRUE;
}

CFifoBase *CVpnProviderSsh::CreateLeftStage(CRLoginDoc *pDoc, CExtSocket *pSock,
										   LPCTSTR host, UINT port, int family)
{
	// Reuse the existing SSH-proxy tunnel path: set m_pSshProxy and return
	// NULL so CExtSocket::FifoLinkLeft() builds the CFifoTunnel and
	// CExtSocket::Open() routes it through Cssh::OpenTunnelSocket().
	if ( m_pBackSsh == NULL )
		return NULL;

	pSock->m_pSshProxy = m_pBackSsh;
	return NULL;
}

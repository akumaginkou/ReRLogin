//////////////////////////////////////////////////////////////////////
// VpnL2tpIpsec.cpp : userspace L2TP/IPsec(PSK) VPN provider (non-admin)
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "RLogin.h"
#include "Data.h"
#include "RLoginDoc.h"
#include "ExtSocket.h"
#include "VpnProvider.h"
#include "VpnL2tpIpsec.h"
#include "VpnIke.h"
#include "VpnCrypto.h"
#include "VpnIkeMM.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CVpnProviderL2tpUs::CVpnProviderL2tpUs()
{
	m_bConnected = FALSE;
}

CVpnProviderL2tpUs::~CVpnProviderL2tpUs()
{
	HangUp();
}

BOOL CVpnProviderL2tpUs::Dial(CRLoginDoc *pDoc, CString &errMsg)
{
	// -------- M2a: run IKEv1 Main Mode messages 1..4 against the router -----
	if ( pDoc == NULL ) { errMsg = _T("VPN: no document"); return FALSE; }
	CServerEntry &se = pDoc->m_ServerEntry;

	if ( se.m_VpnServer.IsEmpty() ) { errMsg = _T("VPN: server is empty"); return FALSE; }

	CBuffer psk;
	CVpnCrypto::PskBytes(se.m_VpnPsk, psk);

	CIkeMainMode mm(pDoc);
	mm.SetPsk(psk.GetPtr(), psk.GetSize());

	CIkePhase1 ph1;
	if ( !mm.RunToMM4(se.m_VpnServer, ph1, errMsg) ) {
		m_LastErrMsg = errMsg;
		return FALSE;
	}

	// M2a stops after key derivation; MM5/6 auth + ESP/L2TP/PPP are next.
	if ( ph1.m_Sock != INVALID_SOCKET )
		closesocket(ph1.m_Sock);

	errMsg.Format(_T("userspace L2TP/IPsec to '%s': IKE Phase 1 (MM1-4) reached ")
				  _T("[enc=%d hash=%d group=%d natT=%d]. MM5/6 auth + ESP/L2TP/PPP ")
				  _T("land in the next milestone."),
				  (LPCTSTR)se.m_VpnServer, ph1.m_EncAlgo, ph1.m_HashAlgo,
				  ph1.m_Group, ph1.m_NatT);
	m_LastErrMsg = errMsg;
	return FALSE;
}

void CVpnProviderL2tpUs::HangUp()
{
	m_bConnected = FALSE;
}

CFifoBase *CVpnProviderL2tpUs::CreateLeftStage(CRLoginDoc * /*pDoc*/, CExtSocket * /*pSock*/,
											   LPCTSTR /*host*/, UINT /*port*/, int /*family*/)
{
	// The session's TCP will ride an lwIP netstack over the tunnel; wired in
	// a later milestone. Until then, no replacement stage.
	return NULL;
}

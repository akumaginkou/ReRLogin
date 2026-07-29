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
	// -------- M1 smoke test: build an IKEv1 Main Mode message 1 (SA) --------
	// Proves the ISAKMP/IKEv1 codec compiles, links and produces a message.
	// The actual UDP transport, DH/PSK crypto, NAT-T, ESP, L2TP and PPP land
	// in later milestones.
	static const CIkeProposalP1 s_props[] = {
		{ IKE_ENC_AES_CBC,  256, IKE_HASH_SHA2_256, IKE_GROUP_MODP2048, 28800 },
		{ IKE_ENC_AES_CBC,  128, IKE_HASH_SHA1,     IKE_GROUP_MODP1024, 28800 },
		{ IKE_ENC_3DES_CBC, 0,   IKE_HASH_SHA1,     IKE_GROUP_MODP1024, 28800 },
	};

	BYTE icookie[8]; ZeroMemory(icookie, sizeof(icookie));  // real cookie in M2
	BYTE rcookie[8]; ZeroMemory(rcookie, sizeof(rcookie));

	CBuffer sa;
	CIkePl::BuildPhase1SA(sa, s_props, _countof(s_props));

	CIkeBuilder ike;
	ike.AddPayload(IKE_PL_SA, sa);

	CBuffer mm1;
	ike.Finish(icookie, rcookie, IKE_XCHG_IDPROT, 0, 0, mm1);

	if ( pDoc != NULL )
		pDoc->LogDebug("VpnL2tpUs: built IKEv1 MM1 (%d bytes, %d proposals)\n",
					   mm1.GetSize(), (int)_countof(s_props));

	errMsg.Format(_T("userspace L2TP/IPsec to '%s': not yet connectable ")
				  _T("(M1 = IKE codec only; transport/crypto land in the next milestone)."),
				  (LPCTSTR)(pDoc != NULL ? pDoc->m_ServerEntry.m_VpnServer : _T("")));
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

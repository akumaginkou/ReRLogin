//////////////////////////////////////////////////////////////////////
// VpnL2tpIpsec.h : userspace L2TP/IPsec(PSK) VPN provider (non-admin)
//
// Connects a single RLogin session through a router acting as an
// L2TP/IPsec(PSK) VPN server, entirely in userspace - no Windows RAS, no
// LSA, no registry, no admin rights. Built bottom-up over several
// milestones: IKEv1 Main/Quick Mode -> ESP -> L2TP -> PPP -> lwIP netstack.
//
// M1 (this commit): provider skeleton + ISAKMP/IKEv1 wire codec (VpnIke.*).
// Dial() only exercises the codec and reports "work in progress".
//////////////////////////////////////////////////////////////////////

#pragma once

#include "VpnProvider.h"

class CVpnProviderL2tpUs : public CVpnProvider
{
public:
	CVpnProviderL2tpUs();
	virtual ~CVpnProviderL2tpUs();

	virtual EVpnKind Kind() const { return VPN_L2TP_US; }
	virtual BOOL Dial(class CRLoginDoc *pDoc, CString &errMsg);
	virtual void HangUp();
	virtual BOOL IsConnected() const { return m_bConnected; }
	virtual CFifoBase *CreateLeftStage(class CRLoginDoc *pDoc, class CExtSocket *pSock,
									   LPCTSTR host, UINT port, int family);

protected:
	BOOL m_bConnected;
};

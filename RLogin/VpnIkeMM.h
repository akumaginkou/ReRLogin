//////////////////////////////////////////////////////////////////////
// VpnIkeMM.h : IKEv1 Main Mode (Phase 1) initiator, PSK auth
//
// Milestone 2 part 2a. Drives the Main Mode exchange against a router
// acting as an L2TP/IPsec VPN server: messages 1-4 (SA negotiation + DH
// key exchange + NAT discovery) and the PSK key derivation (SKEYID,
// SKEYID_d/a/e). The encrypted messages 5/6 (ID + HASH auth) and the
// port-float NAT-T data path are completed in the next step.
//
// Uses the VpnIke codec + VpnCrypto (OpenSSL) + plain WinSock UDP.
//////////////////////////////////////////////////////////////////////

#pragma once

#include "Data.h"        // CBuffer
#include "VpnCrypto.h"

// Result / running state of a Phase-1 negotiation.
class CIkePhase1
{
public:
	CIkePhase1();

	BYTE   m_ICookie[8];
	BYTE   m_RCookie[8];
	int    m_HashAlgo;      // negotiated (IKE_HASH_*)
	int    m_EncAlgo;       // negotiated (IKE_ENC_*)
	int    m_EncKeyLen;     // negotiated cipher key bytes
	int    m_Group;         // negotiated DH group (IKE_GROUP_*)

	CBuffer m_SkeyId;
	CBuffer m_SkeyId_d;     // -> Phase-2 keying
	CBuffer m_SkeyId_a;     // -> Phase-2 / info HASH
	CBuffer m_SkeyId_e;     // -> Phase-1 message encryption
	CBuffer m_Gxy;          // DH shared secret (zero-padded to group len)

	BOOL   m_NatSrc;        // TRUE: we are behind NAT
	BOOL   m_NatDst;        // TRUE: responder is behind NAT
	BOOL   m_NatT;          // TRUE: NAT-T negotiated -> data path uses UDP 4500

	SOCKET m_Sock;          // connected UDP socket (floated to 4500 if m_NatT)
};

class CIkeMainMode
{
public:
	CIkeMainMode(class CRLoginDoc *pDoc);
	~CIkeMainMode();

	void SetPsk(const BYTE *psk, int len);

	// Connect to `host` and run Main Mode messages 1..4 + key derivation.
	// On success fills `ph1` (its socket is left open for the next steps).
	BOOL RunToMM4(LPCTSTR host, CIkePhase1 &ph1, CString &errMsg);

protected:
	class CRLoginDoc *m_pDoc;
	CBuffer  m_Psk;

	SOCKET   m_Sock;
	unsigned long m_DstIp;      // network order
	int      m_DstPort;         // 500, later 4500
	int      m_LastWsa;         // last WinSock error (diagnostics)

	// transport helpers
	BOOL SockOpen(LPCTSTR host, CString &errMsg);
	BOOL SendRaw(CBuffer &msg);
	int  RecvRaw(BYTE *buf, int max, int msec);
	void FloatToNatT();
	BOOL GetLocalAddr(unsigned long &ip, int &port);

	// prf helpers
	BOOL Prf(const BYTE *key, int klen, const BYTE *data, int dlen, CBuffer &out, int hashAlgo);
	void NatdHash(int hashAlgo, const BYTE *ic, const BYTE *rc,
				  unsigned long ip, int port, CBuffer &out);

	void Trace(LPCSTR fmt, ...);
};

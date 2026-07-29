//////////////////////////////////////////////////////////////////////
// VpnIkeMM.cpp : IKEv1 Main Mode (Phase 1) initiator, PSK auth
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "RLogin.h"
#include "Data.h"
#include "RLoginDoc.h"
#include "Fifo.h"          // WinSock types
#include <ws2tcpip.h>
#include "VpnIke.h"
#include "VpnCrypto.h"
#include "VpnIkeMM.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// NAT-T vendor IDs (16 bytes) - offer RFC 3947 + draft-02/03 for interop.
static const BYTE VID_NATT_RFC3947[16] =
	{ 0x4a,0x13,0x1c,0x81,0x07,0x03,0x58,0x45,0x5c,0x57,0x28,0xf2,0x0e,0x95,0x45,0x2f };
static const BYTE VID_NATT_DRAFT02[16] =
	{ 0x90,0xcb,0x80,0x91,0x3e,0xbb,0x69,0x6e,0x08,0x63,0x81,0xb5,0xec,0x42,0x7b,0x1f };
static const BYTE VID_NATT_DRAFT03[16] =
	{ 0x7d,0x94,0x19,0xa6,0x53,0x10,0xca,0x6f,0x2c,0x17,0x9d,0x92,0x15,0x52,0x9d,0x56 };

#define IKE_NONCE_LEN   20
#define IKE_RECV_MAX    4096

//////////////////////////////////////////////////////////////////////

CIkePhase1::CIkePhase1()
{
	ZeroMemory(m_ICookie, sizeof(m_ICookie));
	ZeroMemory(m_RCookie, sizeof(m_RCookie));
	m_HashAlgo = m_EncAlgo = m_EncKeyLen = m_Group = 0;
	m_NatSrc = m_NatDst = m_NatT = FALSE;
	m_Sock = INVALID_SOCKET;
}

//////////////////////////////////////////////////////////////////////

CIkeMainMode::CIkeMainMode(CRLoginDoc *pDoc)
{
	m_pDoc = pDoc;
	m_Sock = INVALID_SOCKET;
	m_DstIp = 0;
	m_DstPort = 500;
}

CIkeMainMode::~CIkeMainMode()
{
	// the socket ownership is handed to CIkePhase1 on success; only close a
	// socket still owned here (failure path).
	if ( m_Sock != INVALID_SOCKET )
		closesocket(m_Sock);
}

void CIkeMainMode::SetPsk(const BYTE *psk, int len)
{
	m_Psk.Clear();
	if ( psk != NULL && len > 0 )
		m_Psk.PutBuf((LPBYTE)psk, len);
}

void CIkeMainMode::Trace(LPCSTR fmt, ...)
{
	if ( m_pDoc == NULL )
		return;
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	_vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
	va_end(ap);
	m_pDoc->LogDebug("%s", buf);
}

//////////////////////////////////////////////////////////////////////
// transport

BOOL CIkeMainMode::SockOpen(LPCTSTR host, CString &errMsg)
{
	CStringA hostA(host);

	struct addrinfo hints, *res = NULL;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family   = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	if ( getaddrinfo((LPCSTR)hostA, "500", &hints, &res) != 0 || res == NULL ) {
		errMsg.Format(_T("VPN: cannot resolve '%s'"), host);
		return FALSE;
	}
	m_DstIp = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(res);

	m_Sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( m_Sock == INVALID_SOCKET ) {
		errMsg = _T("VPN: cannot create UDP socket");
		return FALSE;
	}

	struct sockaddr_in local;
	ZeroMemory(&local, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = 0;
	bind(m_Sock, (struct sockaddr *)&local, sizeof(local));

	m_DstPort = 500;
	struct sockaddr_in dst;
	ZeroMemory(&dst, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = m_DstIp;
	dst.sin_port = htons((u_short)m_DstPort);
	if ( connect(m_Sock, (struct sockaddr *)&dst, sizeof(dst)) != 0 ) {
		errMsg = _T("VPN: cannot connect UDP socket");
		return FALSE;
	}
	return TRUE;
}

BOOL CIkeMainMode::GetLocalAddr(unsigned long &ip, int &port)
{
	struct sockaddr_in sa;
	int len = sizeof(sa);
	if ( getsockname(m_Sock, (struct sockaddr *)&sa, &len) != 0 )
		return FALSE;
	ip = sa.sin_addr.s_addr;
	port = ntohs(sa.sin_port);
	return TRUE;
}

BOOL CIkeMainMode::SendRaw(CBuffer &msg)
{
	CBuffer wire;
	if ( m_DstPort == 4500 )
		wire.Put32Bit(0);           // non-ESP marker once floated to NAT-T
	wire.PutBuf(msg.GetPtr(), msg.GetSize());

	int n = send(m_Sock, (const char *)wire.GetPtr(), wire.GetSize(), 0);
	return (n == wire.GetSize()) ? TRUE : FALSE;
}

int CIkeMainMode::RecvRaw(BYTE *buf, int max, int msec)
{
	fd_set rf;
	FD_ZERO(&rf);
	FD_SET(m_Sock, &rf);
	struct timeval tv;
	tv.tv_sec  = msec / 1000;
	tv.tv_usec = (msec % 1000) * 1000;

	int s = select(0, &rf, NULL, NULL, &tv);
	if ( s <= 0 )
		return 0;                   // timeout / error

	int n = recv(m_Sock, (char *)buf, max, 0);
	if ( n <= 0 )
		return -1;

	if ( m_DstPort == 4500 ) {      // strip non-ESP marker
		if ( n < 4 )
			return -1;
		memmove(buf, buf + 4, n - 4);
		n -= 4;
	}
	return n;
}

void CIkeMainMode::FloatToNatT()
{
	m_DstPort = 4500;
	struct sockaddr_in dst;
	ZeroMemory(&dst, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = m_DstIp;
	dst.sin_port = htons(4500);
	connect(m_Sock, (struct sockaddr *)&dst, sizeof(dst));
}

//////////////////////////////////////////////////////////////////////
// crypto helpers

BOOL CIkeMainMode::Prf(const BYTE *key, int klen, const BYTE *data, int dlen,
					   CBuffer &out, int hashAlgo)
{
	BYTE mac[64];
	if ( !CVpnCrypto::Hmac(hashAlgo, key, klen, data, dlen, mac) )
		return FALSE;
	out.Clear();
	out.PutBuf(mac, CVpnCrypto::HashLen(hashAlgo));
	return TRUE;
}

void CIkeMainMode::NatdHash(int hashAlgo, const BYTE *ic, const BYTE *rc,
							unsigned long ip, int port, CBuffer &out)
{
	CBuffer d;
	d.PutBuf((LPBYTE)ic, 8);
	d.PutBuf((LPBYTE)rc, 8);
	d.PutBuf((LPBYTE)&ip, 4);           // network byte order
	d.Put16Bit(port);
	BYTE h[64];
	CVpnCrypto::Hash(hashAlgo, d.GetPtr(), d.GetSize(), h);
	out.Clear();
	out.PutBuf(h, CVpnCrypto::HashLen(hashAlgo));
}

//////////////////////////////////////////////////////////////////////
// Main Mode messages 1..4 + key derivation

BOOL CIkeMainMode::RunToMM4(LPCTSTR host, CIkePhase1 &ph1, CString &errMsg)
{
	if ( !SockOpen(host, errMsg) )
		return FALSE;

	// ---- cookies ----
	CVpnCrypto::Rand(ph1.m_ICookie, 8);
	ZeroMemory(ph1.m_RCookie, 8);

	// ---- MM1: HDR, SA, VID(natt x3) ----
	static const CIkeProposalP1 s_props[] = {
		{ IKE_ENC_AES_CBC,  256, IKE_HASH_SHA2_256, IKE_GROUP_MODP2048, 28800 },
		{ IKE_ENC_AES_CBC,  128, IKE_HASH_SHA1,     IKE_GROUP_MODP1024, 28800 },
		{ IKE_ENC_3DES_CBC, 0,   IKE_HASH_SHA1,     IKE_GROUP_MODP1024, 28800 },
	};
	CBuffer saBody;
	CIkePl::BuildPhase1SA(saBody, s_props, _countof(s_props));   // = SAi_b

	CBuffer mm1;
	{
		CIkeBuilder b;
		b.AddPayload(IKE_PL_SA, saBody);
		b.AddPayloadRaw(IKE_PL_VID, VID_NATT_RFC3947, 16);
		b.AddPayloadRaw(IKE_PL_VID, VID_NATT_DRAFT02, 16);
		b.AddPayloadRaw(IKE_PL_VID, VID_NATT_DRAFT03, 16);
		b.Finish(ph1.m_ICookie, ph1.m_RCookie, IKE_XCHG_IDPROT, 0, 0, mm1);
	}

	// ---- send MM1, receive MM2 (with retransmit) ----
	BYTE rbuf[IKE_RECV_MAX];
	int rlen = 0;
	int tries;
	for ( tries = 0 ; tries < 4 ; tries++ ) {
		if ( !SendRaw(mm1) ) { errMsg = _T("VPN: send MM1 failed"); return FALSE; }
		if ( (rlen = RecvRaw(rbuf, sizeof(rbuf), 2500)) > 0 )
			break;
	}
	if ( rlen <= 0 ) { errMsg = _T("VPN: no response to MM1 (Phase1)"); return FALSE; }

	CIkeParser p2;
	if ( !p2.Parse(rbuf, rlen) || p2.m_Exchange != IKE_XCHG_IDPROT ) {
		errMsg = _T("VPN: malformed MM2"); return FALSE;
	}
	memcpy(ph1.m_RCookie, p2.m_RCookie, 8);
	Trace("VpnIke: MM2 rcv %d bytes, %d payloads\n", rlen, p2.GetCount());

	// ---- parse chosen transform from MM2's SA payload ----
	int isa = p2.Find(IKE_PL_SA);
	if ( isa < 0 ) { errMsg = _T("VPN: MM2 has no SA"); return FALSE; }
	{
		const BYTE *sa = p2.GetBody(isa);
		int salen = p2.GetBodyLen(isa);
		int pos = 8;                                    // skip DOI(4)+Situation(4)
		if ( pos + 8 > salen ) { errMsg = _T("VPN: bad SA"); return FALSE; }
		int spisz = sa[pos + 6];
		pos += 8 + spisz;                               // skip proposal header + SPI
		if ( pos + 8 > salen ) { errMsg = _T("VPN: bad transform"); return FALSE; }
		int tlen = ((int)sa[pos + 2] << 8) | sa[pos + 3];
		int aEnd = pos + tlen;
		if ( aEnd > salen ) aEnd = salen;
		int a = pos + 8;
		int keybits = 0;
		while ( a + 4 <= aEnd ) {
			int type = ((int)sa[a] << 8) | sa[a + 1];
			int af   = type & 0x8000;
			type &= 0x7FFF;
			int val  = ((int)sa[a + 2] << 8) | sa[a + 3];
			if ( af ) {                                 // TV (basic)
				switch ( type ) {
				case IKE_ATTR_ENCRYPTION: ph1.m_EncAlgo  = val; break;
				case IKE_ATTR_HASH:       ph1.m_HashAlgo = val; break;
				case IKE_ATTR_GROUP_DESC: ph1.m_Group    = val; break;
				case IKE_ATTR_KEYLEN:     keybits        = val; break;
				}
				a += 4;
			} else {                                    // TLV (variable)
				a += 4 + val;
			}
		}
		ph1.m_EncKeyLen = CVpnCrypto::CipherKeyLen(ph1.m_EncAlgo, keybits);
	}
	if ( ph1.m_HashAlgo == 0 || ph1.m_Group == 0 || ph1.m_EncAlgo == 0 ) {
		errMsg = _T("VPN: MM2 transform not understood"); return FALSE;
	}
	Trace("VpnIke: negotiated enc=%d keylen=%d hash=%d group=%d\n",
		  ph1.m_EncAlgo, ph1.m_EncKeyLen, ph1.m_HashAlgo, ph1.m_Group);

	// ---- DH for the chosen group ----
	CVpnCrypto::CDh dh;
	if ( !dh.Init(ph1.m_Group) ) { errMsg = _T("VPN: DH init failed"); return FALSE; }
	CBuffer myPub;
	dh.GetPublic(myPub);

	// nonce Ni
	CBuffer ni;
	{ BYTE t[IKE_NONCE_LEN]; CVpnCrypto::Rand(t, IKE_NONCE_LEN); ni.PutBuf(t, IKE_NONCE_LEN); }

	// local address (for NAT-D)
	unsigned long lip = 0; int lport = 0;
	GetLocalAddr(lip, lport);

	// ---- MM3: HDR, KE, NONCE, NAT-D(dst), NAT-D(src) ----
	CBuffer natdDst, natdSrc;
	NatdHash(ph1.m_HashAlgo, ph1.m_ICookie, ph1.m_RCookie, m_DstIp, 500, natdDst);
	NatdHash(ph1.m_HashAlgo, ph1.m_ICookie, ph1.m_RCookie, lip, lport, natdSrc);

	CBuffer mm3;
	{
		CIkeBuilder b;
		b.AddPayload(IKE_PL_KE, myPub);
		b.AddPayload(IKE_PL_NONCE, ni);
		b.AddPayload(IKE_PL_NATD_RFC, natdDst);
		b.AddPayload(IKE_PL_NATD_RFC, natdSrc);
		b.Finish(ph1.m_ICookie, ph1.m_RCookie, IKE_XCHG_IDPROT, 0, 0, mm3);
	}

	for ( tries = 0 ; tries < 4 ; tries++ ) {
		if ( !SendRaw(mm3) ) { errMsg = _T("VPN: send MM3 failed"); return FALSE; }
		if ( (rlen = RecvRaw(rbuf, sizeof(rbuf), 2500)) > 0 )
			break;
	}
	if ( rlen <= 0 ) { errMsg = _T("VPN: no response to MM3"); return FALSE; }

	CIkeParser p4;
	if ( !p4.Parse(rbuf, rlen) ) { errMsg = _T("VPN: malformed MM4"); return FALSE; }
	Trace("VpnIke: MM4 rcv %d bytes, %d payloads\n", rlen, p4.GetCount());

	// peer KE + Nr
	int ike = p4.Find(IKE_PL_KE), inr = p4.Find(IKE_PL_NONCE);
	if ( ike < 0 || inr < 0 ) { errMsg = _T("VPN: MM4 missing KE/NONCE"); return FALSE; }
	if ( !dh.ComputeSecret(p4.GetBody(ike), p4.GetBodyLen(ike), ph1.m_Gxy) ) {
		errMsg = _T("VPN: DH shared secret failed"); return FALSE;
	}
	CBuffer nr;
	nr.PutBuf((LPBYTE)p4.GetBody(inr), p4.GetBodyLen(inr));

	// ---- NAT detection: is our local addr hash among MM4's NAT-D set? ----
	CBuffer myLocalHash;
	NatdHash(ph1.m_HashAlgo, ph1.m_ICookie, ph1.m_RCookie, lip, lport, myLocalHash);
	ph1.m_NatSrc = TRUE;
	int hl = CVpnCrypto::HashLen(ph1.m_HashAlgo);
	for ( int i = 0 ; (i = p4.Find(IKE_PL_NATD_RFC, i)) >= 0 ; i++ ) {
		if ( p4.GetBodyLen(i) == hl && memcmp(p4.GetBody(i), myLocalHash.GetPtr(), hl) == 0 ) {
			ph1.m_NatSrc = FALSE;   // our address seen unchanged -> no NAT on our side
			break;
		}
	}
	// also accept the draft NAT-D payload type
	if ( ph1.m_NatSrc ) {
		for ( int i = 0 ; (i = p4.Find(IKE_PL_NATD_DRAFT, i)) >= 0 ; i++ ) {
			if ( p4.GetBodyLen(i) == hl && memcmp(p4.GetBody(i), myLocalHash.GetPtr(), hl) == 0 ) {
				ph1.m_NatSrc = FALSE; break;
			}
		}
	}
	ph1.m_NatT = (p4.Find(IKE_PL_NATD_RFC) >= 0 || p4.Find(IKE_PL_NATD_DRAFT) >= 0) ? TRUE : FALSE;

	// ---- PSK key derivation (RFC 2409 5) ----
	// SKEYID = prf(psk, Ni_b | Nr_b)
	{
		CBuffer nn;
		nn.PutBuf(ni.GetPtr(), ni.GetSize());
		nn.PutBuf(nr.GetPtr(), nr.GetSize());
		if ( !Prf(m_Psk.GetPtr(), m_Psk.GetSize(), nn.GetPtr(), nn.GetSize(),
				  ph1.m_SkeyId, ph1.m_HashAlgo) ) {
			errMsg = _T("VPN: SKEYID failed"); return FALSE;
		}
	}
	// common tail: g^xy | CKY-I | CKY-R
	CBuffer tail;
	tail.PutBuf(ph1.m_Gxy.GetPtr(), ph1.m_Gxy.GetSize());
	tail.PutBuf(ph1.m_ICookie, 8);
	tail.PutBuf(ph1.m_RCookie, 8);

	// SKEYID_d = prf(SKEYID, g^xy|CKY-I|CKY-R|0)
	{
		CBuffer d;
		d.PutBuf(tail.GetPtr(), tail.GetSize());
		d.Put8Bit(0);
		Prf(ph1.m_SkeyId.GetPtr(), ph1.m_SkeyId.GetSize(), d.GetPtr(), d.GetSize(),
			ph1.m_SkeyId_d, ph1.m_HashAlgo);
	}
	// SKEYID_a = prf(SKEYID, SKEYID_d|g^xy|CKY-I|CKY-R|1)
	{
		CBuffer d;
		d.PutBuf(ph1.m_SkeyId_d.GetPtr(), ph1.m_SkeyId_d.GetSize());
		d.PutBuf(tail.GetPtr(), tail.GetSize());
		d.Put8Bit(1);
		Prf(ph1.m_SkeyId.GetPtr(), ph1.m_SkeyId.GetSize(), d.GetPtr(), d.GetSize(),
			ph1.m_SkeyId_a, ph1.m_HashAlgo);
	}
	// SKEYID_e = prf(SKEYID, SKEYID_a|g^xy|CKY-I|CKY-R|2)
	{
		CBuffer d;
		d.PutBuf(ph1.m_SkeyId_a.GetPtr(), ph1.m_SkeyId_a.GetSize());
		d.PutBuf(tail.GetPtr(), tail.GetSize());
		d.Put8Bit(2);
		Prf(ph1.m_SkeyId.GetPtr(), ph1.m_SkeyId.GetSize(), d.GetPtr(), d.GetSize(),
			ph1.m_SkeyId_e, ph1.m_HashAlgo);
	}

	Trace("VpnIke: Phase1 MM1-4 OK gxy=%d SKEYID=%d natT=%d natSrc=%d\n",
		  ph1.m_Gxy.GetSize(), ph1.m_SkeyId.GetSize(), ph1.m_NatT, ph1.m_NatSrc);

	// float to NAT-T port for the (upcoming) encrypted MM5/6 + data path
	if ( ph1.m_NatT )
		FloatToNatT();

	// hand the socket to the caller; our destructor must not close it
	ph1.m_Sock = m_Sock;
	m_Sock = INVALID_SOCKET;
	return TRUE;
}

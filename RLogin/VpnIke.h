//////////////////////////////////////////////////////////////////////
// VpnIke.h : ISAKMP / IKEv1 wire-format codec (RFC 2407/2408/2409)
//
// Milestone 1 of the userspace L2TP/IPsec(PSK) client. This file is the
// pure, crypto-free wire codec: it builds and parses ISAKMP messages and
// the IKEv1 payloads needed for Main Mode + Quick Mode against a router
// acting as an L2TP/IPsec VPN server. Serialization uses RLogin's CBuffer
// (big-endian Put/Get = network byte order). No sockets, no OpenSSL here.
//
// Later milestones add: UDP transport (:500/:4500), DH/PSK crypto, NAT-T,
// ESP, L2TP and PPP. See the design notes "ReRLogin 接続捨てVPN".
//////////////////////////////////////////////////////////////////////

#pragma once

#include "Data.h"   // CBuffer (big-endian Put/Get)

// ---- ISAKMP header ----------------------------------------------------
#define IKE_HDR_SIZE            28
#define IKE_VERSION_1_0         0x10

// Exchange types (RFC 2408 3.1)
#define IKE_XCHG_BASE           1
#define IKE_XCHG_IDPROT         2   // Identity Protection = Main Mode
#define IKE_XCHG_AUTHONLY       3
#define IKE_XCHG_AGGRESSIVE     4
#define IKE_XCHG_INFORMATIONAL  5
#define IKE_XCHG_QUICK          32  // IKEv1 Quick Mode (Phase 2)

// Header flags
#define IKE_FLAG_ENCRYPTION     0x01
#define IKE_FLAG_COMMIT         0x02
#define IKE_FLAG_AUTHONLY       0x04

// Payload types (RFC 2408 / RFC 3947 NAT-D)
#define IKE_PL_NONE             0
#define IKE_PL_SA               1
#define IKE_PL_PROPOSAL         2
#define IKE_PL_TRANSFORM        3
#define IKE_PL_KE               4
#define IKE_PL_ID               5
#define IKE_PL_CERT             6
#define IKE_PL_CERTREQ          7
#define IKE_PL_HASH             8
#define IKE_PL_SIG              9
#define IKE_PL_NONCE            10
#define IKE_PL_NOTIFY           11
#define IKE_PL_DELETE           12
#define IKE_PL_VID              13
#define IKE_PL_NATD_RFC         20  // RFC 3947 NAT-Discovery
#define IKE_PL_NATOA_RFC        21
#define IKE_PL_NATD_DRAFT       130 // draft-ietf-ipsec-nat-t-ike-02/03
#define IKE_PL_NATOA_DRAFT      131

// IPsec DOI (RFC 2407)
#define IKE_DOI_IPSEC           1
#define IKE_SIT_IDENTITY_ONLY   1

// Protocol IDs
#define IKE_PROTO_ISAKMP        1
#define IKE_PROTO_IPSEC_ESP     3

// ISAKMP (Phase 1) transform id
#define IKE_TRANS_KEY_IKE       1

// Phase-1 SA attribute types (RFC 2409 Appendix A)
#define IKE_ATTR_ENCRYPTION     1   // value: 5=3DES-CBC, 7=AES-CBC
#define IKE_ATTR_HASH           2   // value: 1=MD5, 2=SHA1, 4=SHA2-256
#define IKE_ATTR_AUTH_METHOD    3   // value: 1=PSK
#define IKE_ATTR_GROUP_DESC     4   // value: 2=modp1024, 5=modp1536, 14=modp2048
#define IKE_ATTR_LIFE_TYPE      11  // value: 1=seconds, 2=kbytes
#define IKE_ATTR_LIFE_DURATION  12  // value: seconds
#define IKE_ATTR_KEYLEN         14  // AES key length in bits (TV)

// attribute values
#define IKE_ENC_3DES_CBC        5
#define IKE_ENC_AES_CBC         7
#define IKE_HASH_MD5            1
#define IKE_HASH_SHA1           2
#define IKE_HASH_SHA2_256       4
#define IKE_AUTH_PSK            1
#define IKE_GROUP_MODP1024      2
#define IKE_GROUP_MODP1536      5
#define IKE_GROUP_MODP2048      14
#define IKE_LIFE_SECONDS        1

// ID types (RFC 2407 4.6.2)
#define IKE_ID_IPV4_ADDR        1
#define IKE_ID_FQDN             2
#define IKE_ID_USER_FQDN        3
#define IKE_ID_IPV4_SUBNET      4
#define IKE_ID_KEY_ID           11

// ----------------------------------------------------------------------
// One transform proposal (a single transform-set to offer in the SA).
struct CIkeProposalP1 {
	int enc;        // IKE_ENC_*
	int keylen;     // AES key bits (0 = not applicable, e.g. 3DES)
	int hash;       // IKE_HASH_*
	int group;      // IKE_GROUP_*
	int lifeSec;    // SA lifetime seconds (0 = omit)
};

// ----------------------------------------------------------------------
// CIkeBuilder - assemble one ISAKMP message payload-by-payload, handling
// the next-payload chaining and the header length backpatch.
class CIkeBuilder
{
public:
	CIkeBuilder();

	// append a generic payload (its body already encoded in `data`)
	void AddPayload(int type, class CBuffer &data);
	void AddPayloadRaw(int type, const BYTE *data, int len);

	// finalize into `out`: writes the 28-byte ISAKMP header + all payloads.
	void Finish(const BYTE icookie[8], const BYTE rcookie[8],
				int exchange, int flags, DWORD msgId, class CBuffer &out);

protected:
	CBuffer m_Body;           // concatenated payloads
	int  m_FirstType;         // type of first payload (-> header NextPayload)
	int  m_PrevNextOff;       // offset of previous payload's NextPayload byte
};

// ----------------------------------------------------------------------
// Payload body builders (produce just the payload-specific body; the
// generic 4-byte payload header is added by CIkeBuilder::AddPayload).
namespace CIkePl {
	// Phase-1 ISAKMP SA payload body: DOI + situation + one proposal whose
	// transforms are `props[0..n-1]` (each becomes a numbered transform).
	void BuildPhase1SA(class CBuffer &out, const CIkeProposalP1 *props, int nprops);

	// Identity payload body (ID type + protocol/port + data).
	void BuildID(class CBuffer &out, int idType, int protocol, int port,
				 const BYTE *idData, int idLen);

	// Vendor ID / NAT-D / generic opaque body = raw bytes (use AddPayloadRaw).
}

// ----------------------------------------------------------------------
// CIkeParser - walk the payloads of a received ISAKMP message.
class CIkeParser
{
public:
	CIkeParser();

	// Parse a full datagram. Returns FALSE on malformed input.
	BOOL Parse(const BYTE *buf, int len);

	// header fields (valid after a successful Parse)
	BYTE  m_ICookie[8];
	BYTE  m_RCookie[8];
	int   m_Exchange;
	int   m_Flags;
	DWORD m_MsgId;
	int   m_FirstPayload;

	// payload iteration
	int   GetCount() const { return m_Count; }
	int   GetType(int i) const   { return (i >= 0 && i < m_Count) ? m_Type[i] : IKE_PL_NONE; }
	const BYTE *GetBody(int i) const { return (i >= 0 && i < m_Count) ? m_Body[i] : NULL; }
	int   GetBodyLen(int i) const { return (i >= 0 && i < m_Count) ? m_BodyLen[i] : 0; }
	int   Find(int type, int from = 0) const;  // index of first payload of `type`, or -1

protected:
	enum { IKE_MAX_PL = 64 };
	int          m_Count;
	int          m_Type[IKE_MAX_PL];
	const BYTE  *m_Body[IKE_MAX_PL];
	int          m_BodyLen[IKE_MAX_PL];
};

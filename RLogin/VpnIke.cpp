//////////////////////////////////////////////////////////////////////
// VpnIke.cpp : ISAKMP / IKEv1 wire-format codec (crypto-free)
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "RLogin.h"
#include "Data.h"
#include "VpnIke.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//////////////////////////////////////////////////////////////////////
// ISAKMP attribute helpers (RFC 2408 3.3) - basic (TV) attributes only.
// Format: [AF(1)|Type(15)] [Value(16)]  with AF=1 meaning TV (short form).

static void PutAttrTV(CBuffer &out, int type, int value)
{
	out.Put16Bit(0x8000 | (type & 0x7FFF));
	out.Put16Bit(value & 0xFFFF);
}

//////////////////////////////////////////////////////////////////////
// CIkeBuilder

CIkeBuilder::CIkeBuilder()
{
	m_FirstType   = IKE_PL_NONE;
	m_PrevNextOff = -1;
	m_Body.Clear();
}

void CIkeBuilder::AddPayloadRaw(int type, const BYTE *data, int len)
{
	// chain the previous payload's NextPayload field to this payload's type
	if ( m_FirstType == IKE_PL_NONE )
		m_FirstType = type;
	else if ( m_PrevNextOff >= 0 )
		*(m_Body.GetPos(m_PrevNextOff)) = (BYTE)type;

	int start = m_Body.GetSize();
	m_Body.Put8Bit(IKE_PL_NONE);        // NextPayload (backpatched by next Add)
	m_Body.Put8Bit(0);                  // RESERVED
	m_Body.Put16Bit(4 + len);           // payload length (incl. this header)
	if ( data != NULL && len > 0 )
		m_Body.PutBuf((LPBYTE)data, len);

	m_PrevNextOff = start;              // remember where to backpatch
}

void CIkeBuilder::AddPayload(int type, CBuffer &data)
{
	AddPayloadRaw(type, data.GetPtr(), data.GetSize());
}

void CIkeBuilder::Finish(const BYTE icookie[8], const BYTE rcookie[8],
						 int exchange, int flags, DWORD msgId, CBuffer &out)
{
	out.Clear();
	out.PutBuf((LPBYTE)icookie, 8);
	out.PutBuf((LPBYTE)rcookie, 8);
	out.Put8Bit(m_FirstType);           // NextPayload = first payload type
	out.Put8Bit(IKE_VERSION_1_0);       // Version (MjVer 1, MnVer 0)
	out.Put8Bit(exchange);
	out.Put8Bit(flags);
	out.Put32Bit((LONG)msgId);
	out.Put32Bit((LONG)(IKE_HDR_SIZE + m_Body.GetSize()));   // total length
	if ( m_Body.GetSize() > 0 )
		out.PutBuf(m_Body.GetPtr(), m_Body.GetSize());
}

//////////////////////////////////////////////////////////////////////
// Payload body builders

void CIkePl::BuildPhase1SA(CBuffer &out, const CIkeProposalP1 *props, int nprops)
{
	out.Clear();

	// SA payload body: DOI + Situation, then the Proposal payload.
	out.Put32Bit(IKE_DOI_IPSEC);
	out.Put32Bit(IKE_SIT_IDENTITY_ONLY);

	// Build all transforms first so we can size the Proposal payload.
	CBuffer trans;
	for ( int i = 0 ; i < nprops ; i++ ) {
		const CIkeProposalP1 &p = props[i];

		CBuffer attrs;
		PutAttrTV(attrs, IKE_ATTR_ENCRYPTION, p.enc);
		if ( p.enc == IKE_ENC_AES_CBC && p.keylen > 0 )
			PutAttrTV(attrs, IKE_ATTR_KEYLEN, p.keylen);
		PutAttrTV(attrs, IKE_ATTR_HASH, p.hash);
		PutAttrTV(attrs, IKE_ATTR_AUTH_METHOD, IKE_AUTH_PSK);
		PutAttrTV(attrs, IKE_ATTR_GROUP_DESC, p.group);
		if ( p.lifeSec > 0 ) {
			PutAttrTV(attrs, IKE_ATTR_LIFE_TYPE, IKE_LIFE_SECONDS);
			PutAttrTV(attrs, IKE_ATTR_LIFE_DURATION, p.lifeSec);
		}

		// Transform payload: next(1)/rsv(1)/len(2)/tnum(1)/tid(1)/rsv2(2)/attrs
		int tlen = 8 + attrs.GetSize();
		trans.Put8Bit(i + 1 < nprops ? IKE_PL_TRANSFORM : IKE_PL_NONE);
		trans.Put8Bit(0);
		trans.Put16Bit(tlen);
		trans.Put8Bit(i + 1);               // transform number
		trans.Put8Bit(IKE_TRANS_KEY_IKE);   // transform id (KEY_IKE)
		trans.Put16Bit(0);                  // reserved
		trans.PutBuf(attrs.GetPtr(), attrs.GetSize());
	}

	// Proposal payload: next(1)/rsv(1)/len(2)/pnum(1)/proto(1)/spisize(1)/#trans(1)/SPI/transforms
	int plen = 8 + trans.GetSize();
	out.Put8Bit(IKE_PL_NONE);               // last (only) proposal
	out.Put8Bit(0);
	out.Put16Bit(plen);
	out.Put8Bit(1);                         // proposal #
	out.Put8Bit(IKE_PROTO_ISAKMP);          // protocol-id = ISAKMP
	out.Put8Bit(0);                         // SPI size (0 for phase 1)
	out.Put8Bit(nprops);                    // # transforms
	out.PutBuf(trans.GetPtr(), trans.GetSize());
}

void CIkePl::BuildID(CBuffer &out, int idType, int protocol, int port,
					 const BYTE *idData, int idLen)
{
	out.Clear();
	out.Put8Bit(idType);
	out.Put8Bit(protocol);
	out.Put16Bit(port);
	if ( idData != NULL && idLen > 0 )
		out.PutBuf((LPBYTE)idData, idLen);
}

//////////////////////////////////////////////////////////////////////
// CIkeParser

CIkeParser::CIkeParser()
{
	m_Count = 0;
	m_Exchange = 0;
	m_Flags = 0;
	m_MsgId = 0;
	m_FirstPayload = IKE_PL_NONE;
	ZeroMemory(m_ICookie, sizeof(m_ICookie));
	ZeroMemory(m_RCookie, sizeof(m_RCookie));
}

BOOL CIkeParser::Parse(const BYTE *buf, int len)
{
	m_Count = 0;
	if ( buf == NULL || len < IKE_HDR_SIZE )
		return FALSE;

	memcpy(m_ICookie, buf + 0, 8);
	memcpy(m_RCookie, buf + 8, 8);
	m_FirstPayload = buf[16];
	// buf[17] = version
	m_Exchange = buf[18];
	m_Flags    = buf[19];
	m_MsgId    = ((DWORD)buf[20] << 24) | ((DWORD)buf[21] << 16) |
				 ((DWORD)buf[22] << 8)  | ((DWORD)buf[23]);
	DWORD total = ((DWORD)buf[24] << 24) | ((DWORD)buf[25] << 16) |
				  ((DWORD)buf[26] << 8)  | ((DWORD)buf[27]);
	if ( total < (DWORD)IKE_HDR_SIZE || total > (DWORD)len )
		return FALSE;

	// Encrypted payloads (phase 1 msg 5/6, informational) can't be walked
	// until decrypted; report zero payloads but a valid header.
	if ( m_Flags & IKE_FLAG_ENCRYPTION )
		return TRUE;

	int next = m_FirstPayload;
	int pos  = IKE_HDR_SIZE;
	while ( next != IKE_PL_NONE && pos + 4 <= (int)total && m_Count < IKE_MAX_PL ) {
		int nextType = buf[pos];
		int plLen    = ((int)buf[pos + 2] << 8) | (int)buf[pos + 3];
		if ( plLen < 4 || pos + plLen > (int)total )
			return FALSE;

		m_Type[m_Count]    = next;
		m_Body[m_Count]    = buf + pos + 4;
		m_BodyLen[m_Count] = plLen - 4;
		m_Count++;

		pos  += plLen;
		next  = nextType;
	}
	return TRUE;
}

int CIkeParser::Find(int type, int from) const
{
	for ( int i = (from < 0 ? 0 : from) ; i < m_Count ; i++ ) {
		if ( m_Type[i] == type )
			return i;
	}
	return -1;
}

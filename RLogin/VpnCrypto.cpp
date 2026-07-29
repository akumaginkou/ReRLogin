//////////////////////////////////////////////////////////////////////
// VpnCrypto.cpp : OpenSSL helpers for the userspace IKEv1 / IPsec client
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "RLogin.h"
#include "Data.h"
#include "VpnIke.h"
#include "VpnCrypto.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

namespace CVpnCrypto {

//////////////////////////////////////////////////////////////////////
// small selectors

static const EVP_MD *MdOf(int hashAlgo)
{
	switch ( hashAlgo ) {
	case IKE_HASH_MD5:      return EVP_md5();
	case IKE_HASH_SHA1:     return EVP_sha1();
	case IKE_HASH_SHA2_256: return EVP_sha256();
	}
	return NULL;
}

static const EVP_CIPHER *CipherOf(int enc, int keylen)
{
	if ( enc == IKE_ENC_3DES_CBC )
		return EVP_des_ede3_cbc();
	if ( enc == IKE_ENC_AES_CBC ) {
		switch ( keylen ) {
		case 16: return EVP_aes_128_cbc();
		case 24: return EVP_aes_192_cbc();
		case 32: return EVP_aes_256_cbc();
		}
	}
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// random / hash / hmac

BOOL Rand(BYTE *out, int len)
{
	return (RAND_bytes(out, len) == 1) ? TRUE : FALSE;
}

int HashLen(int hashAlgo)
{
	const EVP_MD *md = MdOf(hashAlgo);
	return (md != NULL) ? EVP_MD_get_size(md) : 0;
}

BOOL Hash(int hashAlgo, const BYTE *data, int len, BYTE *out)
{
	const EVP_MD *md = MdOf(hashAlgo);
	if ( md == NULL )
		return FALSE;
	unsigned int olen = 0;
	return (EVP_Digest(data, (size_t)len, out, &olen, md, NULL) == 1) ? TRUE : FALSE;
}

BOOL Hmac(int hashAlgo, const BYTE *key, int keylen,
		  const BYTE *data, int datalen, BYTE *out)
{
	const EVP_MD *md = MdOf(hashAlgo);
	if ( md == NULL )
		return FALSE;
	unsigned int olen = 0;
	return (HMAC(md, key, keylen, data, (size_t)datalen, out, &olen) != NULL) ? TRUE : FALSE;
}

BOOL Hmac2(int hashAlgo, const BYTE *key, int keylen,
		   const BYTE *d1, int l1, const BYTE *d2, int l2, BYTE *out)
{
	// concatenate then use the one-shot HMAC (avoids the deprecated HMAC_CTX)
	CBuffer msg;
	if ( d1 != NULL && l1 > 0 ) msg.PutBuf((LPBYTE)d1, l1);
	if ( d2 != NULL && l2 > 0 ) msg.PutBuf((LPBYTE)d2, l2);
	return Hmac(hashAlgo, key, keylen, msg.GetPtr(), msg.GetSize(), out);
}

//////////////////////////////////////////////////////////////////////
// CBC cipher (no padding; caller pads to block size, ISAKMP style)

int CipherBlockLen(int enc)
{
	if ( enc == IKE_ENC_3DES_CBC ) return 8;
	if ( enc == IKE_ENC_AES_CBC )  return 16;
	return 0;
}

int CipherKeyLen(int enc, int aesKeyBits)
{
	if ( enc == IKE_ENC_3DES_CBC ) return 24;
	if ( enc == IKE_ENC_AES_CBC )  return (aesKeyBits > 0 ? aesKeyBits / 8 : 16);
	return 0;
}

static BOOL CbcRun(int enc, const BYTE *key, int keylen, const BYTE *iv,
				   const BYTE *in, int len, BYTE *out, int doEnc)
{
	const EVP_CIPHER *c = CipherOf(enc, keylen);
	if ( c == NULL || len <= 0 || (len % CipherBlockLen(enc)) != 0 )
		return FALSE;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if ( ctx == NULL )
		return FALSE;

	BOOL ok = FALSE;
	int outl = 0;
	if ( EVP_CipherInit_ex(ctx, c, NULL, key, iv, doEnc) == 1 ) {
		EVP_CIPHER_CTX_set_padding(ctx, 0);
		if ( EVP_CipherUpdate(ctx, out, &outl, in, len) == 1 && outl == len )
			ok = TRUE;
	}

	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

BOOL CbcEncrypt(int enc, const BYTE *key, int keylen, const BYTE *iv,
				const BYTE *in, int len, BYTE *out)
{
	return CbcRun(enc, key, keylen, iv, in, len, out, 1);
}

BOOL CbcDecrypt(int enc, const BYTE *key, int keylen, const BYTE *iv,
				const BYTE *in, int len, BYTE *out)
{
	return CbcRun(enc, key, keylen, iv, in, len, out, 0);
}

//////////////////////////////////////////////////////////////////////
// PSK bytes

static int HexVal(int c)
{
	if ( c >= '0' && c <= '9' ) return c - '0';
	if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
	if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
	return -1;
}

void PskBytes(LPCTSTR psk, CBuffer &out)
{
	out.Clear();

	// TCHAR -> UTF-8 narrow string
	CStringA a;
#ifdef _UNICODE
	int need = ::WideCharToMultiByte(CP_UTF8, 0, psk, -1, NULL, 0, NULL, NULL);
	if ( need > 1 ) {
		::WideCharToMultiByte(CP_UTF8, 0, psk, -1, a.GetBuffer(need), need, NULL, NULL);
		a.ReleaseBuffer();
	}
#else
	a = psk;
#endif

	LPCSTR s = (LPCSTR)a;
	int n = a.GetLength();

	// hex form? "0x...." or an even-length all-hex string.
	int start = 0;
	if ( n >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') )
		start = 2;

	int hexlen = n - start;
	BOOL isHex = (hexlen > 0 && (hexlen % 2) == 0);
	if ( isHex ) {
		for ( int i = start ; i < n ; i++ ) {
			if ( HexVal((BYTE)s[i]) < 0 ) { isHex = FALSE; break; }
		}
	}
	// a bare passphrase that merely happens to be hex is ambiguous; only treat
	// as hex when it is 0x-prefixed OR looks like a raw key (>= 16 hex chars).
	if ( isHex && start == 0 && hexlen < 16 )
		isHex = FALSE;

	if ( isHex ) {
		for ( int i = start ; i + 1 < n ; i += 2 )
			out.Put8Bit((HexVal((BYTE)s[i]) << 4) | HexVal((BYTE)s[i + 1]));
	} else {
		if ( n > 0 )
			out.PutBuf((LPBYTE)s, n);
	}
}

//////////////////////////////////////////////////////////////////////
// Diffie-Hellman over an IKE MODP group

CDh::CDh()
{
	m_pP = m_pG = m_pPriv = m_pPub = NULL;
	m_Len = 0;
}

CDh::~CDh()
{
	Clear();
}

void CDh::Clear()
{
	if ( m_pP    != NULL ) { BN_free((BIGNUM *)m_pP);    m_pP = NULL; }
	if ( m_pG    != NULL ) { BN_free((BIGNUM *)m_pG);    m_pG = NULL; }
	if ( m_pPriv != NULL ) { BN_clear_free((BIGNUM *)m_pPriv); m_pPriv = NULL; }
	if ( m_pPub  != NULL ) { BN_free((BIGNUM *)m_pPub);  m_pPub = NULL; }
	m_Len = 0;
}

BOOL CDh::Init(int group)
{
	Clear();

	BIGNUM *p = NULL;
	switch ( group ) {
	case IKE_GROUP_MODP1024: p = BN_get_rfc2409_prime_1024(NULL); break;
	case IKE_GROUP_MODP1536: p = BN_get_rfc3526_prime_1536(NULL); break;
	case IKE_GROUP_MODP2048: p = BN_get_rfc3526_prime_2048(NULL); break;
	default: return FALSE;
	}
	if ( p == NULL )
		return FALSE;

	BIGNUM *g = BN_new();
	BIGNUM *x = BN_new();
	BIGNUM *pub = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if ( g == NULL || x == NULL || pub == NULL || ctx == NULL )
		goto fail;

	BN_set_word(g, 2);

	// private exponent: random, same bit size as the prime.
	if ( BN_rand(x, BN_num_bits(p), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) != 1 )
		goto fail;
	// public = g^x mod p
	if ( BN_mod_exp(pub, g, x, p, ctx) != 1 )
		goto fail;

	m_pP   = p;
	m_pG   = g;
	m_pPriv = x;
	m_pPub = pub;
	m_Len  = BN_num_bytes(p);

	BN_CTX_free(ctx);
	return TRUE;

fail:
	if ( g != NULL )   BN_free(g);
	if ( x != NULL )   BN_clear_free(x);
	if ( pub != NULL ) BN_free(pub);
	if ( ctx != NULL ) BN_CTX_free(ctx);
	if ( p != NULL )   BN_free(p);
	return FALSE;
}

// left-pad a BIGNUM's big-endian bytes to `len` into out
static void BnToFixed(const BIGNUM *bn, int len, CBuffer &out)
{
	out.Clear();
	int nb = BN_num_bytes(bn);
	for ( int i = nb ; i < len ; i++ )
		out.Put8Bit(0);
	if ( nb > 0 ) {
		LPBYTE tmp = out.PutSpc(nb);
		BN_bn2bin(bn, tmp);
	}
}

BOOL CDh::GetPublic(CBuffer &out) const
{
	if ( m_pPub == NULL || m_Len <= 0 )
		return FALSE;
	BnToFixed((const BIGNUM *)m_pPub, m_Len, out);
	return TRUE;
}

BOOL CDh::ComputeSecret(const BYTE *peerPub, int peerLen, CBuffer &secret) const
{
	if ( m_pP == NULL || m_pPriv == NULL || peerPub == NULL || peerLen <= 0 )
		return FALSE;

	BIGNUM *peer = BN_bin2bn(peerPub, peerLen, NULL);
	BIGNUM *sec  = BN_new();
	BN_CTX *ctx  = BN_CTX_new();
	BOOL ok = FALSE;

	if ( peer != NULL && sec != NULL && ctx != NULL &&
		 BN_mod_exp(sec, peer, (const BIGNUM *)m_pPriv, (const BIGNUM *)m_pP, ctx) == 1 ) {
		BnToFixed(sec, m_Len, secret);      // zero-padded to group length (IKE requires)
		ok = TRUE;
	}

	if ( peer != NULL ) BN_free(peer);
	if ( sec  != NULL ) BN_clear_free(sec);
	if ( ctx  != NULL ) BN_CTX_free(ctx);
	return ok;
}

} // namespace CVpnCrypto

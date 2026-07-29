//////////////////////////////////////////////////////////////////////
// VpnCrypto.h : OpenSSL helpers for the userspace IKEv1 / IPsec client
//
// Milestone 2. Isolates all OpenSSL usage (DH over IKE MODP groups,
// HMAC/prf, hash, CBC cipher, secure random, PSK byte derivation) behind a
// small crypto-agnostic surface so the protocol code stays clean and the
// OpenSSL 3.x API risk is contained in one translation unit.
//
// Algorithm ids reuse the IKE_* constants from VpnIke.h.
//////////////////////////////////////////////////////////////////////

#pragma once

#include "Data.h"   // CBuffer

namespace CVpnCrypto {

	// ---- random ----
	BOOL Rand(BYTE *out, int len);

	// ---- hash (IKE_HASH_MD5 / SHA1 / SHA2_256) ----
	int  HashLen(int hashAlgo);                 // digest size in bytes, 0 = unknown
	BOOL Hash(int hashAlgo, const BYTE *data, int len, BYTE *out);

	// ---- HMAC (the IKEv1 prf) ----
	BOOL Hmac(int hashAlgo, const BYTE *key, int keylen,
			  const BYTE *data, int datalen, BYTE *out);   // out = HashLen bytes
	// convenience: HMAC over two concatenated buffers
	BOOL Hmac2(int hashAlgo, const BYTE *key, int keylen,
			   const BYTE *d1, int l1, const BYTE *d2, int l2, BYTE *out);

	// ---- cipher (IKE_ENC_3DES_CBC / IKE_ENC_AES_CBC), no padding ----
	int  CipherBlockLen(int enc);               // 8 (3DES) / 16 (AES)
	int  CipherKeyLen(int enc, int aesKeyBits); // 24 (3DES) / aesKeyBits/8
	BOOL CbcEncrypt(int enc, const BYTE *key, int keylen, const BYTE *iv,
					const BYTE *in, int len, BYTE *out);   // len % blocklen == 0
	BOOL CbcDecrypt(int enc, const BYTE *key, int keylen, const BYTE *iv,
					const BYTE *in, int len, BYTE *out);

	// ---- PSK bytes: accept an ASCII/UTF-8 passphrase, or hex ("0x..." or
	//      an even-length all-hex string) which is decoded to raw bytes. ----
	void PskBytes(LPCTSTR psk, CBuffer &out);

	// ---- Diffie-Hellman over an IKE MODP group (IKE_GROUP_2/5/14) ----
	class CDh
	{
	public:
		CDh();
		~CDh();

		BOOL Init(int group);                   // load p,g; generate private + public
		int  Len() const { return m_Len; }      // group prime length in bytes
		BOOL GetPublic(CBuffer &out) const;      // our g^x mod p, left-padded to Len()
		BOOL ComputeSecret(const BYTE *peerPub, int peerLen, CBuffer &secret) const;
		void Clear();

	protected:
		void *m_pP;     // BIGNUM* prime
		void *m_pG;     // BIGNUM* generator
		void *m_pPriv;  // BIGNUM* private exponent x
		void *m_pPub;   // BIGNUM* public value g^x mod p
		int   m_Len;
	};
}

/**
 * @file   uefi.h
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  lots of constants, GUIDs, and structures taken from other EFI
 *         sources
 *
 * [MIT license]
 *
 * Copyright (c) 2024 Ingo A. Kubbilun
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef _INC_UEFI_H_
#define _INC_UEFI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <byteswap.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/mount.h>

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/aes.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/engine.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs7.h>

/**
 * many of the following declarations originate from GNU EFI - the main source
 * SHALL ALWAYS be the UEFI specification, version 2.10
 */

typedef struct __attribute__((packed)) _EFI_TIME
{
  uint16_t      Year;           // 1998 - 20XX
  uint8_t       Month;          // 1 - 12
  uint8_t       Day;            // 1 - 31
  uint8_t       Hour;           // 0 - 23
  uint8_t       Minute;         // 0 - 59
  uint8_t       Second;         // 0 - 59
  uint8_t       _Pad1;
  uint32_t      Nanosecond;     // 0 - 999,999,999
  int16_t       TimeZone;       // -1440 to 1440 or 2047
  uint8_t       Daylight;
  uint8_t       _Pad2;
} EFI_TIME;

#ifndef SHA256_DIGEST_SIZE

#define SHA1_DIGEST_SIZE          20  // DEPRECATED, DO NOT USE ANYMORE
#define SHA224_DIGEST_SIZE        28  // this is SHA-2 - also applicable to SHA-3
#define SHA256_DIGEST_SIZE        32  // this is SHA-2 - also applicable to SHA-3
#define SHA384_DIGEST_SIZE        48  // this is SHA-2 - also applicable to SHA-3
#define SHA512_DIGEST_SIZE        64  // this is SHA-2 - also applicable to SHA-3

#endif

typedef uint8_t     EFI_SHA1_HASH[SHA1_DIGEST_SIZE];
typedef uint8_t     EFI_SHA224_HASH[SHA224_DIGEST_SIZE];
typedef uint8_t     EFI_SHA256_HASH[SHA256_DIGEST_SIZE];
typedef uint8_t     EFI_SHA384_HASH[SHA384_DIGEST_SIZE];
typedef uint8_t     EFI_SHA512_HASH[SHA512_DIGEST_SIZE];

#define EFI_GLOBAL_VARIABLE                                 { 0x8BE4DF61, 0x93CA, 0x11d2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } } // see type 'GUID' below

#define GUID_EFI_IMAGE_SECURITY_DATABASE                    "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
#define EFI_IMAGE_SECURITY_DATABASE_GUID                    { 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } } // see type 'GUID' below

// UEFI-Spec: This identifies a signature containing a SHA-256 hash. The SignatureHeader size shall always be 0. The SignatureSize shall always be 16 (size of SignatureOwner component) + 32 bytes.
#define EFI_CERT_SHA256_GUID                                { 0xc1c41626, 0x504c, 0x4092, { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } } // see type 'GUID' below

/* UEFI-Spec:
 * This identifies a signature containing an RSA-2048 key. The key (only the modulus since the public key exponent is
 * known to be 0x10001) shall be stored in big-endian order.
 * The SignatureHeader size shall always be 0. The SignatureSize shall always be 16 (size of SignatureOwner component) +
 + 256 bytes.
 */
#define EFI_CERT_RSA2048_GUID                               { 0x3c5766e8, 0x269c, 0x4e34, { 0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6 } } // see type 'GUID' below

/** UEFI-Spec:
 * This identifies a signature containing a RSA-2048 signature of a SHA-256 hash. The SignatureHeader size shall always
 * be 0. The SignatureSize shall always be 16 (size of SignatureOwner component) + 256 bytes.
 */
#define EFI_CERT_RSA2048_SHA256_GUID                        { 0xe2b36190, 0x879b, 0x4a3d, { 0xad, 0x8d, 0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84 } } // see type 'GUID' below

/** DO NOT USE ANYMORE (SHA-1 IS DEPRECATED), UEFI-Spec:
 * This identifies a signature containing a SHA-1 hash. The SignatureSize shall always be 16 (size of SignatureOwner
 * component) + 20 bytes.
 */
#define EFI_CERT_SHA1_GUID                                  { 0x826ca512, 0xcf10, 0x4ac9, { 0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd } } // see type 'GUID' below

/** DO NOT USE ANYMORE (SHA-1 IS DEPRECATED), UEFI-Spec:
 * This identifies a signature containing a RSA-2048 signature of a SHA-1 hash. The SignatureHeader size shall always
 * be 0. The SignatureSize shall always be 16 (size of SignatureOwner component) + 256 bytes.
 */
#define EFI_CERT_RSA2048_SHA1_GUID                          { 0x67f8444f, 0x8743, 0x48f1, { 0xa3, 0x28, 0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80 } } // see type 'GUID' below

/** UEFI-Spec:
 * This identifies a signature based on a DER-encoded X.509 certificate. If the signature is an X.509 certificate then
 * verification of the signature of an image should validate the public key certificate in the image using certificate path
 * verification, up to this X.509 certificate as a trusted root. If the signature is in a device signature variable, this signature
 * is one root certificate authority (CA) certificate or an intermediate certificate for the device. The SignatureHeader size
 * shall always be 0. The SignatureSize may vary but shall always be 16 (size of the SignatureOwner component) + the
 * size of the certificate itself.
 * NOTE: This means that each certificate will normally be in a separate EFI_SIGNATURE_LIST.
 */
#define EFI_CERT_X509_GUID                                  { 0xa5c059a1, 0x94e4, 0x4aa7, { 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72 } } // see type 'GUID' below

/**
 * This identifies a signature containing a SHA-224 hash. The SignatureHeader size shall always be 0. The SignatureSize
 * shall always be 16 (size of SignatureOwner component) + 28 bytes.
 */
#define EFI_CERT_SHA224_GUID                                { 0xb6e5233, 0xa65c, 0x44c9, { 0x94, 0x07, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd } } // see type 'GUID' below

/**
* This identifies a signature containing a SHA-384 hash. The SignatureHeader size shall always be 0. The SignatureSize
* shall always be 16 (size of SignatureOwner component) + 48 bytes.
*/
#define EFI_CERT_SHA384_GUID                                { 0xff3e5307, 0x9fd0, 0x48c9,  {0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01 } } // see type 'GUID' below

/**
 * This identifies a signature containing a SHA-512 hash. The SignatureHeader size shall always be 0. The SignatureSize
 * shall always be 16 (size of SignatureOwner component) + 64 bytes.
 */
#define EFI_CERT_SHA512_GUID                                { 0x93e0fae, 0xa6c4, 0x4f50, { 0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a } } // see type 'GUID' below

#define EFI_CERT_X509_SHA256_GUID                           { 0x3bd2a492, 0x96c0, 0x4079, { 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed } } // see type 'GUID' below

/**
 * Members
 * ToBeSignedHash       The SHA256 hash of an X.509 certificate’s To-Be-Signed contents.
 * TimeOfRevocation     The time that the certificate shall be considered to be revoked.
 * This identifies a signature containing the SHA256 hash of an X.509 certificate’s To-Be-Signed contents, and a
 * time of revocation. If the signature is in a device signature variable, this signature is a SHA256 hash of a root
 * certificate authority (CA) certificate or an intermediate certificate for the device. The SignatureHeader size shall
 * always be 0. The SignatureSize shall always be 16 (size of the SignatureOwner component) + 48 bytes for an
 * EFI_CERT_X509_SHA256 structure. If the TimeOfRevocation is non-zero, the certificate should be considered
 * to be revoked from that time and onwards, and otherwise the certificate shall be considered to always be revoked.
 */
typedef struct __attribute__((packed)) _EFI_CERT_X509_SHA256
{
  EFI_SHA256_HASH   ToBeSignedHash;
  EFI_TIME          TimeOfRevocation;
} EFI_CERT_X509_SHA256;

/**
 * Members
 * ToBeSignedHash       The SHA384 hash of an X.509 certificate’s To-Be-Signed contents.
 * TimeOfRevocation     The time that the certificate shall be considered to be revoked.
 *
 * This identifies a signature containing the SHA384 hash of an X.509 certificate’s To-Be-Signed contents, and a time
 * of revocation. If the signature is in a device signature variable, this signature is a SHA384 hash of a root certificate
 * authority (CA) certificate or an intermediate certificate for the device. The SignatureHeader size shall always be 0. The
 * SignatureSize shall always be 16 (size of the SignatureOwner component) + 64 bytes for an EFI_CERT_X509_SHA384
 * structure. If the TimeOfRevocation is non-zero, the certificate should be considered to be revoked from that time and
 * onwards, and otherwise the certificate shall be considered to always be revoked.
 */
#define EFI_CERT_X509_SHA384_GUID                           { 0x7076876e, 0x80c2, 0x4ee6, { 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b } } // see type 'GUID' below

typedef struct __attribute__((packed)) _EFI_CERT_X509_SHA384
{
  EFI_SHA384_HASH   ToBeSignedHash;
  EFI_TIME          TimeOfRevocation;
} EFI_CERT_X509_SHA384;

/**
 * Members
 * ToBeSignedHash
 * The SHA512 hash of an X.509 certificate’s To-Be-Signed contents.
 * TimeOfRevocation
 * The time that the certificate shall be considered to be revoked.
 * This identifies a signature containing the SHA512 hash of an X.509 certificate’s To-Be-Signed contents, and a time
 * of revocation. If the signature is in a device signature variable, this signature is a SHA512 hash of a root certificate
 * authority (CA) certificate or an intermediate certificate for the device. The SignatureHeader size shall always be 0. The
 * SignatureSize shall always be 16 (size of the SignatureOwner component) + 80 bytes for an EFI_CERT_X509_SHA512
 * structure. If the TimeOfRevocation is non-zero, the certificate should be considered to be revoked from that time and
 * onwards, and otherwise the certificate shall be considered to always be revoked.
 */
#define EFI_CERT_X509_SHA512_GUID                           { 0x446dbf63, 0x2502, 0x4cda, { 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d } } // see type 'GUID' below

typedef struct __attribute__((packed)) _EFI_CERT_X509_SHA512
{
  EFI_SHA512_HASH   ToBeSignedHash;
  EFI_TIME          TimeOfRevocation;
} EFI_CERT_X509_SHA512;

#define EFI_VAR_ATTR_NON_VOLATILE                           0x00000001
#define EFI_VAR_ATTR_BOOTSERVICE_ACCESS                     0x00000002
#define EFI_VAR_ATTR_RUNTIME_ACCESS                         0x00000004
#define EFI_VAR_ATTR_HARDWARE_ERROR_RECORD                  0x00000008
#define EFI_VAR_ATTR_AUTHENTICATED_WRITE_ACCESS             0x00000010
#define EFI_VAR_ATTR_TIME_BASED_AUTHENTICATED_WRITE_ACCESS  0x00000020  ///< see EFI_VARIABLE_AUTHENTICATION_2
#define EFI_VAR_ATTR_APPEND_WRITE                           0x00000040
#define EFI_VAR_ATTR_ENHANCED_AUTHENTICATED_ACCESS          0x00000080  ///< see EFI_VARIABLE_AUTHENTICATION_3

/* from the UEFI specification, version 2.10 */

// textual GUID is: aabbccdd-eeff-gghh-iijj-kkllmmnnoopp

typedef struct __attribute__((packed, aligned(16))) _GUID
{
  uint32_t      Data1;
  uint16_t      Data2;
  uint16_t      Data3;
  uint8_t       Data4[8];
} GUID;

#define ZERO_GUID { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } }

typedef uint8_t __attribute__((aligned(16))) EFI_GUID[16];

typedef struct __attribute__((packed)) _EFI_CRYPTO_INDICATION
{
  uint32_t                            Version;
  uint32_t                            Length;
  uint64_t                            HashAlgorithmBitmap;
  uint64_t                            AsymAlgorithmBitmap;
} EFI_CRYPTO_INDICATION;

#define EFI_CRYPTO_INDICATION_VERSION_1                 0x00000001

#define EFI_CRYPTO_INDICATION_HASH_SHA_256              0x01
#define EFI_CRYPTO_INDICATION_HASH_SHA_384              0x02

#define EFI_CRYPTO_INDICATION_HASH_SHIFT                16

#define EFI_CRYPTO_INDICATION_ASYM_RSASSA_2048          0x01
#define EFI_CRYPTO_INDICATION_ASYM_RSASSA_3072          0x02
#define EFI_CRYPTO_INDICATION_ASYM_RSASSA_4096          0x04

#define EFI_CRYPTO_INDICATION_ASYM_RSAPSS_2048          0x08    // not in spec!
#define EFI_CRYPTO_INDICATION_ASYM_RSAPSS_3072          0x10
#define EFI_CRYPTO_INDICATION_ASYM_RSAPSS_4096          0x20

#define EFI_CRYPTO_INDICATION_ASYM_ECDSA_ECC_NIST_P256  0x40
#define EFI_CRYPTO_INDICATION_ASYM_ECDSA_ECC_NIST_P384  0x80

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

typedef struct __attribute__((packed))
{
  uint32_t  dwLength;
  uint16_t  wRevision;
  uint16_t  wCertificateType;
  uint8_t   bCertificate[0];
} WIN_CERTIFICATE;

#pragma GCC diagnostic pop

#define SHA256_DIGEST_SIZE        32
#define SHA384_DIGEST_SIZE        48
#define SHA512_DIGEST_SIZE        64

typedef uint8_t   EFI_SHA256_HASH[SHA256_DIGEST_SIZE];
typedef uint8_t   EFI_SHA384_HASH[SHA384_DIGEST_SIZE];
typedef uint8_t   EFI_SHA512_HASH[SHA512_DIGEST_SIZE];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

typedef struct __attribute__((packed))
{
  EFI_GUID          SignatureOwner;
  uint8_t           SignatureData[0];
} EFI_SIGNATURE_DATA;

#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

typedef struct __attribute__((packed))
{
  EFI_GUID            SignatureType;
  uint32_t            SignatureListSize;
  uint32_t            SignatureHeaderSize;
  uint32_t            SignatureSize;
  uint8_t             SignatureHeader[0];
  ///
  /// Header before the array of signatures. The format of this header is specified
  /// by the SignatureType.
  /// UINT8           SignatureHeader[SignatureHeaderSize];
  ///
  /// An array of signatures. Each signature is SignatureSize bytes in length.
  /// EFI_SIGNATURE_DATA Signatures[][SignatureSize];
  ///
} EFI_SIGNATURE_LIST;

#pragma GCC diagnostic pop

#define WIN_CERT_TYPE_X509              0x0001      ///< The bCertificate member contains an X.509 certificate
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA  0x0002      ///< [UEFI spec] The bCertificate member contains a PKCS SignedData structure
#define WIN_CERT_TYPE_RESERVED_1        0x0003      ///< Reserved
#define WIN_CERT_TYPE_PKCS1_SIGN        0x0009      ///< The bCertificate member contains PKCS1_MODULE_SIGN fields
#define WIN_CERT_TYPE_EFI_PKCS115       0x0EF0      ///< [UEFI spec]
#define WIN_CERT_TYPE_EFI_GUID          0x0EF1      ///< [UEFI spec]

#define WIN_CERT_REVISION_1_0           0x0100      ///< LEGACY!!!
#define WIN_CERT_REVISION_2_0           0x0200      ///< current version

typedef struct __attribute__((packed))
{
  EFI_GUID      HashType;
  uint8_t       PublicKey[256];
  uint8_t       Signature[256];
} EFI_CERT_BLOCK_RSA_2048_SHA256;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

typedef struct __attribute__((packed))
{
  WIN_CERTIFICATE   Hdr;
  EFI_GUID          CertType;
  uint8_t           CertData[0];
} WIN_CERTIFICATE_UEFI_GUID;

typedef struct __attribute__((packed))
{
  WIN_CERTIFICATE Hdr;
  EFI_GUID        HashAlgorithm;
  uint8_t         Signature[0];
} WIN_CERTIFICATE_EFI_PKCS1_15;

#pragma GCC diagnostic pop

typedef struct __attribute__((packed))
{
  uint64_t                    MonotonicCount;
  WIN_CERTIFICATE_UEFI_GUID   AuthInfo;
} EFI_VARIABLE_AUTHENTICATION;

typedef struct __attribute__((packed))
{
  EFI_TIME                    TimeStamp;
  WIN_CERTIFICATE_UEFI_GUID   AuthInfo;
} EFI_VARIABLE_AUTHENTICATION_2;

#define EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE    1
#define EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE        2

typedef struct __attribute__((packed))
{
  uint8_t                     Version;      ///< currently hardcoded to 0x01 (according to UEFI spec 2.10)
  uint8_t                     Type;         ///< can be either EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE(1) or EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE(2)
  uint32_t                    MetadataSize;
  uint32_t                    Flags;
} EFI_VARIABLE_AUTHENTICATION_3;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

typedef struct __attribute__((packed))
{
  uint32_t                    NonceSize;
  uint8_t                     Nonce[0];
} EFI_VARIABLE_AUTHENTICATION_3_NONCE;

#pragma GCC diagnostic pop

#define EFI_CERT_TYPE_RSA2048_SHA256_GUID                   { 0xa7717414, 0xc616, 0x4977, {0x94, 0x20, 0x84, 0x47, 0x12, 0xa7, 0x35, 0xbf} }
#define EFI_CERT_TYPE_PKCS7_GUID                            { 0x4aafd29d, 0x68df, 0x49ee, {0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7} }

#define GUID_EFI_GLOBAL_VARIABLE                            "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define GUID_EFI_IMAGE_SECURITY_DATABASE                    "d719b2cb-3d3a-4596-a3bc-dad00e67656f"

#define _UEFI_VARIABLE_AUDITMODE                            "AuditMode"
#define _UEFI_VARIABLE_BOOT_NNNN                            "Boot%04u"
#define _UEFI_VARIABLE_BOOTCURRENT                          "BootCurrent"
#define _UEFI_VARIABLE_BOOtOPTIONSUPPORT                    "BootOptionSupport"
#define _UEFI_VARIABLE_BOOTORDER                            "BootOrder"
#define _UEFI_VARIABLE_CRYPTOINDICATIONS                    "CryptoIndications"
#define _UEFI_VARIABLE_CRYPTOINDICATIONSSUPPORTED           "CryptoIndicationsSupported"
#define _UEFI_VARIABLE_CRYPTOINDICATIONSACTIVATED           "CryptoIndicationsActivated"
#define _UEFI_VARIABLE_DB                                   "db"
#define _UEFI_VARIABLE_DBX                                  "dbx"
#define _UEFI_VARIABLE_DBDEFAULT                            "dbDefault"
#define _UEFI_VARIABLE_DBXDEFAULT                           "dbxDefault"
#define _UEFI_VARIABLE_DEPLOYEDMODE                         "DeployedMode"
#define _UEFI_VARIABLE_KEK                                  "KEK"
#define _UEFI_VARIABLE_KEKDEFAULT                           "KEKDefault"
#define _UEFI_VARIABLE_PK                                   "PK"
#define _UEFI_VARIABLE_PKDEFAULT                            "PKDefault"
#define _UEFI_VARIABLE_SECUREBOOT                           "SecureBoot"
#define _UEFI_VARIABLE_SETUPMODE                            "SetupMode"
#define _UEFI_VARIABLE_SIGNATURSUPPORT                      "SignatureSupport"

#define UEFI_VARIABLE_AUDITMODE                             _UEFI_VARIABLE_AUDITMODE "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_BOOT_NNNN                             _UEFI_VARIABLE_BOOT_NNNN "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_BOOTCURRENT                           _UEFI_VARIABLE_BOOTCURRENT "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_BOOtOPTIONSUPPORT                     _UEFI_VARIABLE_BOOtOPTIONSUPPORT "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_BOOTORDER                             _UEFI_VARIABLE_BOOTORDER "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_CRYPTOINDICATIONS                     _UEFI_VARIABLE_CRYPTOINDICATIONS "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_CRYPTOINDICATIONSACTIVATED            _UEFI_VARIABLE_CRYPTOINDICATIONSACTIVATED "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_CRYPTOINDICATIONSSUPPORTED            _UEFI_VARIABLE_CRYPTOINDICATIONSSUPPORTED "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_DB                                    _UEFI_VARIABLE_DB "-" GUID_EFI_IMAGE_SECURITY_DATABASE
#define UEFI_VARIABLE_DBX                                   _UEFI_VARIABLE_DBX "-" GUID_EFI_IMAGE_SECURITY_DATABASE
#define UEFI_VARIABLE_DBDEFAULT                             _UEFI_VARIABLE_DBDEFAULT "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_DBXDEFAULT                            _UEFI_VARIABLE_DBXDEFAULT "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_DEPLOYEDMODE                          _UEFI_VARIABLE_DEPLOYEDMODE "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_KEK                                   _UEFI_VARIABLE_KEK "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_KEKDEFAULT                            _UEFI_VARIABLE_KEKDEFAULT "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_PK                                    _UEFI_VARIABLE_PK "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_PKDEFAULT                             _UEFI_VARIABLE_PKDEFAULT "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_SECUREBOOT                            _UEFI_VARIABLE_SECUREBOOT "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_SETUPMODE                             _UEFI_VARIABLE_SETUPMODE "-" GUID_EFI_GLOBAL_VARIABLE
#define UEFI_VARIABLE_SIGNATURSUPPORT                       _UEFI_VARIABLE_SIGNATURSUPPORT "-" GUID_EFI_GLOBAL_VARIABLE

#define X509_KEY_TYPE_UNKNOWN     0
#define X509_KEY_TYPE_RSA         1
#define X509_KEY_TYPE_EC          2
#define X509_KEY_TYPE_ED25519     3
#define X509_KEY_TYPE_ED448       4

typedef struct _x509_information        x509_info, *x509_info_ptr;

struct _x509_information
{
  char                serialno[128];  ///< printed decimal serial number
  char                notBefore[32];  ///< printed notBefore date
  char                notAfter[32];   ///< printed notAfter date
  char                subjectDN[512]; ///< printed subject distinguished name
  char                issuerDN[512];  ///< printed issuer distinguished name (matches subjectDN if self-signed or self-issued (cross), respectively)
  uint32_t            key_type;       ///< X509_KEY_TYPE_xxx constants (see above)
  uint32_t            key_bit_size;   ///< 0 if unknown
};

/**
 * @brief mounts the efivarfs (if not already mounted)
 *
 * @param [in]      efivarfs_mountpoint       pointer to folder, default: "/sys/firmware/efi/efivarfs"
 *
 * @return true if OK, false on error
 */
bool efivarfs_mount ( const char *efivarfs_mountpoint );

/**
 * @brief un-mounts the efivarfs (if this application has mounted it)
 *
 * @param [in]      efivarfs_mountpoint       pointer to folder, default: "/sys/firmware/efi/efivarfs"
 */
void efivarfs_umount ( const char *efivarfs_mountpoint );

/**
 * @brief returns either offset 0 or 4. If an ESL file was read from the EFIVARFS, then
 *        the first four bytes contain the EFI variable attributes in LITTLE ENDIAN.
 *        Only one byte is currently used, which means that offsets [1], [2], and [3]
 *        are always zero (0x00). On the other hand, there is no GUID with three zero(s)
 *        right after the first byte.
 *        It is safe to just inspect the three bytes at [1..3] (at least currently).
 *        Otherwise, we could compare several GUIDs to see if the data offset is zero or
 *        four... (a TODO???)
 *
 * @param [in]      esl_data      pointer to ESL data (EFI SIGNATURE LIST)
 * @param [in]      esl_size      size of the file in bytes
 * @param [in/out]  signer_info   (OPTIONAL, may be NULL): pointer to an X.509 information
 *                                structure filled with the PKCS#7 signer information if
 *                                this is not an ESL but an AUTH file.
 *
 * @return either zero (0) if 'bare' ESL file or four (4) if EFI attributes in first
 *         four bytes (always LITTLE ENDIAN).
 */
uint32_t esl_file_get_offset ( const uint8_t *esl_data, uint32_t esl_size, x509_info_ptr signer_info );

#define SIGTYPE_ERROR                           0
#define SIGTYPE_UNKNOWN                         1
#define SIGTYPE_EFI_CERT_RSA2048_GUID           2
#define SIGTYPE_EFI_CERT_RSA2048_SHA1_GUID      3
#define SIGTYPE_EFI_CERT_RSA2048_SHA256_GUID    4
#define SIGTYPE_EFI_CERT_SHA1_GUID              5
#define SIGTYPE_EFI_CERT_SHA224_GUID            6
#define SIGTYPE_EFI_CERT_SHA256_GUID            7
#define SIGTYPE_EFI_CERT_SHA384_GUID            8
#define SIGTYPE_EFI_CERT_SHA512_GUID            9
#define SIGTYPE_EFI_CERT_X509_GUID              10
#define SIGTYPE_EFI_CERT_X509_SHA256_GUID       11
#define SIGTYPE_EFI_CERT_X509_SHA384_GUID       12
#define SIGTYPE_EFI_CERT_X509_SHA512_GUID       13

/**
 * @brief retrieves the type of the signature as a numeric constant
 *
 * @param [in/out]  esl_data        pointer to ESL
 * @param [in]      esl_index       zero-based index in esl_data
 * @param [in]      esl_size        sizeof ESL in bytes
 *
 * @eturn one of the SIGTYPE_xxx constants (see above)
 */
uint32_t esl_get_signature_type ( const uint8_t *esl_data, uint32_t esl_index, uint32_t esl_size );

/**
 * @brief retrieves the textual description of an EFI signature type
 *
 * @param [in]      index           an index, which is a SIGTYPE_xxx constant
 *
 * @return "(null)" on error or the pointer to the zero-terminated description string
 */
const char *esl_get_signature_description ( uint32_t index );

/**
 * @brief retrieves the file infix (for building file names) of an EFI signature type
 *
 * @param [in]      index           an index, which is a SIGTYPE_xxx constant
 *
 * @return "(null)" on error or the pointer to the zero-terminated file infix string
 */
const char *esl_get_signature_file_infix ( uint32_t index );

/**
 * @brief retrieves the EFI signature size in bytes; (uint32_t)-1 means X.509v3 DER-encoding
 *
 * @param [in]      index           an index, which is a SIGTYPE_xxx constant
 *
 * @return 0 on error, -1 if X.509 DER (determine size from TLV), size in bytes otherwise.
 */
uint32_t esl_get_signature_size ( uint32_t index );

/**
 * @brief formats a GUID in memory as a human-readable string
 *
 * @param [in]      guid              pointer to 16 bytes
 * @param [in/out]  buffer            pointer to string buffer
 * @param [in]      buffer_size       number of bytes available in string buffer
 * @param [in]      with_curly_braces true to surround the GUID with curlys
 *
 * @return true on success, false otherwise; because the output is always zero-terminated,
 *         either 37 (no curlys) or 41 (with curlys) bytes are required in buffer.
 */
bool format_guid (const uint8_t *guid, char *buffer, uint32_t buffer_size, bool with_curly_braces );

/**
 * @brief extracts the X.509v3 digital certificate size (only DER-encoding supported!)
 *
 * This function works for any ASN.1 DER encoding (X.690) beginning with a tag 0x30
 * (SEQUENCE(0x10) | CONSTRUCTED(0x20)).
 *
 * @param [in]      cert_data         pointer to DER-encoding
 * @param [in]      cert_size         size of DER-encoding area (may be greater than the X.509 size)
 *
 * @return 0 on error or the size of the X.509v3 certificate in bytes.
 */
uint32_t x509_get_certificate_size ( const uint8_t *cert_data, uint32_t cert_size );

/**
 * @brief Extracts certain (human-readable) information items from an X.509 certificate.
 *
 * @param [in/out]  x509_data       either DER-encoding or an X509* (OpenSSL), see next param
 * @param [in]      x509_size       if 0 specified, then x509_data is interpreted as an OpenSSL
 *                                  X509*, otherwise, this is the size in bytes of the DER encoding
 * @param [in/out]  info            pointer to a user-supplied structure filled with information on
 *                                  OUT
 *
 * @return true (success), false on error.
 */
bool x509_get_information ( const uint8_t *x509_data, uint32_t x509_size, x509_info_ptr info );

#ifdef __cplusplus
}
#endif

#endif // _INC_UEFI_H_

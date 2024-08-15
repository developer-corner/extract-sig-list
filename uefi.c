/**
 * @file   uefi.c
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  functions for working with UEFI stuff (please refer to the
 *         UEFI specification, version 2.10 for details)
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

#include <uefi.h>

static bool g_have_mounted_efivarfs = false;

bool efivarfs_mount ( const char *efivarfs_mountpoint )
{
  char            testfile[256];

  snprintf(testfile, sizeof(testfile), "%s/" UEFI_VARIABLE_SECUREBOOT, efivarfs_mountpoint);

  if (0 == access(testfile, F_OK))
    return true;

  if (0 != mount("none",efivarfs_mountpoint,"efivarfs", MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID,NULL))
    return false; // either has to be root or CAP_SYS_ADMIN required or EFIVARFS is simply not in the kerne

  if (0 != access(testfile, F_OK))
  {
    umount(efivarfs_mountpoint);
    return false;
  }

  g_have_mounted_efivarfs = true;

  return true;
}

void efivarfs_umount ( const char *efivarfs_mountpoint )
{
  if (g_have_mounted_efivarfs)
  {
    umount(efivarfs_mountpoint);
    g_have_mounted_efivarfs = false;
  }
}

uint32_t esl_file_get_offset ( const uint8_t *esl_data, uint32_t esl_size, x509_info_ptr signer_info )
{
  const uint8_t        *try_data;
  uint32_t              try_size, pkcs7_size;
  WIN_CERTIFICATE      *win_cert;
  static const GUID     efiCertTypePkcs7Guid = EFI_CERT_TYPE_PKCS7_GUID;
  const uint8_t        *pkcs7_der_ptr;
  PKCS7                *pkcs7;
  BIO                  *membio;
  STACK_OF(X509)       *signers;
  X509                 *signer_cert;

  if (NULL == esl_data || esl_size < 4)
    return 0;

  if (NULL != signer_info)
    memset(signer_info, 0, sizeof(x509_info));

  // #1: Check if the file starts with the EFI variable attributes (Little Endian, 32bit, one byte, followed by three zero bytes - currently)

  if  (0x00 == esl_data[1] && 0x00 == esl_data[2] && 0x00 == esl_data[3])
    return 4; // this is an ESL file, the first four bytes filled with EFI variable attributes (most likely read from /sys/firmware/efi/efivars dir)

  // #2: Check if this is an AUTHENTICATION_2 structure (the file is an .auth file)
  //
  // EFI_TIME                   TimeStamp
  // WIN_CERTIFICATE_UEFI_GUID  AuthInfo:
  // .... WIN_CERTIFICATE           Hdr:
  // ........  uint32_t  dwLength;
  // ........  uint16_t  wRevision;
  // ........  uint16_t  wCertificateType;
  // ........  uint8_t   bCertificate[0];         <== PKCS#7 SignedData
  // .... EFI_GUID                  CertType
  // .... uint8_t                   CertData[]:
  // ==========================================================================
  // CertData is:
  //
  // UTF-16 variable name
  // GUID variable GUID
  // uint32_t attributes
  // EFI_TIME timestamp
  // data[data_len] ==> THIS IS THE ESL WE ARE LOOKING FOR

#if 0 // THIS IS AN EXAMPLE OF A REAL-LIFE .auth file (some intermediate data cut!)

  00000000  E8 07 07 1E 0E 2F 1C 00 00 00 00 00 00 00 00 00  è..../..........     EFI_TIME, the TimeStamp

  00000010  8E 05 00 00 00 02 F1 0E   9D D2 AF 4A DF 68 EE 49  Ž.....ñ..Ò¯JßhîI     WIN_CERTIFICATE with dwLength=0x058E, wRevision = 0x0200, wCertificateType = 0x0EF1

  EFI_GUID = 9D D2 AF 4A DF 68 EE 49 8A A9 34 7D 37 56 65 A7

  00000020  8A A9 34 7D 37 56 65 A7

  bCertificate[<variable size>] containts the PKCS#7 data: tag 0x30, length 0x82,0x05,0x72 => Length 0x0572 (Big Endian because ASN.1)

                                    30 82 05 72 06 09 2A 86  Š©4}7Ve§0‚.r..*†
  00000030  48 86 F7 0D 01 07
  [...]
  00000590  79 4E EC C3 57 51 6D 84 7E BC 33 85 87 CA
                                                      A1 59  yNìÃWQm„~¼3…‡Ê¡Y     Offset 0x059E (0x2C+0x572) This is SignatureType of EFI_SIGNATURE_LIST
  000005A0  C0 A5 E4 94 A7 4A 87 B5 AB 15 5C 2B F0 72
                                                      C3 03  À¥ä”§J‡µ«.\+ðrÃ.
  000005B0  00 00  00000000  A7030000     4C DB 9D 31 95 0F  ......§...LÛ.1•.
  000005C0  8A 4F A9 02 6A B2 4B 90 5A 41 30 82 03 93 30 82  ŠO©.j²K.ZA0‚.“0‚
  [...]
  00000950  62 39 11 AA 67 01 7F 4B 7B 69 B4 7C D9 B3 91 3F  b9.ªg..K{i´|Ù³‘?
  00000960  B1                                               ±

#endif

  try_data = esl_data;
  try_size = esl_size;

  if (try_size < sizeof(EFI_TIME))
    goto CheckAuth3;
  try_data += sizeof(EFI_TIME);

  if (try_size < sizeof(WIN_CERTIFICATE_UEFI_GUID)) // this is 'AuthInfo'
    goto CheckAuth3;

  if ((*((uint32_t*)try_data)) < sizeof(WIN_CERTIFICATE))
    goto CheckAuth3;

  win_cert = (WIN_CERTIFICATE*)try_data;

  if (WIN_CERT_REVISION_2_0 != win_cert->wRevision) // 0x0200
    goto CheckAuth3;

  if (/* WIN_CERT_TYPE_PKCS_SIGNED_DATA != win_cert->wCertificateType && // 0x0002
         WIN_CERT_TYPE_EFI_PKCS115 != win_cert->wCertificateType &&      // 0x0EF0 */
         WIN_CERT_TYPE_EFI_GUID != win_cert->wCertificateType)           // 0x0EF1
    goto CheckAuth3;

  if (memcmp(&efiCertTypePkcs7Guid, &win_cert->bCertificate, sizeof(GUID)))
    goto CheckAuth3;

  // function's name is 'x509_get_certificate_size' but this also works for PKCS#7 SignedData
  // because it is also just an ASN.1 SEQUENCE (0x30 = 0x10 | CONSTRUCTED)...

  pkcs7_der_ptr = win_cert->bCertificate + sizeof(GUID);
  pkcs7_size = x509_get_certificate_size( pkcs7_der_ptr , esl_size - sizeof(EFI_TIME) - sizeof(WIN_CERTIFICATE) - sizeof(GUID));
  if (0 == pkcs7_size)
    goto CheckAuth3;

  if (NULL != signer_info)
  {
    membio = BIO_new_mem_buf((void*)pkcs7_der_ptr, pkcs7_size);
    if (NULL == membio)
      goto CheckAuth3;

    pkcs7 = d2i_PKCS7_bio(membio, NULL);

    if (NULL == pkcs7)
    {
      BIO_free(membio);
      goto CheckAuth3;
    }

    BIO_free(membio);

    signers = PKCS7_get0_signers(pkcs7,NULL,0);

    if (NULL != signers)
    {
      if (1 == sk_X509_num(signers)) // we support one single signer only
      {
        signer_cert = sk_X509_value(signers, 0); // get the X.509 certificate
        if (NULL != signer_cert)
        {
          if (!x509_get_information((const uint8_t*)signer_cert, 0, signer_info))
            memset(signer_info, 0, sizeof(x509_info));
        }
      }
      sk_X509_free(signers);
    }

    PKCS7_free(pkcs7);
  }

  // the ESL itself (EFI_SIGNATURE_LIST) is the trailing item in a .auth file, so just return its offset:

  return sizeof(EFI_TIME) + sizeof(WIN_CERTIFICATE) + sizeof(GUID) + pkcs7_size;

  // #3: Check if this is an AUTHENTICATION_3 structure (the file is also an .auth file)

CheckAuth3:

  // TODO: NOT YET IMPLEMENTED

  // #4: Otherwise assume that this is just a 'bare' ESL file starting with a GUID

  return 0; // offset is zero in this case
}

static const struct
{
  GUID          guid;
  uint32_t      sigsize;
  char          file_infix[32];
  char          desc[256];
} signature_type_table[] =
{
  { ZERO_GUID                   , 0                 , ""                  , "" },
  { ZERO_GUID                   , 0                 , ""                  , "" },
  { EFI_CERT_RSA2048_GUID       , 256               , "RSA2048_MOD"       , "RSA public modulus n (2048bit), e always 65.537" },
  { EFI_CERT_RSA2048_SHA1_GUID  , SHA1_DIGEST_SIZE  , "SHA1_RSA2048_MOD"  , "SHA-1 over RSA public modulus n (2048bit), e always 65.537 - DEPRECATED" },
  { EFI_CERT_RSA2048_SHA256_GUID, SHA256_DIGEST_SIZE, "SHA256_RSA2048_MOD","SHA-256 over RSA public modulus n (2048bit), e always 65.537" },
  { EFI_CERT_SHA1_GUID          , SHA1_DIGEST_SIZE  , "SHA1"              , "SHA-1 hash - DEPRECATED" },
  { EFI_CERT_SHA224_GUID        , SHA224_DIGEST_SIZE, "SHA224"            , "SHA-224 hash" },
  { EFI_CERT_SHA256_GUID        , SHA256_DIGEST_SIZE, "SHA256"            , "SHA-256 hash" },
  { EFI_CERT_SHA384_GUID        , SHA384_DIGEST_SIZE, "SHA384"            , "SHA-384 hash" },
  { EFI_CERT_SHA512_GUID        , SHA512_DIGEST_SIZE, "SHA512"            , "SHA-512 hash" },
  { EFI_CERT_X509_GUID          , ((uint32_t)-1)    , "X509"              , "ITU-T X.509 certificate (DER-encoded)" },
  { EFI_CERT_X509_SHA256_GUID   , SHA256_DIGEST_SIZE, "SHA256_TBS_X509"   , "SHA-256 of TBS of ITU-T X.509 certificate" },
  { EFI_CERT_X509_SHA384_GUID   , SHA384_DIGEST_SIZE, "SHA384_TBS_X509"   , "SHA-384 of TBS of ITU-T X.509 certificate" },
  { EFI_CERT_X509_SHA512_GUID   , SHA512_DIGEST_SIZE, "SHA512_TBS_X509"   , "SHA-512 of TBS of ITU-T X.509 certificate" }
};

uint32_t esl_get_signature_type ( const uint8_t *esl_data, uint32_t esl_index, uint32_t esl_size )
{
  uint32_t          i;

  if (NULL == esl_data || (esl_index + sizeof(GUID)) > esl_size)
    return SIGTYPE_ERROR;

  for (i = 2; i < sizeof(signature_type_table) / sizeof(signature_type_table[0]); i++)
  {
    if (!memcmp(esl_data + esl_index, &signature_type_table[i].guid, sizeof(GUID)))
      return i;
  }

  return SIGTYPE_UNKNOWN;
}

const char *esl_get_signature_description ( uint32_t index )
{
  if (index >= (sizeof(signature_type_table) / sizeof(signature_type_table[0])))
    return "(null)";

  return signature_type_table[index].desc;
}

const char *esl_get_signature_file_infix ( uint32_t index )
{
  if (index >= (sizeof(signature_type_table) / sizeof(signature_type_table[0])))
    return "(null)";

  return signature_type_table[index].file_infix;
}

uint32_t esl_get_signature_size ( uint32_t index )
{
  if (index >= (sizeof(signature_type_table) / sizeof(signature_type_table[0])))
    return 0;

  return signature_type_table[index].sigsize;
}

bool format_guid (const uint8_t *guid, char *buffer, uint32_t buffer_size, bool with_curly_braces )
{
  static const char hex_digits[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
  uint32_t          ofs;

  if (NULL == guid || NULL == buffer || 0 == buffer_size)
    return false;

  if (!with_curly_braces)
  {
    if (buffer_size < 37)
      return false;

    ofs = 0;
    buffer[36] = 0x00;
  }
  else
  {
    if (buffer_size < 41)
      return false;

    buffer[ 0] = '{';
    buffer[ 1] = ' ';
    buffer[38] = ' ';
    buffer[39] = '}';
    buffer[40] = 0x00;

    ofs = 2;
  }

  buffer[ofs+0 ] = hex_digits[guid[3]>>4];
  buffer[ofs+1 ] = hex_digits[guid[3]&15];
  buffer[ofs+2 ] = hex_digits[guid[2]>>4];
  buffer[ofs+3 ] = hex_digits[guid[2]&15];
  buffer[ofs+4 ] = hex_digits[guid[1]>>4];
  buffer[ofs+5 ] = hex_digits[guid[1]&15];
  buffer[ofs+6 ] = hex_digits[guid[0]>>4];
  buffer[ofs+7 ] = hex_digits[guid[0]&15];
  buffer[ofs+8 ] = '-';

  buffer[ofs+9 ] = hex_digits[guid[5]>>4];
  buffer[ofs+10] = hex_digits[guid[5]&15];
  buffer[ofs+11] = hex_digits[guid[4]>>4];
  buffer[ofs+12] = hex_digits[guid[4]&15];
  buffer[ofs+13] = '-';

  buffer[ofs+14] = hex_digits[guid[7]>>4];
  buffer[ofs+15] = hex_digits[guid[7]&15];
  buffer[ofs+16] = hex_digits[guid[6]>>4];
  buffer[ofs+17] = hex_digits[guid[6]&15];
  buffer[ofs+18] = '-';

  buffer[ofs+19] = hex_digits[guid[8]>>4];
  buffer[ofs+20] = hex_digits[guid[8]&15];
  buffer[ofs+21] = hex_digits[guid[9]>>4];
  buffer[ofs+22] = hex_digits[guid[9]&15];
  buffer[ofs+23] = '-';

  buffer[ofs+24] = hex_digits[guid[10]>>4];
  buffer[ofs+25] = hex_digits[guid[10]&15];
  buffer[ofs+26] = hex_digits[guid[11]>>4];
  buffer[ofs+27] = hex_digits[guid[11]&15];
  buffer[ofs+28] = hex_digits[guid[12]>>4];
  buffer[ofs+29] = hex_digits[guid[12]&15];
  buffer[ofs+30] = hex_digits[guid[13]>>4];
  buffer[ofs+31] = hex_digits[guid[13]&15];
  buffer[ofs+32] = hex_digits[guid[14]>>4];
  buffer[ofs+33] = hex_digits[guid[14]&15];
  buffer[ofs+34] = hex_digits[guid[15]>>4];
  buffer[ofs+35] = hex_digits[guid[15]&15];

  return true;
}

uint32_t x509_get_certificate_size ( const uint8_t *cert_data, uint32_t cert_size )
{
  uint32_t        x509_size = 0, idx = 0, num_len_bytes;

  if (NULL == cert_data || cert_size < 2)
    return 0;

  if (0x30 != cert_data[idx++]) // this is the ASN.1 tag: SEQUENCE(0x10) | CONSTRUCTED (0x20)
    return 0;

  x509_size = (uint32_t)cert_data[idx++];
  if (0x80 == (x509_size & 0x80))
  {
    num_len_bytes = x509_size & 0x7F;

    if (0 == num_len_bytes) // this is X.690 BER -> NOT SUPPORTED HERE
      return 0;

    if (num_len_bytes > 3) // this would be already VERY VERY big certificates..
      return 0;

    if ((idx + num_len_bytes) > cert_size) // ran out of data
      return 0;

    switch(num_len_bytes)
    {
      case 1:
        x509_size = (uint32_t)cert_data[idx++];
        break;
      case 2:
        x509_size = (((uint32_t)cert_data[idx])<<8) | ((uint32_t)cert_data[idx + 1]);
        idx += 2;
        break;
      default: // 3
        x509_size = (((uint32_t)cert_data[idx])<<16) | (((uint32_t)cert_data[idx + 1])<<8) | ((uint32_t)cert_data[idx + 2]);
        idx += 3;
        break;
    }
  }

  if ((idx + x509_size) > cert_size)
    return 0;

  return x509_size + idx;
}

#define NAME_FLAGS ( ASN1_STRFLGS_RFC2253 | XN_FLAG_SEP_COMMA_PLUS | XN_FLAG_FN_SN | XN_FLAG_DUMP_UNKNOWN_FIELDS )

bool x509_get_information ( const uint8_t *x509_data, uint32_t x509_size, x509_info_ptr info )
{
  const uint8_t        *p;
  X509                 *x509 = NULL;
  X509_NAME            *subjectDN = NULL;
  X509_NAME            *issuerDN  = NULL;
  BIO                  *bio       = NULL;
  char                 *pBio      = NULL;
  long                  lenBio    = 0;
  const ASN1_INTEGER   *serialNo;
  BIGNUM               *bn;
  char                 *sn;
  const ASN1_TIME      *x509_time;
  EVP_PKEY             *pkey = NULL;
  bool                  dont_free_x509 = false;

  if (NULL == x509_data || NULL == info)
    return false;

  memset(info, 0, sizeof(x509_info));

  if (0 == x509_size) // ok, we treat x509_data as an OpenSSL X509* pointer
  {
    x509 = (X509*)x509_data;
    dont_free_x509 = true;
  }
  else
  {
    p = x509_data;
    if (!d2i_X509(&x509, &p, x509_size))
      return false;

    if ((x509_data + x509_size) != p)
    {
ErrorExit:
      if (NULL != pkey)
        EVP_PKEY_free(pkey);
      if (!dont_free_x509)
        X509_free(x509);
      return false;
    }
  }

  subjectDN = X509_get_subject_name(x509); // MUST NOT be freed, is an OpenSSL-internal pointer
  issuerDN  = X509_get_issuer_name(x509);  // MUST NOT be freed, is an OpenSSL-internal pointer

  if (NULL == subjectDN || NULL == issuerDN )
    goto ErrorExit;

  bio = BIO_new(BIO_s_mem());
  if ( NULL == bio )
    goto ErrorExit;
  X509_NAME_print_ex(bio,subjectDN,0,NAME_FLAGS);
  pBio = NULL;
  lenBio = BIO_get_mem_data(bio, &pBio);
  if ( pBio == NULL || lenBio <= 0 )
    goto ErrorExit;
  if (((unsigned long)lenBio) >= sizeof(info->subjectDN))
    lenBio = sizeof(info->subjectDN) - 1;
  memcpy(info->subjectDN, pBio, lenBio);
  BIO_free(bio);

  bio = BIO_new(BIO_s_mem());
  if ( NULL == bio )
    goto ErrorExit;
  X509_NAME_print_ex(bio,issuerDN,0,NAME_FLAGS);
  pBio = NULL;
  lenBio = BIO_get_mem_data(bio, &pBio);
  if ( pBio == NULL || lenBio <= 0 )
    goto ErrorExit;
  if (((unsigned long)lenBio) >= sizeof(info->issuerDN))
    lenBio = sizeof(info->issuerDN) - 1;
  memcpy(info->issuerDN, pBio, lenBio);
  BIO_free(bio);

  serialNo = X509_get0_serialNumber(x509);
  if (NULL == serialNo)
    goto ErrorExit;
  bn = BN_new();
  if (NULL == bn)
    goto ErrorExit;
  ASN1_INTEGER_to_BN(serialNo,bn);
  sn = BN_bn2dec(bn);
  if (NULL == sn)
  {
    BN_free(bn);
    goto ErrorExit;
  }
  strncpy(info->serialno, sn, sizeof(info->serialno) - 1);
  OPENSSL_free(sn);
  BN_free(bn);

  x509_time = X509_get0_notBefore(x509);
  if (NULL == x509_time)
    goto ErrorExit;
  bio = BIO_new(BIO_s_mem());
  if ( NULL == bio )
    goto ErrorExit;
  ASN1_TIME_print(bio, x509_time);
  pBio = NULL;
  lenBio = BIO_get_mem_data(bio, &pBio);
  if ( pBio == NULL || lenBio <= 0 )
    goto ErrorExit;
  if (((unsigned long)lenBio) >= sizeof(info->notBefore))
    lenBio = sizeof(info->notBefore) - 1;
  memcpy(info->notBefore, pBio, lenBio);
  BIO_free(bio);

  x509_time = X509_get0_notAfter(x509);
  if (NULL == x509_time)
    goto ErrorExit;
  bio = BIO_new(BIO_s_mem());
  if ( NULL == bio )
    goto ErrorExit;
  ASN1_TIME_print(bio, x509_time);
  pBio = NULL;
  lenBio = BIO_get_mem_data(bio, &pBio);
  if ( pBio == NULL || lenBio <= 0 )
    goto ErrorExit;
  if (((unsigned long)lenBio) >= sizeof(info->notAfter))
    lenBio = sizeof(info->notAfter) - 1;
  memcpy(info->notAfter, pBio, lenBio);
  BIO_free(bio);

  pkey = X509_get_pubkey(x509);
  if (NULL == pkey)
    goto ErrorExit;

  switch (EVP_PKEY_id(pkey))
  {
    case EVP_PKEY_RSA:
      info->key_type = X509_KEY_TYPE_RSA;
      info->key_bit_size = EVP_PKEY_bits(pkey);
      break;

    case EVP_PKEY_EC:
      info->key_type = X509_KEY_TYPE_EC;
      info->key_bit_size = EVP_PKEY_bits(pkey);
      break;

    case EVP_PKEY_ED25519:
      info->key_type = X509_KEY_TYPE_ED25519;
      info->key_bit_size = 255;
      break;

    case EVP_PKEY_ED448:
      info->key_type = X509_KEY_TYPE_ED448;
      info->key_bit_size = 448;
      break;

    default:
      break;
  }

  EVP_PKEY_free(pkey);
  if (!dont_free_x509)
    X509_free(x509);

  return true;
}


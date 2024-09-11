/**
 * @file   main.c
 * @author Ingo A. Kubbilun (ingo.kubbilun@gmail.com)
 * @brief  main routine of tool for extracting EFI Signature Lists (ESLs)
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

#define PROG_VERSION          "1.1"
#define PROG_DATE             "2024/09/11"

#ifdef _BIG_ENDIAN_HOST
#define efi_bswap_16(_x)      bswap_16(_x)
#define efi_bswap_32(_x)      bswap_32(_x)
#define efi_bswap_64(_x)      bswap_64(_x)
#else
#define efi_bswap_16(_x)      (_x)
#define efi_bswap_32(_x)      (_x)
#define efi_bswap_64(_x)      (_x)
#endif

#define CTRL_RESET              "\033[0m"
#define CTRL_RED                "\033[1;31m"
#define CTRL_GREEN              "\033[1;32m"
#define CTRL_YELLOW             "\033[1;33m"
#define CTRL_BLUE               "\033[1;34m"
#define CTRL_MAGENTA            "\033[1;35m"
#define CTRL_CYAN               "\033[1;36m"

char          g_col_reset[8];
char          g_col_red[8];
char          g_col_green[8];
char          g_col_yellow[8];
char          g_col_blue[8];
char          g_col_magenta[8];
char          g_col_cyan[8];

static void setup_console_colors ( bool use_color )
{
  memset(g_col_reset, 0x00, sizeof(CTRL_RESET));
  memset(g_col_red, 0x00, sizeof(CTRL_RED));
  memset(g_col_green, 0x00, sizeof(CTRL_GREEN));
  memset(g_col_yellow, 0x00, sizeof(CTRL_YELLOW));
  memset(g_col_blue, 0x00, sizeof(CTRL_BLUE));
  memset(g_col_magenta, 0x00, sizeof(CTRL_MAGENTA));
  memset(g_col_cyan, 0x00, sizeof(CTRL_CYAN));

  if (use_color)
  {
    memcpy(g_col_reset, CTRL_RESET, sizeof(CTRL_RESET) - 1);
    memcpy(g_col_red, CTRL_RED, sizeof(CTRL_RED) - 1);
    memcpy(g_col_green, CTRL_GREEN, sizeof(CTRL_GREEN) - 1);
    memcpy(g_col_yellow, CTRL_YELLOW, sizeof(CTRL_YELLOW) - 1);
    memcpy(g_col_blue, CTRL_BLUE, sizeof(CTRL_BLUE) - 1);
    memcpy(g_col_magenta, CTRL_MAGENTA, sizeof(CTRL_MAGENTA) - 1);
    memcpy(g_col_cyan, CTRL_CYAN, sizeof(CTRL_CYAN) - 1);
  }
}

int main ( int argc, char *argv[] )
{
  const char             *esl_file;
  const char             *target_folder;
  bool                    use_colors = true;
  char                    efivarfs_mountpoint[256], *envvar;
  int                     fd = -1, rc = 1;
  struct stat             st;
  uint8_t                *esl_data = NULL, *esl_sig_data;
  uint32_t                esl_index, esl_size, efi_sig_type, efi_sig_size, x509_size, to_be_written;
  const char             *efi_sig_desc;
  char                    strbuffer[256];
  uint32_t                ESL_size, sig_header_size, sig_size, esl_sig_index;
  char                    output_file[256];
  x509_info               x509info;
  uint32_t                filecnt = 0;
  x509_info               signer_infos;
  char                    buffer[256];

  if (3 != argc && 4 != argc)
  {
ShowHelp:
    fprintf(stdout,"usage: %s <ESL|AUTH file> <folder> [--no-colors]\n",argv[0]);
    fprintf(stdout,"------\n");
    fprintf(stdout,"       <ESL file> is the input file, which may\n");
    fprintf(stdout,"       contain four (4) bytes EFI attributes as the\n");
    fprintf(stdout,"       very first four bytes (if this ESL was extracted\n");
    fprintf(stdout,"       from an EFI variable in an EFIVARFS file system).\n\n");
    fprintf(stdout,"       You MAY alternatively specify an .auth file.\n");
    fprintf(stdout,"       The PKCS#7 signer is extracted and displayed in this case.\n\n");
    fprintf(stdout,"       If you omit the trailing GUID of an EFI variable file below\n");
    fprintf(stdout,"       a mounted efivarfs, then the tool tries to lookup and append\n");
    fprintf(stdout,"       the correct GUID for you (you have to specify the variable name\n");
    fprintf(stdout,"       with a trailing dash '-' in this case, e.g. 'dbDefault-'\n\n");
    fprintf(stdout,"       <folder> is the target folder where extracted files\n");
    fprintf(stdout,"       are stored. If the folder does not exist, then it\n");
    fprintf(stdout,"       will be created.\n");
    fprintf(stdout,"       Existing files will be overwritten without warning!\n\n");
    fprintf(stdout,"       Optionally specify --no-colors if you want to disable\n");
    fprintf(stdout,"       colored console output.\n\n");
    fprintf(stdout,"       The environment variable EFIVARFS_MOUNT_POINT may be set\n");
    fprintf(stdout,"       to a location other than /sys/firmware/efi/efivars\n\n");
    fprintf(stdout,"       [version "PROG_VERSION" dated "PROG_DATE" -\n");
    fprintf(stdout,"        Ingo A. Kubbilun - mailto:ingo.kubbilun@gmail.com]\n\n");

    return 1;
  }

  esl_file = argv[1];
  target_folder = argv[2];

  if (4 == argc)
  {
    if (strcmp(argv[3],"--no-colors"))
      goto ShowHelp;
    use_colors = false;
  }

  setup_console_colors(use_colors);

  memset(efivarfs_mountpoint,0x00,sizeof(efivarfs_mountpoint));

  envvar = getenv("EFIVARFS_MOUNT_POINT");
  if (NULL != envvar)
    strncpy(efivarfs_mountpoint, envvar, sizeof(efivarfs_mountpoint) - 1);
  else
    strncpy(efivarfs_mountpoint, "/sys/firmware/efi/efivars", sizeof(efivarfs_mountpoint) - 1);

  // check if we need access to a mounted EFIVARFS (otherwise, the file is a regular file anywhere on disk)

  if (NULL != strstr(esl_file, efivarfs_mountpoint))
  {
    if (!efivarfs_mount(efivarfs_mountpoint))
    {
      fprintf(stderr,"%s[ERROR]%s: Unable to mount EFIVARFS at %s; errno(%i): %s\n", g_col_red, g_col_reset, efivarfs_mountpoint, errno, strerror(errno));
      return 1;
    }
  }

  if (0 != access(target_folder, F_OK))
  {
    if (0 != mkdir(target_folder, 0775))
    {
      fprintf(stderr,"%s[ERROR]%s: Unable to create target folder %s; errno(%i): %s\n", g_col_red, g_col_reset, target_folder, errno, strerror(errno));
      return 1;
    }
  }

  // NEW: if the caller has just specified the prefix of the EFI variable name
  // ---- (without GUID), then try to lookup the variable name in the internal
  //      lookup table adding the GUID to the filename.
  //
  //      The specified prefix has to end with a dash '-', e.g. "dbDefault-"

  memset(buffer, 0, sizeof(buffer));
  strncpy(buffer, esl_file, sizeof(buffer) - 1);
  if (efivar_complete_filename(buffer, sizeof(buffer)))
    esl_file = buffer;

  fd = open(esl_file, O_RDONLY);
  if (fd < 0)
  {
    fprintf(stderr,"%s[ERROR]%s: Unable to open ESL file %s; errno(%i): %s\n", g_col_red, g_col_reset, esl_file, errno, strerror(errno));
    goto DoExit;
  }

  if (0 != fstat(fd,&st))
  {
    fprintf(stderr,"%s[ERROR]%s: Unable to get file information of ESL file %s; errno(%i): %s\n", g_col_red, g_col_reset, esl_file, errno, strerror(errno));
    goto DoExit;
  }

  if (0 == st.st_size)
  {
    fprintf(stderr,"%s[ERROR]%s: Input ESL file %s has zero-length\n", g_col_red, g_col_reset, esl_file);
    goto DoExit;
  }

  esl_size = (uint32_t)st.st_size;

  esl_data = (uint8_t*)malloc(esl_size);
  if (NULL == esl_data)
  {
    fprintf(stderr,"%s[ERROR]%s: Insufficient memory available\n", g_col_red, g_col_reset);
    goto DoExit;
  }

  if (esl_size != ((uint32_t)read(fd, esl_data, esl_size)))
  {
    fprintf(stderr,"%s[ERROR]%s: Unable to read ESL file %s; errno(%i): %s\n", g_col_red, g_col_reset, esl_file, errno, strerror(errno));
    goto DoExit;
  }

  close(fd), fd = -1;

  esl_index = esl_file_get_offset ( esl_data, esl_size, &signer_infos );

  while (esl_index != esl_size)
  {
    efi_sig_type = esl_get_signature_type(esl_data, esl_index, esl_size);
    switch(efi_sig_type)
    {
      case SIGTYPE_ERROR:
        fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X\n", g_col_red, g_col_reset, esl_file, esl_index);
        goto DoExit;

      case SIGTYPE_UNKNOWN:
        format_guid(esl_data + esl_index, strbuffer, sizeof(strbuffer), true/* with curly braces */);
        fprintf(stdout,"%s * found ESL, UNKNOWN type '%s%s%s' at offset %s0x%08X%s\n", g_col_cyan, g_col_magenta, strbuffer, g_col_cyan, g_col_red, esl_index, g_col_reset);
        goto GoOn;

      default:
        efi_sig_desc = esl_get_signature_description(efi_sig_type);
        fprintf(stdout,"%s * found ESL, type '%s%s%s' at offset %s0x%08X%s\n", g_col_cyan, g_col_green, efi_sig_desc, g_col_cyan, g_col_red, esl_index, g_col_reset);
        if (0 != signer_infos.subjectDN[0] && 0 != signer_infos.serialno[0])
          fprintf(stdout,"%s * Signed by subject DN '%s%s%s', serial no. %s%s%s\n", g_col_cyan, g_col_green, signer_infos.subjectDN, g_col_cyan, g_col_green, signer_infos.serialno, g_col_reset);
GoOn:
        if ((esl_index + 12) > esl_size)
        {
          fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (ran out of data)\n", g_col_red, g_col_reset, esl_file, esl_index);
          goto DoExit;
        }

        ESL_size        = efi_bswap_32(*((uint32_t*) (esl_data + esl_index + sizeof(GUID))));
        sig_header_size = efi_bswap_32(*((uint32_t*) (esl_data + esl_index + sizeof(GUID) + 4)));
        sig_size        = efi_bswap_32(*((uint32_t*) (esl_data + esl_index + sizeof(GUID) + 8)));

        if ((esl_index + ESL_size) > esl_size)
        {
          fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (ran out of data)\n", g_col_red, g_col_reset, esl_file, esl_index);
          goto DoExit;
        }

        if (sig_size < sizeof(GUID))
        {
          fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (ran out of data)\n", g_col_red, g_col_reset, esl_file, esl_index);
          goto DoExit;
        }

        esl_sig_index = esl_index + sizeof(GUID) + 12 + sig_header_size;
        esl_sig_data  = esl_data + esl_sig_index; /* shall be always zero (0), we do not care about any header */

        esl_index += ESL_size;

        ESL_size -= 12 + sizeof(GUID);

        if (SIGTYPE_UNKNOWN != efi_sig_type)
        {
          efi_sig_size = esl_get_signature_size(efi_sig_type);

          // a GUID (the owner) follows with the bare signature data

          while (0 != ESL_size)
          {
            if (ESL_size < sizeof(GUID))
            {
              fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (ran out of data)\n", g_col_red, g_col_reset, esl_file, esl_sig_index);
              goto DoExit;
            }

            format_guid(esl_sig_data, strbuffer, sizeof(strbuffer), false/* no curly braces */);

            esl_sig_data  += sizeof(GUID); // this is the owner
            esl_sig_index += sizeof(GUID);
            ESL_size      -= sizeof(GUID);

            // It depends now: either we have a real signature size or it is (uint32_t)-1, which means that an X.509 certificate (DER-encoded) follows

            if (SIGTYPE_EFI_CERT_X509_GUID == efi_sig_type)
            {
              x509_size = x509_get_certificate_size(esl_sig_data, ESL_size);
              if (0 == x509_size)
              {
                fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (ran out of data)\n", g_col_red, g_col_reset, esl_file, esl_sig_index);
                goto DoExit;
              }
              to_be_written = x509_size;

              if (x509_get_information(esl_sig_data, x509_size, &x509info))
              {
                fprintf(stdout,"%s   +  Serial no ........: %s%s%s\n", g_col_cyan, g_col_green, x509info.serialno, g_col_reset);
                fprintf(stdout,"%s   +  Not before .......: %s%s%s\n", g_col_cyan, g_col_green, x509info.notBefore, g_col_reset);
                fprintf(stdout,"%s   +  Not after ........: %s%s%s\n", g_col_cyan, g_col_green, x509info.notAfter, g_col_reset);
                fprintf(stdout,"%s   +  subject DN .......: %s%s%s\n", g_col_cyan, g_col_green, x509info.subjectDN, g_col_reset);
                fprintf(stdout,"%s   +  issuer DN ........: %s%s%s\n", g_col_cyan, g_col_green, x509info.issuerDN, g_col_reset);
                switch(x509info.key_type)
                {
                  case X509_KEY_TYPE_RSA:
                    fprintf(stdout,"%s   +  key type .........: %sRSA/%ubit%s\n", g_col_cyan, g_col_green, x509info.key_bit_size, g_col_reset);
                    break;
                  case X509_KEY_TYPE_EC:
                    fprintf(stdout,"%s   +  key type .........: %sElliptic Curve/%ubit%s\n", g_col_cyan, g_col_green, x509info.key_bit_size, g_col_reset);
                    break;
                  case X509_KEY_TYPE_ED25519:
                    fprintf(stdout,"%s   +  key type .........: %sEdwards Curve/255bit%s\n", g_col_cyan, g_col_green, g_col_reset);
                    break;
                  case X509_KEY_TYPE_ED448:
                    fprintf(stdout,"%s   +  key type .........: %sEdwards Curve/448bit%s\n", g_col_cyan, g_col_green, g_col_reset);
                    break;
                  default:
                    break;
                }
              }
            }
            else
            {
              if (ESL_size < efi_sig_size)
              {
                fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (ran out of data)\n", g_col_red, g_col_reset, esl_file, esl_sig_index);
                goto DoExit;
              }
              to_be_written = efi_sig_size;
            }

            snprintf(output_file, sizeof(output_file), "%s/%04u-efisig_%s_%s.%s", target_folder, ++filecnt, esl_get_signature_file_infix(efi_sig_type), strbuffer, SIGTYPE_EFI_CERT_X509_GUID == efi_sig_type ? "crt" : "hsh");

            fprintf(stdout,"%s   => dumping to %s%s%s\n", g_col_cyan, g_col_magenta, output_file, g_col_reset);

            fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0664);
            if (fd < 0)
            {
              fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (unable to open/create output file: %s); errno(%i): %s\n", g_col_red, g_col_reset, esl_file, esl_sig_index, output_file, errno, strerror(errno));
              goto DoExit;
            }

            if (to_be_written != ((uint32_t)write(fd, esl_sig_data, to_be_written)))
            {
              fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (unable to write into output file: %s); errno(%i): %s\n", g_col_red, g_col_reset, esl_file, esl_sig_index, output_file, errno, strerror(errno));
              goto DoExit;
            }

            close(fd), fd = -1;

            esl_sig_data  += to_be_written;
            ESL_size      -= to_be_written;
            esl_sig_index += to_be_written;
          }
        }
        else // BULK dump...
        {
          if ((((uint32_t)(esl_sig_data - esl_data)) + sig_size) > esl_size)
          {
            fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X: data to be written exceeds file size (is this an ESL?)\n", g_col_red, g_col_reset, esl_file, esl_sig_index);
            goto DoExit;
          }

          format_guid(esl_data + esl_index, strbuffer, sizeof(strbuffer), false/* no curly braces */);

          snprintf(output_file, sizeof(output_file), "%s/%04u-efisig_unknown_%s.raw", target_folder, ++filecnt, strbuffer);

          fprintf(stdout,"%s   => dumping to %s%s%s\n", g_col_cyan, g_col_magenta, output_file, g_col_reset);

          fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0664);
          if (fd < 0)
          {
            fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (unable to open/create output file: %s); errno(%i): %s\n", g_col_red, g_col_reset, esl_file, esl_sig_index, output_file, errno, strerror(errno));
            goto DoExit;
          }

          if (sig_size != ((uint32_t)write(fd, esl_sig_data, sig_size)))
          {
            fprintf(stderr,"%s[ERROR]%s: ESL '%s': unable to proceed at offset 0x%08X (unable to write into output file: %s); errno(%i): %s\n", g_col_red, g_col_reset, esl_file, esl_sig_index, output_file, errno, strerror(errno));
            goto DoExit;
          }

          close(fd), fd = -1;
        }

        break;
    }
  }

  rc = 0;

DoExit:

  if (NULL != esl_data)
    free(esl_data);

  if (fd >= 0)
    close(fd);

  efivarfs_umount(efivarfs_mountpoint);

  return rc;
}


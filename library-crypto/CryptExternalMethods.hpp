/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * (c)Copyright 2006 Hewlett-Packard Development Company, LP.
 *
 */

#ifndef _CRYPT_EXTERNAL_METHODS_H
#define _CRYPT_EXTERNAL_METHODS_H

#include "ProtocolDataType.hpp"

#include <openssl/md5.h>

/* AKA */

#define RANDLEN 16
#define AUTNLEN 16
#define NONCELEN 32
#define AKLEN 6
#define CKLEN 16
#define IKLEN 16
#define RESLEN 8


extern "C" int crypto_method (T_pValueData  P_msgPart,
                              T_pValueData  P_args,
                              T_pValueData  P_result);

extern "C" int crypto_method_radius (T_pValueData  P_msgPart,
                                     T_pValueData  P_args,
                                     T_pValueData  P_result);

extern "C" int crypto_method_diameter (T_pValueData  P_msgPart,
                                     T_pValueData  P_args,
                                     T_pValueData  P_result);

extern "C" int crypto_method_sip_AV (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result);

extern "C" int crypto_method_sip_authorization (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result);

extern "C" int crypto_method_ck (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result);

extern "C" int crypto_method_ik (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result);

extern "C" int build_Cx_User_Data (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result);
#endif // _CRYPT_EXTERNAL_METHODS_H


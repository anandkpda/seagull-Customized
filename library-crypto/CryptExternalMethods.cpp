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

#include "CryptExternalMethods.hpp"
#include "Utils.hpp"
#include "string_t.hpp"
#include <regex.h>
#include <cstring>

#ifdef DEBUG_MODE
#define GEN_DEBUG(l,a) iostream_error << a << iostream_endl << iostream_flush ; 
#else
#define GEN_DEBUG(l,a) 
#endif

#define GEN_ERROR(l,a) iostream_error << a << iostream_endl << iostream_flush ; 



extern char *stristr (const char *s1, const char *s2) ;
extern int createAuthHeaderMD5(char * user, char * password, char * method,
                               char * uri, char * msgbody, char * auth, 
                               char * algo, char * result);
extern int createAuthHeaderAKAv1MD5(char * user, char * OP,
                                    char * AMF,
                                    char * K,
                                    char * method,
                                    char * uri, char * msgbody, char * auth, char *algo,
                                    char * result);

extern int createAuthenticationVectors(char * aka_OP,
                             char * aka_AMF,
                             char * aka_K,
                             char * sqn_p, char * auth,
                             char * result, char *m_ck, char *m_ik);

char* external_find_text_value (char *P_buf, char *P_field) {

  if ((P_buf == NULL) || (P_field == NULL))
    return NULL;


  char *L_value = NULL ;

  regex_t    L_reg_expr ;
  int        L_status ;
  char       L_buffer[100];
  regmatch_t L_pmatch[3] ;
  size_t     L_size = 0 ;

  string_t   L_string = "" ;
  
  L_string  = "([[:blank:]]*" ;
  L_string += P_field ;
  L_string += "[[:blank:]]*=[[:blank:]]*)([^;]+)";

  L_status = regcomp (&L_reg_expr, 
		      L_string.c_str(),
		      REG_EXTENDED) ;

  if (L_status != 0) {
    regerror(L_status, &L_reg_expr, L_buffer, 100);
    regfree (&L_reg_expr) ;
  } else {
  
    L_status = regexec (&L_reg_expr, P_buf, 3, L_pmatch, 0) ;
    regfree (&L_reg_expr) ;
    if (L_status == 0) {
      L_size = L_pmatch[2].rm_eo - L_pmatch[2].rm_so ;
      ALLOC_TABLE(L_value, char*, sizeof(char), L_size+1);
      memcpy(L_value, &(P_buf[L_pmatch[2].rm_so]), L_size);
      L_value[L_size]='\0' ;
    } 
  }
  return (L_value);
}

typedef struct _crypto_args_string {
  char * m_user; 
  char * m_password; 
  char * m_method;
  char * m_uri; 
  char * m_auth; 
  int    m_algo_id;
  char * m_algo ;
  char * m_aka_k ;
  char * m_aka_op ;
  char * m_aka_amf ;
  char * m_shared_secret ;
  char * m_realm ;		//AGNI - Added newly for Diameter Digest-HA1 AVP calculation
  char * m_sqn ;		//Anand- Added newly for Diameter Digest-AKA calculation
  char * m_imsi ;		//Anand- Added newly for Diameter Digest-AKA calculation
  char * m_res ;		//Anand- Added newly for Diameter Digest-AKA calculation
  char * m_ck ;		//Anand- Added newly for Diameter Digest-AKA calculation
  char * m_ik ;		//Anand- Added newly for Diameter Digest-AKA calculation
} T_CryptoArgsStr, *T_pCryptoArgsStr ;


static const T_CryptoArgsStr Crypto_Args_Str_init = {
  NULL,
  NULL , 
  NULL,
  NULL,
  NULL, 
  -1,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,			//AGNI - Added newly for Diameter Digest-HA1 AVP calculation 
  NULL,                 //Anand- Added newly for Diameter Digest-AKA calculation
  NULL,                 //Anand- Added newly for Diameter Digest-AKA calculation
  NULL,                 //Anand- Added newly for Diameter Digest-AKA calculation
  NULL,                 //Anand- Added newly for Diameter Digest-AKA calculation
  NULL                  //Anand- Added newly for Diameter Digest-AKA calculation
} ;

int check_algorithm(char * auth) {
  
  char algo[32]="MD5";
  char *start, *end;
  
  if ((start = stristr(auth, "Digest")) == NULL) {
    return (-1);
  }
  
  if ((start = stristr(auth, "algorithm=")) != NULL) {
    start = start + strlen("algorithm=");
    if (*start == '"') { start++; }
    end = start + strcspn(start, " ,\"\r\n");
    strncpy(algo, start, end - start);
    algo[end - start] ='\0';
  }
  
  if (strncasecmp(algo, "MD5", 3)==0) {
    return (0);
  } else if (strncasecmp(algo, "AKAv1-MD5", 9)==0) {
    return (1);
  } else {
    return (-1) ;
  }
}

int crypto_args_analysis (T_pValueData  P_args, T_pCryptoArgsStr P_result) {

  int             L_ret = 0 ;

  *P_result = Crypto_Args_Str_init ;
  P_result->m_user = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                             (char*)"username")  ;
  if (P_result->m_user == NULL ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "user no defined in format of the action: set-value format=\"username=.. ");
    L_ret = -1;
    return (L_ret);
  }
  
  P_result->m_method = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                (char*)"method")  ;
  if (P_result->m_method == NULL ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "method no defined in format of the action: set-value format=\"method=.. ");
    L_ret = -1;
    return (L_ret);
  }
  
  P_result->m_uri = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                        (char*)"uri")  ;
  if (P_result->m_uri == NULL ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "uri no defined in format of the action: set-value format=\"uri=.. ");
    L_ret = -1;
    return (L_ret);
  }

  P_result->m_auth = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                              (char*)"auth")  ;
  if (P_result->m_auth == NULL ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "auth no defined in format of the action: set-value format=\"auth=.. ");
    L_ret = -1;
    return (L_ret);
  }

  P_result->m_algo_id = check_algorithm(P_result->m_auth);
  if (P_result->m_algo_id == -1 ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "algorithm not defined (MD5 or AKA)");
    L_ret = -1;
    return (L_ret);
  }

  // MD5 only
  if (P_result->m_algo_id == 0) { // MD5 

    ALLOC_TABLE(P_result->m_algo, char*, sizeof(char), 4);
    strcpy(P_result->m_algo, (char*)"MD5");

    P_result->m_password = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                    (char*)"password")  ;
    if (P_result->m_password == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "password no defined in format of the action: set-value format=\"password=...");
      L_ret = -1;
      return (L_ret);
    }

    
  } else {

    ALLOC_TABLE(P_result->m_algo, char*, sizeof(char), 10);
    strcpy(P_result->m_algo, (char*)"AKAv1-MD5");

    // AKA only
    P_result->m_aka_op = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                  (char*)"aka_op")  ;
    if (P_result->m_aka_op == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "aka_op no defined in format of the action: set-value format=\"aka_op=...");
      L_ret = -1;
      return (L_ret);
    }
    
    P_result->m_aka_amf = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                   (char*)"aka_amf")  ;
    if (P_result->m_aka_amf == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "aka_amf no defined in format of the action: set-value format=\"aka_amf=...");
      L_ret = -1;
      return (L_ret);
    }
    
    P_result->m_aka_k = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                        (char*)"aka_k")  ;
    if (P_result->m_aka_k == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "aka_k no defined in format of the action: set-value format=\"aka_k=...");
      L_ret = -1;
      return (L_ret);
    }

  }
  return (L_ret);
}


int crypto_method (T_pValueData  P_msgPart,
                   T_pValueData  P_args,
                   T_pValueData  P_result) {
  
  GEN_DEBUG(1, "AGNI crypto_method start");
  int             L_ret    = 0    ;
  T_CryptoArgsStr L_crypto ;
  char            L_result [2049] ;

  L_ret = crypto_args_analysis(P_args, &L_crypto);
  if (L_ret != -1) {
    if (L_crypto.m_algo_id == 0) {
      L_ret = createAuthHeaderMD5(L_crypto.m_user,
                                  L_crypto.m_password,
                                  L_crypto.m_method,
                                  L_crypto.m_uri,
                                  (char*)P_msgPart->m_value.m_val_binary.m_value,
                                  L_crypto.m_auth,
                                  L_crypto.m_algo,
                                  L_result);
    } else {
      L_ret = createAuthHeaderAKAv1MD5(L_crypto.m_user, 
                                       L_crypto.m_aka_op,
                                       L_crypto.m_aka_amf,
                                       L_crypto.m_aka_k,
                                       L_crypto.m_method,
                                       L_crypto.m_uri,
                                       (char*)P_msgPart->m_value.m_val_binary.m_value,
                                       L_crypto.m_auth,
                                       L_crypto.m_algo,
                                       L_result);
    }
    if (L_ret == 1) {
      P_result->m_type = E_TYPE_STRING ;
      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
                  unsigned char*,
                  sizeof(unsigned char),
                  strlen(L_result));      
      P_result->m_value.m_val_binary.m_size = strlen(L_result);
      memcpy(P_result->m_value.m_val_binary.m_value, L_result, strlen(L_result));
    } else {
      L_ret = -1 ;
    }
  }

  FREE_TABLE(L_crypto.m_user); 
  FREE_TABLE(L_crypto.m_password); 
  FREE_TABLE(L_crypto.m_method);
  FREE_TABLE(L_crypto.m_uri); 
  FREE_TABLE(L_crypto.m_auth); 
  FREE_TABLE(L_crypto.m_algo );
  FREE_TABLE(L_crypto.m_aka_k );
  FREE_TABLE(L_crypto.m_aka_op );
  FREE_TABLE(L_crypto.m_aka_amf );
  FREE_TABLE(L_crypto.m_shared_secret );

  GEN_DEBUG(1, "AGNI crypto_method end");
  return (L_ret);
}

/** Analyze arguments for radius protocol 
  * \param P_args uses to determine the shared secret 
  * \param P_result contains the shared secret
  * \return 0 if OK
  */
int crypto_args_analysis_radius (T_pValueData  P_args, T_pCryptoArgsStr P_result) {

  int             L_ret = 0 ;

  *P_result = Crypto_Args_Str_init ;
  if (P_args->m_value.m_val_binary.m_size > 0) {
    P_result->m_shared_secret = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                         (char*)"shared_secret")  ;
  }
  return (L_ret);
}

void convertHashToHex(unsigned char *_b, unsigned char *_h)
{
  unsigned short i;
  unsigned char j;

  for (i = 0; i < 16; i++) {
    j = (_b[i] >> 4) & 0xf;
    if (j <= 9) {
      _h[i * 2] = (j + '0');
    } else {
      _h[i * 2] = (j + 'a' - 10);
    }
    j = _b[i] & 0xf;
    if (j <= 9) {
      _h[i * 2 + 1] = (j + '0');
    } else {
      _h[i * 2 + 1] = (j + 'a' - 10);
    }
  };
  _h[32] = '\0';
}



/** Authentication algorithm for radius protocol 
  * \param P_msgPart uses to calculate the key   
  * \param P_args contains the shared secret
  * \param P_result contains the result of this algorithm
  * \return 0 if OK
  */
int create_algo_MD5_radius(char          *  P_msg,
                           int              P_msg_size,
                           char          *  P_shared_secret,
                           unsigned char *  P_result) {
  GEN_DEBUG(1, "AGNI create_algo_MD5_radius start");

  int        L_ret         = 0 ;
  int        L_size_shared = 0 ;
  char       *p, *msg_secret;

  //MD5_CTX    L_Md5Ctx ;
   if (P_shared_secret != NULL) {
    L_size_shared = strlen(P_shared_secret);
  }
  //AGNI - This code has been corrected from original
  //Reference: http://networkconvergence.blogspot.com/2015/11/i-fixed-radius-accounting-request.html
  /*
 *   MD5_Init(&L_Md5Ctx);
 *   if (L_size_shared > 0) {
 *      MD5_Update(&L_Md5Ctx, P_shared_secret, L_size_shared);
 *    }
 *    MD5_Update(&L_Md5Ctx, P_msg, P_msg_size);
 *    MD5_Final(P_result, &L_Md5Ctx);
 **/
  msg_secret = (char *)malloc(P_msg_size + L_size_shared);
  memcpy(msg_secret, P_msg, P_msg_size);
  p = msg_secret + P_msg_size;
  memcpy(p, P_shared_secret, L_size_shared);

  MD5((unsigned char *)msg_secret, P_msg_size + L_size_shared, P_result);
  free(msg_secret);


  GEN_DEBUG(1, "AGNI create_algo_MD5_radius stop");
  return (L_ret);
}


/** Authentication method for radius protocol 
  * \param P_msgPart uses to calculate the key   
  * \param P_args contains the shared secret
  * \param P_result contains the result of this method
  * \return 0 if OK
  */
int crypto_method_radius (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result) {
  GEN_DEBUG(1, "AGNI crypto_method_radius start");
  
  int             L_ret    = 0    ;
  T_CryptoArgsStr L_crypto        ;
  unsigned char   L_result [32]   ;


  L_ret = crypto_args_analysis_radius(P_args, &L_crypto);
  if (L_ret != -1) {
    L_ret =  create_algo_MD5_radius((char*)P_msgPart->m_value.m_val_binary.m_value,
                                    P_msgPart->m_value.m_val_binary.m_size,
                                    L_crypto.m_shared_secret,
                                    L_result);
    if (L_ret != -1) {
      P_result->m_type = E_TYPE_STRING ;
      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
                  unsigned char*,
                  sizeof(unsigned char),
                  32);      
      P_result->m_value.m_val_binary.m_size = 32;
      memcpy(P_result->m_value.m_val_binary.m_value, L_result, 32);
    } 
  }

  FREE_TABLE(L_crypto.m_shared_secret );
  GEN_DEBUG(1, "AGNI crypto_method_radius end");
  return (L_ret);
}


/** Author: Agnivesh Kumpati
 *  Analyze arguments for diameter protocol 
 ** \param P_args uses to determine the username, realm, password
 ** \return 0 if OK
 **/
int crypto_args_analysis_diameter (T_pValueData  P_args, T_pCryptoArgsStr P_result) {

  GEN_DEBUG(1, "AGNI crypto_args_analysis_diameter start");

  int             L_ret = 0 ;
  *P_result = Crypto_Args_Str_init ;

  if (P_args->m_value.m_val_binary.m_size > 0) {
    P_result->m_user = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                         (char*)"username")  ;
    if (P_result->m_user == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
              "username not defined in format of the action: set-value format=\"username=.. ");
      L_ret = -1;
      return (L_ret);
    }

    P_result->m_realm = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                         (char*)"realm")  ;
    if (P_result->m_realm == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
              "realm not defined in format of the action: set-value format=\"realm=.. ");
      L_ret = -1;
      return (L_ret);
    }

    P_result->m_password = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                    (char*)"password")  ;
    if (P_result->m_password == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "password not defined in format of the action: set-value format=\"password=..");
      L_ret = -1;
      return (L_ret);
    }
  }
  GEN_DEBUG(1, "AGNI crypto_args_analysis_diameter end");
  return (L_ret);
}




/** Author: Agnivesh Kumpati
 *  Authentication algorithm for diameter protocol 
 ** \param P_user, P_realm, P_password contains username, realm, password respectively
 ** \param P_result contains the MD5 Hash of username:realm:password
 ** \return 0 if OK
 **/
int create_algo_MD5_diameter(char          *  P_user,
                           char          *  P_realm,
                           char          *  P_password,
                           char *  P_result) {
  GEN_DEBUG(1, "AGNI create_algo_MD5_diameter start");

  int        L_ret         = 0 ;
  MD5_CTX    L_Md5Ctx ;
  unsigned char ha1[16];
  unsigned char ha1_hex[33];

  GEN_DEBUG(1, "AGNI create_algo_MD5_diameter user = " << P_user << ", realm = " << P_realm << ", pass = " << P_password);

  MD5_Init(&L_Md5Ctx);
  MD5_Update(&L_Md5Ctx, P_user, strlen(P_user));
  MD5_Update(&L_Md5Ctx, ":", 1);
  MD5_Update(&L_Md5Ctx, P_realm, strlen(P_realm));
  MD5_Update(&L_Md5Ctx, ":", 1);
  MD5_Update(&L_Md5Ctx, P_password, strlen(P_password));
  MD5_Final(ha1, &L_Md5Ctx);


  convertHashToHex(&ha1[0], &ha1_hex[0]);
  GEN_DEBUG(1, "AGNI create_algo_MD5_diameter ha1_hex after = " << ha1_hex);
  sprintf(P_result, "%s",ha1_hex);
  /*GEN_DEBUG(1, "AGNI create_algo_MD5_diameter P_result is ");
  for(int i=0; i < 32; i++) {
      printf("%02x",P_result[i]);
  }
  printf("\n");*/

  GEN_DEBUG(1, "AGNI create_algo_MD5_diameter end");
  return (L_ret);
}



/** Author: Agnivesh Kumpati
 ** Creates and return MD5 hash for diameter protocol 
 ** \param P_args contains username, realm and password parameters sent from scenario file
 ** \param P_result contains the MD5 Hash of username:realm:password
 ** \return 0 if OK
 **/
int crypto_method_diameter (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result) {
  GEN_DEBUG(1, "AGNI crypto_method_diameter start");

  int             L_ret    = 0    ;
  T_CryptoArgsStr L_crypto ;
  char            L_result [32] ;

  L_ret = crypto_args_analysis_diameter(P_args, &L_crypto);
  if (L_ret != -1) {
    L_ret =  create_algo_MD5_diameter(L_crypto.m_user,
				      L_crypto.m_realm,
				      L_crypto.m_password,
                                      L_result);
    if (L_ret != -1) {
      P_result->m_type = E_TYPE_STRING ;
      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
                  unsigned char*,
                  sizeof(unsigned char),
                  strlen(L_result));
      P_result->m_value.m_val_binary.m_size = strlen(L_result);
      memcpy(P_result->m_value.m_val_binary.m_value, L_result, strlen(L_result));
    }
  }

  //FREE_TABLE(L_crypto.m_user );		// TODO: Double free/Corruption Crash
  FREE_TABLE(L_crypto.m_realm );
  FREE_TABLE(L_crypto.m_password );

  GEN_DEBUG(1, "AGNI crypto_method_diameter end");

  return (L_ret);     
}
//Anand added are here 

__thread T_CryptoArgsStr L_ak_crypto ;

int crypto_args_analysis_diameterAKA (T_pValueData  P_args, T_pCryptoArgsStr P_result) {

  GEN_DEBUG(1, "ANAND  crypto_args_analysis_diameterAKA start");

  int L_ret = 0 ;
  *P_result = Crypto_Args_Str_init ;

  if (P_args->m_value.m_val_binary.m_size > 0) {
   
    P_result->m_aka_op = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                  (char*)"aka_op")  ;
    if (P_result->m_aka_op == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "aka_op no defined in format of the action: set-value format=\"aka_op=...");
      L_ret = -1;
      return (L_ret);
    }

    P_result->m_aka_amf = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                   (char*)"aka_amf")  ;
    if (P_result->m_aka_amf == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "aka_amf no defined in format of the action: set-value format=\"aka_amf=...");
      L_ret = -1;
      return (L_ret);
    }

    P_result->m_aka_k = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                        (char*)"aka_k")  ;
    if (P_result->m_aka_k == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "aka_k no defined in format of the action: set-value format=\"aka_k=...");
      L_ret = -1;
      return (L_ret);
    }

    P_result->m_sqn = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                        (char*)"sqn")  ;
    if (P_result->m_sqn == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR, 
                "sqn no defined in format of the action: set-value format=\"sqn=...");
      L_ret = -1;
      return (L_ret);
    }

  }
  GEN_DEBUG(1, "Anand crypto_args_analysis_diameterAKA end");
  return (L_ret);
}


int crypto_method_sip_AV (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result) {
  GEN_DEBUG(1, "Anand crypto_method_sip_AV start");
	  int             L_ret    = 0 ;
	  char L_auth[64], L_res[16], L_ck[32],L_ik[32];
	  L_ret = crypto_args_analysis_diameterAKA(P_args, &L_ak_crypto);
	  if (L_ret != -1) {

	   L_ret = createAuthenticationVectors(L_ak_crypto.m_aka_op,
					       L_ak_crypto.m_aka_amf,
					       L_ak_crypto.m_aka_k,
					       L_ak_crypto.m_sqn,
					       L_auth, L_res , L_ck, L_ik);


	    if (L_ret != -1) {
	      P_result->m_type = E_TYPE_STRING ;
	      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
			  unsigned char*, sizeof(unsigned char), NONCELEN);
	      P_result->m_value.m_val_binary.m_size = NONCELEN;
	      memcpy(P_result->m_value.m_val_binary.m_value, L_auth, NONCELEN);
	    }

	  } 

	  ALLOC_TABLE(L_ak_crypto.m_res, char*, sizeof(char), RESLEN+1);
	  memcpy(L_ak_crypto.m_res,L_res,RESLEN);
	  L_ak_crypto.m_res[RESLEN] = '\0';

	  ALLOC_TABLE(L_ak_crypto.m_ck, char*, sizeof(char), CKLEN+1);
	  memcpy(L_ak_crypto.m_ck,L_ck,CKLEN);
	  L_ak_crypto.m_ck[CKLEN] = '\0';

	  ALLOC_TABLE(L_ak_crypto.m_ik, char*, sizeof(char), IKLEN+1);
	  memcpy(L_ak_crypto.m_ik,L_ik,IKLEN);
	  L_ak_crypto.m_ik[IKLEN] = '\0';

	  GEN_DEBUG(1, "Anand crypto_method_sip_AV end");
	  return (0);
	}

int crypto_method_sip_authorization (T_pValueData  P_msgPart,
				  T_pValueData  P_args,
				  T_pValueData  P_result) {
	  GEN_DEBUG(1, "Anand crypto_method_sip_authorization start");

	//return already generated values:
	      P_result->m_type = E_TYPE_STRING ;
	      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
			  unsigned char*, sizeof(unsigned char), RESLEN);
	      P_result->m_value.m_val_binary.m_size = RESLEN;
	      memcpy(P_result->m_value.m_val_binary.m_value, L_ak_crypto.m_res, RESLEN);

	  GEN_DEBUG(1, "Anand crypto_method_sip_authorization end");

	  return (0);
}


int crypto_method_ck (T_pValueData  P_msgPart,
				  T_pValueData  P_args,
				  T_pValueData  P_result) {
	  GEN_DEBUG(1, "Anand crypto_method_ck start");

	//return already generated values:
	      P_result->m_type = E_TYPE_STRING ;
	      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
			  unsigned char*, sizeof(unsigned char), CKLEN);
	      P_result->m_value.m_val_binary.m_size = CKLEN;
	      memcpy(P_result->m_value.m_val_binary.m_value, L_ak_crypto.m_ck, CKLEN);

	  GEN_DEBUG(1, "Anand crypto_method_ck end");
	  return(0);
}

int crypto_method_ik (T_pValueData  P_msgPart,
				  T_pValueData  P_args,
				  T_pValueData  P_result) {
	  GEN_DEBUG(1, "Anand crypto_method_ik start");

	//return already generated values:
	      P_result->m_type = E_TYPE_STRING ;
	      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
			  unsigned char*, sizeof(unsigned char), IKLEN);
	      P_result->m_value.m_val_binary.m_size = IKLEN;
	      memcpy(P_result->m_value.m_val_binary.m_value, L_ak_crypto.m_ik, IKLEN);

	  FREE_TABLE(L_ak_crypto.m_sqn); 
	  FREE_TABLE(L_ak_crypto.m_aka_k );
	  FREE_TABLE(L_ak_crypto.m_aka_op );
	  FREE_TABLE(L_ak_crypto.m_aka_amf );
	  FREE_TABLE(L_ak_crypto.m_ck );
	  FREE_TABLE(L_ak_crypto.m_ik );
	  FREE_TABLE(L_ak_crypto.m_res );

	  GEN_DEBUG(1, "Anand crypto_method_ik end");
	  return(0);
}

int crypto_args_analysis_username (T_pValueData  P_args, T_pCryptoArgsStr P_result) {

	  GEN_DEBUG(1, "Anand crypto_args_analysis_username start");

	  int             L_ret = 0 ;
	  *P_result = Crypto_Args_Str_init ;

	  if (P_args->m_value.m_val_binary.m_size > 0) {
	    P_result->m_imsi = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
								 (char*)"username")  ;
	    if (P_result->m_imsi == NULL ) {
	      GEN_ERROR(E_GEN_FATAL_ERROR,
		      "username not defined in format of the action: set-value format=\"username=.. ");
	      L_ret = -1;
	      return (L_ret);
	    }
	  }
	  if (P_args->m_value.m_val_binary.m_size > 0) {
	    P_result->m_user = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
								 (char*)"pub-identity")  ;
	    if (P_result->m_user == NULL ) {
	      GEN_ERROR(E_GEN_FATAL_ERROR,
		      "username not defined in format of the action: set-value format=\"pub-identity=.. ");
	      L_ret = -1;
	      return (L_ret);
	    }
	  }

	  GEN_DEBUG(1, "Anand crypto_args_analysis_username end");
	  return (L_ret);
	}



	int build_Cx_User_Data (T_pValueData  P_msgPart,
				  T_pValueData  P_args,
				  T_pValueData  P_result) {
	  GEN_DEBUG(1, "Anand build_Cx_User_Data start");

	  int             L_ret    = 0   , len = 0 , srvcc_flag = 0 ;
  T_CryptoArgsStr L_crypto ;
  char            L_result [2048] ;
  char *start, *end;
  char imsi[128] ,domain[128], pub_user[256], msisdn[64];


  L_ret = crypto_args_analysis_username(P_args, &L_crypto);

  if (L_ret != -1) {
  len = strlen(L_crypto.m_user);
  memcpy(pub_user, L_crypto.m_user , len);
  pub_user[len] ='\0';
  GEN_DEBUG(1, "Anand pub-identity copied  = " << pub_user << ", private id  =" << L_crypto.m_imsi );

  // seperating imsi and domain
  start = pub_user;
  start = start + strlen("sip:");
  end = start + strcspn(start, "@");
    if (end == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
              "pub-identity not defined in format of the action: set-value format=\"username=<imsi@domain> ");
      L_ret = -1;
      return (L_ret);
    }
  //strncpy(imsi, start, 15);
  sprintf(domain,"%s", end );
  //imsi[16] ='\0';
  //imsi[len-19] ='\0';

  strcpy(imsi, L_crypto.m_imsi);
  // generating msisdn

  if (strstr(imsi, "2080161") != NULL ){
    sprintf(msisdn,"+446%s",&imsi[6]);
    srvcc_flag = 1;
  } else {
    sprintf(msisdn,"+366%s",&imsi[6]);
  }

  GEN_DEBUG(1, "Anand pub-identity = " << L_crypto.m_user << ", imsi =" << imsi  <<" & domain = "<< domain << " & msisdn = "<<msisdn);
  // building  XML user data 
  if ( srvcc_flag ) 
     sprintf(L_result, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><IMSSubscription><PrivateID>%s</PrivateID><ServiceProfile><PublicIdentity><BarringIndication>0</BarringIndication><Identity>sip:%s%s</Identity><Extension><IdentityType>0</IdentityType></Extension></PublicIdentity><PublicIdentity><BarringIndication>0</BarringIndication><Identity>tel:%s</Identity><Extension><IdentityType>0</IdentityType></Extension></PublicIdentity><PublicIdentity><BarringIndication>1</BarringIndication><Identity>%s</Identity><Extension><IdentityType>0</IdentityType></Extension></PublicIdentity><CoreNetworkServicesAuthorization><SubscribedMediaProfileId>1</SubscribedMediaProfileId><Extension><ListOfServiceIds><ServiceId>1</ServiceId></ListOfServiceIds></Extension></CoreNetworkServicesAuthorization><InitialFilterCriteria><Priority>1</Priority><TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF><SPT><ConditionNegated>0</ConditionNegated><Group>0</Group><Method>INVITE</Method></SPT></TriggerPoint><ApplicationServer><ServerName>sip:193.252.231.160:5060</ServerName><DefaultHandling>0</DefaultHandling><ServiceInfo>Busy</ServiceInfo></ApplicationServer><ProfilePartIndicator>0</ProfilePartIndicator></InitialFilterCriteria></ServiceProfile></IMSSubscription>",L_crypto.m_imsi,msisdn,domain,msisdn, pub_user);
  else
     sprintf(L_result, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><IMSSubscription><PrivateID>%s</PrivateID><ServiceProfile><PublicIdentity><BarringIndication>0</BarringIndication><Identity>sip:%s%s</Identity><Extension><IdentityType>0</IdentityType></Extension></PublicIdentity><PublicIdentity><BarringIndication>0</BarringIndication><Identity>tel:%s</Identity><Extension><IdentityType>0</IdentityType></Extension></PublicIdentity><PublicIdentity><BarringIndication>1</BarringIndication><Identity>%s</Identity><Extension><IdentityType>0</IdentityType></Extension></PublicIdentity><CoreNetworkServicesAuthorization><SubscribedMediaProfileId>1</SubscribedMediaProfileId><Extension><ListOfServiceIds><ServiceId>1</ServiceId></ListOfServiceIds></Extension></CoreNetworkServicesAuthorization><InitialFilterCriteria><Priority>1</Priority><TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF><SPT><ConditionNegated>0</ConditionNegated><Group>0</Group><Method>REGISTER</Method></SPT><SPT><ConditionNegated>0</ConditionNegated><Group>0</Group><Method>INVITE</Method></SPT></TriggerPoint><ApplicationServer><ServerName>sip:193.252.231.158:5060</ServerName><DefaultHandling>0</DefaultHandling><ServiceInfo>Busy</ServiceInfo></ApplicationServer><ProfilePartIndicator>0</ProfilePartIndicator></InitialFilterCriteria><InitialFilterCriteria><Priority>2</Priority><TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF><SPT><ConditionNegated>0</ConditionNegated><Group>0</Group><Method>SUBSCRIBE</Method></SPT></TriggerPoint><ApplicationServer><ServerName>sip:193.252.231.158:5060</ServerName><DefaultHandling>0</DefaultHandling><ServiceInfo>Busy</ServiceInfo></ApplicationServer><ProfilePartIndicator>0</ProfilePartIndicator></InitialFilterCriteria></ServiceProfile></IMSSubscription>",L_crypto.m_imsi,msisdn,domain,msisdn, pub_user);

      P_result->m_type = E_TYPE_STRING ;
      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
                  unsigned char*,
                  sizeof(unsigned char),
                  strlen(L_result));
      P_result->m_value.m_val_binary.m_size = strlen(L_result);
      memcpy(P_result->m_value.m_val_binary.m_value, L_result, strlen(L_result));
      GEN_DEBUG(1, "Anand build_Cx_User_Data stlen(L_res)" << strlen(L_result));
      GEN_DEBUG(1, "Anand build_Cx_User_Data (L_res value)" << L_result);
  }

  FREE_TABLE(L_crypto.m_user); 
  FREE_TABLE(L_crypto.m_imsi); 
  GEN_DEBUG(1, "Anand crypto_method_ik end");


  return (L_ret);
}

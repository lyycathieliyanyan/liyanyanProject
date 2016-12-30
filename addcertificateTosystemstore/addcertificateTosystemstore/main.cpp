#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>

//#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#pragma comment(lib, "crypt32.lib")
#define CERT_LEN 100000

void HandleError(char *s);

void main(void)
{
    HCRYPTPROV hCryptProv = NULL; 
	LPCWSTR UserContainerName = L"lxycathie";  
	/*L"Microsoft Strong Cryptographic Provider"*/
	if(CryptAcquireContext( &hCryptProv,NULL,L"Microsoft Strong Cryptographic Provider",PROV_RSA_FULL,NULL)) 
	{
		printf("A cryptographic context with the %s key container \n", 
			UserContainerName);
		printf("has been acquired.\n\n");
	}
	else
	{ 

	if (GetLastError() == NTE_BAD_KEYSET)
	{
		if(CryptAcquireContext(
			&hCryptProv, 
			UserContainerName, 
			L"Microsoft Strong Cryptographic Provider", 
			PROV_RSA_FULL, 
			CRYPT_NEWKEYSET)) 
		{
			printf("A new key container has been created.\n");
		}
		else
		{
			printf("Could not create a new key container.\n");
			exit(1);
		}
	}
	else
	{
		printf("A cryptographic service handle could not be "
			"acquired.\n");
		exit(1);
	}

} // End of else.

  HCRYPTKEY hKeyCAPI;
  PCCERT_CONTEXT   pCertContext=NULL;  
 // BYTE byCertInfo[CERT_LEN] = {0};
  BYTE * pCertInfo = NULL;
  DWORD dwCertLen = 0;
  HCERTSTORE       hCertStore;        
  char pszStoreName[256] = "TestSystemstore"; 
  BOOL bRet;
  bRet = CryptGetUserKey(hCryptProv,AT_SIGNATURE,&hKeyCAPI);
  if (!bRet)
  {
	  if(!bRet)
	  {
		  //获取失败，现在创建新的RSA密钥对。\n");   
		  bRet = CryptGenKey(hCryptProv, 2, CRYPT_EXPORTABLE | 0X04000000, &hKeyCAPI);
		  if(!bRet)
		  {
			  printf("CryptGenKey fail!\n");
		  }
	  }
  }

  if (CryptGetKeyParam(hKeyCAPI,KP_CERTIFICATE,NULL,&dwCertLen,0))  
  {  
	  pCertInfo = (LPBYTE) LocalAlloc(0, dwCertLen);  
	  if (!pCertInfo)  
	  {  
		  printf("Failed!") ;
	  }  

	  if (CryptGetKeyParam(hKeyCAPI,KP_CERTIFICATE,pCertInfo,&dwCertLen,0)) 
	  {
		  pCertContext =CertCreateCertificateContext(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
			  pCertInfo,
			  dwCertLen) ;
		  if ( NULL == pCertContext )
		  {
			  printf("CspGetCertInfo  CertCreateCertificateContext Failed <=======");
		  }
	  }
  }
//   BYTE byCertInfo[CERT_LEN] = {0};
//   // Der 格式证书长度
//   int dwcbBinary = CERT_LEN;
//   pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, byCertInfo, dwcbBinary);  
		  ////
//    if (CryptGetKeyParam(hKeyCAPI, KP_CERTIFICATE, pCertInfo, &dwCertLen, 0))
//    {
//       if (CryptGetKeyParam(hKeyCAPI, KP_CERTIFICATE, pCertInfo, &dwCertLen, 0))
// 	  {
// 		  pCertContext =CertCreateCertificateContext(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
// 			  pCertInfo,
// 			  dwCertLen) ;
// 		  if ( NULL == pCertContext )
// 		  {
// 			  printf("CspGetCertInfo  CertCreateCertificateContext Failed <=======");
// 		  }
// 
// 	  }
// 
//    }
   if ( hCertStore = CertOpenSystemStore(
	   NULL,
	   (LPCTSTR)pszStoreName))

   {
	   fprintf(stderr,"The %s store has been opened. \n", pszStoreName);
   }
   else
   {
	   //If the store was not opened, exit to an error routine.
	   HandleError("The store was not opened.");
   }
   CRYPT_KEY_PROV_INFO ckpi = {0};
   ckpi.pwszProvName =L"Microsoft Strong Cryptographic Provider";
   ckpi.pwszContainerName = L"lxycathie";  
   ckpi.dwProvType = PROV_RSA_FULL;
   ckpi.dwKeySpec = AT_KEYEXCHANGE;
   ckpi.dwFlags = CERT_KEY_CONTEXT_PROP_ID;
   ckpi.cProvParam = 0;
   ckpi.rgProvParam = NULL;
   CertSetCertificateContextProperty(
	   pCertContext,
	   CERT_KEY_PROV_INFO_PROP_ID,

	   CERT_STORE_NO_CRYPT_RELEASE_FLAG,

	   &ckpi);
   CertAddCertificateContextToStore(
	   hCertStore,
	   pCertContext,
	   CERT_STORE_ADD_REPLACE_EXISTING,
	   NULL);
   CryptReleaseContext(hCryptProv,0);

 
}

void HandleError(char *s)
{
	fprintf(stderr,"An error occurred in running the program. \n");
	fprintf(stderr,"%s\n",s);
	fprintf(stderr, "Error number %x.\n", GetLastError());
	fprintf(stderr, "Program terminating. \n");
	exit(1);
} // End of HandleError.




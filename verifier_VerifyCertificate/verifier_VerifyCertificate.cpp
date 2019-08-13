#include "verifier_VerifyCertificate.h"
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void printSubjectName(PCCERT_CONTEXT pTargetCert);

JNIEXPORT jstring JNICALL Java_verifier_VerifyCertificate_verify
(JNIEnv *env, jobject obj, jbyteArray cert, jlong signingTime){
	PCCERT_CHAIN_CONTEXT     pChainContext;
	HCERTSTORE               hCertStore;
	CERT_ENHKEY_USAGE        EnhkeyUsage;
	CERT_USAGE_MATCH         CertUsage;
	CERT_CHAIN_PARA          ChainPara;
	PCCERT_CONTEXT			 pTargetCert = NULL;
	FILETIME				 verificationTime;
	FILETIME				 verificationTimeLocal;
	char* result;

	memcpy(&verificationTime, &signingTime, sizeof(verificationTime)); 
	//FileTimeToLocalFileTime(&verificationTime, &verificationTimeLocal);

	//-------------------------------------------------------------------
	// pTargetCert is a pointer to the desired certificate.
	jboolean isCopy;
	jbyte* cert_array = env->GetByteArrayElements(cert, &isCopy);
	const BYTE* pbCertArray;
	pbCertArray = (unsigned char*)cert_array;
	DWORD cbCertArray = env->GetArrayLength(cert);
	
	pTargetCert = CertCreateCertificateContext(MY_ENCODING_TYPE,
		pbCertArray,
		cbCertArray);
	if (!(pTargetCert)) {
		printf("Certificate create failed\n");
		return env->NewStringUTF("The chain could not be created.");
	}

	//---------------------------------------------------------
	// Initialize data structures.

	EnhkeyUsage.cUsageIdentifier = 0;
	EnhkeyUsage.rgpszUsageIdentifier = NULL;
	CertUsage.dwType = USAGE_MATCH_TYPE_AND;
	CertUsage.Usage = EnhkeyUsage;
	ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
	ChainPara.RequestedUsage = CertUsage;
	
	//-------------------------------------------------------------------
	// Build a chain using CertGetCertificateChain
	// and the certificate retrieved.

	if (!CertGetCertificateChain(
		NULL,                  // use the default chain engine
		pTargetCert,           // pointer to the end certificate
		&verificationTime, // use the non default time
		NULL,                  // search no additional stores
		&ChainPara,            // use AND logic and enhanced key usage 
		//  as indicated in the ChainPara 
		//  data structure
		CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_CHECK_CHAIN,
		NULL,                  // currently reserved
		&pChainContext))       // return a pointer to the chain created
	{
		printf("The chain could not be created. Error number %x.\n", GetLastError());
		return env->NewStringUTF("The chain could not be created.");
	}

	switch (pChainContext->TrustStatus.dwErrorStatus)
	{
	case CERT_TRUST_NO_ERROR:
		result = "No error found for this certificate or chain.";
		break;
	default:
		if (pChainContext->TrustStatus.dwErrorStatus & (CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_CYCLIC)){
			result = "The certificate chain is not complete and One of the certificates in the chain was issued by a certification authority that the original certificate had certified.";
			break;
		}
		if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID){
			result = "This certificate or one of the certificates in the certificate chain is not time-valid.";
			break;
		}
		if (pChainContext->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED){
			result = "Trust for this certificate or one of the certificates in the certificate chain has been revoked.";
			break;
		}
		if (pChainContext->TrustStatus.dwErrorStatus & (CERT_TRUST_IS_OFFLINE_REVOCATION | CERT_TRUST_REVOCATION_STATUS_UNKNOWN)){
			result = "The revocation status of the certificate or one of the certificates in the certificate chain is either offline or stale and The revocation status of the certificate or one of the certificates in the certificate chain is unknown.";
			break;
		}
		result = "The chain could not be created.";
		break;
	} // End switch
	/*
	printf("\nInfo status for the chain:\n");
	switch (pChainContext->TrustStatus.dwInfoStatus)
	{
	case 0:
		printf("No information status reported.\n");
		break;
	case CERT_TRUST_HAS_EXACT_MATCH_ISSUER:
		printf("An exact match issuer certificate has been found for "
			"this certificate.\n");
		break;
	case CERT_TRUST_HAS_KEY_MATCH_ISSUER:
		printf("A key match issuer certificate has been found for this "
			"certificate.\n");
		break;
	case CERT_TRUST_HAS_NAME_MATCH_ISSUER:
		printf("A name match issuer certificate has been found for this "
			"certificate.\n");
		break;
	case CERT_TRUST_IS_SELF_SIGNED:
		printf("This certificate is self-signed.\n");
		break;
	case CERT_TRUST_IS_COMPLEX_CHAIN:
		printf("The certificate chain created is a complex chain.\n");
		break;
	} // end switch
	*/
	// Free chain.
	CertFreeCertificateChain(pChainContext);

	//-------------------------------------------------------------------
	// Clean up memory and quit.
	if (pTargetCert)
		CertFreeCertificateContext(pTargetCert);

	return env->NewStringUTF(result);
} // End of main

void printSubjectName(PCCERT_CONTEXT pTargetCert){
	DWORD cbSize = CertNameToStr(
		pTargetCert->dwCertEncodingType,
		&(pTargetCert->pCertInfo->Subject),
		CERT_X500_NAME_STR,
		NULL,
		0);
	LPTSTR pszString;
	pszString = (LPTSTR)malloc(cbSize * sizeof(TCHAR));
	cbSize = CertNameToStr(
		pTargetCert->dwCertEncodingType,
		&(pTargetCert->pCertInfo->Subject),
		CERT_X500_NAME_STR,
		pszString,
		cbSize);
	int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, pszString, -1, NULL, 0, NULL, NULL);
	char * pszName = new char[sizeNeeded];
	WideCharToMultiByte(CP_UTF8, 0, pszString, -1, pszName, sizeNeeded, NULL, NULL);
	printf("%s", pszName);
}
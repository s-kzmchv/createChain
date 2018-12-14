#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <string.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <bitset>
#include <sstream>
#include <fstream>

void MyHandleError(char *s);

int main(void)
{
//---------------------------------------------------------
// Copyright (C) Microsoft.  All rights reserved.
// Declare and initialize variables.

    HCERTCHAINENGINE         hChainEngine;
    CERT_CHAIN_ENGINE_CONFIG ChainConfig;
    PCCERT_CHAIN_CONTEXT     pChainContext;
    HCERTSTORE               hCertStore;
    PCCERT_CONTEXT           pCertContext = NULL;
    CERT_ENHKEY_USAGE        EnhkeyUsage;
    CERT_USAGE_MATCH         CertUsage;
    CERT_CHAIN_PARA          ChainPara;
    DWORD                    dwFlags=0;
    LPWSTR                   pszNameString;



//---------------------------------------------------------
// Initialize data structures.

    /*if(!(pszNameString=(LPWSTR)malloc(256)))
        MyHandleError("Memory allocation failed.");*/

    char* nameOfCert = "SUAI_au14_28";

    const size_t cSize = strlen(nameOfCert)+1;
    wchar_t wc[cSize];
    mbstowcs (wc, nameOfCert, cSize);

    //pszNameString = "SUAI_au14_28";

    EnhkeyUsage.cUsageIdentifier = 0;
    EnhkeyUsage.rgpszUsageIdentifier=NULL;
    CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage  = EnhkeyUsage;
    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage=CertUsage;

    ChainConfig.cbSize = sizeof(CERT_CHAIN_ENGINE_CONFIG);
    ChainConfig.hRestrictedRoot= NULL ;
    ChainConfig.hRestrictedTrust= NULL ;
    ChainConfig.hRestrictedOther= NULL ;
    ChainConfig.cAdditionalStore=0 ;
    ChainConfig.rghAdditionalStore = NULL ;
    ChainConfig.dwFlags = CERT_CHAIN_CACHE_END_CERT;
    ChainConfig.dwUrlRetrievalTimeout= 0 ;
    ChainConfig.MaximumCachedCertificates=0 ;
    ChainConfig.CycleDetectionModulus = 0;

//---------------------------------------------------------
// Create the nondefault certificate chain engine.

    if(CertCreateCertificateChainEngine(
            &ChainConfig,
            &hChainEngine))
    {
        printf("A chain engine has been created.\n");
    }
    else
    {
        MyHandleError("The engine creation function failed.");
    }
// Open the My system store.

    if(hCertStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            NULL,
            CERT_SYSTEM_STORE_CURRENT_USER,
            L"MY"))
    {
        printf("The MY Store is open.\n");
    }
    else
    {
        MyHandleError("The MY system store did not open.");
    }

//-------------------------------------------------------
// Loop through the certificates in the store,
// and create a chain for each.




    if(pCertContext = CertFindCertificateInStore(
            hCertStore,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR,
            wc,
            NULL))
    {
        printf(TEXT("The signer's certificate was found.\n"));
    }
    else
    {
        MyHandleError( TEXT("Signer certificate not found."));
    }


    /*while(pCertContext = CertEnumCertificatesInStore(
            hCertStore,
            pCertContext))
    {*/
//-------------------------------------------------------------------
// Get and display the name of subject of the certificate.



        if(CertGetNameStringW(
                pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                NULL,
                pszNameString,
                128))
        {
            printf("\nCertificate for %s found.\n", reinterpret_cast<char *>(pszNameString));
        }
        else
        {
            MyHandleError("CertGetName failed.");
        }

//-------------------------------------------------------------------
// Build a chain using CertGetCertificateChain
// and the certificate retrieved.

        if(CertGetCertificateChain(
                NULL,                  // use the default chain engine
                pCertContext,          // pointer to the end certificate
                NULL,                  // use the default time
                NULL,                  // search no additional stores
                &ChainPara,            // use AND logic and enhanced key usage
                //  as indicated in the ChainPara
                //  data structure
                dwFlags,
                NULL,                  // currently reserved
                &pChainContext))       // return a pointer to the chain created
        {
            printf("The chain has been created. \n");
        }
        else
        {
            MyHandleError("The chain could not be created.");
        }



//---------------------------------------------------------------
// Display some of the contents of the chain.

        printf("The size of the chain context "
               "is %d. \n",pChainContext->cbSize);
        printf("%d simple chains found.\n",pChainContext->cChain);
        printf("\nError status for the chain:\n");

        switch(pChainContext->TrustStatus.dwErrorStatus)
        {
            case CERT_TRUST_NO_ERROR :
                printf("No error found for this certificate or chain.\n");
                break;
            case CERT_TRUST_IS_NOT_TIME_VALID:
                printf("This certificate or one of the certificates in the "
                       "certificate chain is not time-valid.\n");
                break;
            case CERT_TRUST_IS_REVOKED:
                printf("Trust for this certificate or one of the certificates "
                       "in the certificate chain has been revoked.\n");
                break;
            case CERT_TRUST_IS_NOT_SIGNATURE_VALID:
                printf("The certificate or one of the certificates in the "
                       "certificate chain does not have a valid signature.\n");
                break;
            case CERT_TRUST_IS_NOT_VALID_FOR_USAGE:
                printf("The certificate or certificate chain is not valid "
                       "in its proposed usage.\n");
                break;
            case CERT_TRUST_IS_UNTRUSTED_ROOT:
                printf("The certificate or certificate chain is based "
                       "on an untrusted root.\n");
                break;
            case CERT_TRUST_REVOCATION_STATUS_UNKNOWN:
                printf("The revocation status of the certificate or one of the"
                       "certificates in the certificate chain is unknown.\n");
                break;
            case CERT_TRUST_IS_CYCLIC :
                printf("One of the certificates in the chain was issued by a "
                       "certification authority that the original certificate "
                       "had certified.\n");
                break;
            case CERT_TRUST_IS_PARTIAL_CHAIN:
                printf("The certificate chain is not complete.\n");
                break;
            case CERT_TRUST_CTL_IS_NOT_TIME_VALID:
                printf("A CTL used to create this chain was not time-valid.\n");
                break;
            case CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID:
                printf("A CTL used to create this chain did not have a valid "
                       "signature.\n");
                break;
            case CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE:
                printf("A CTL used to create this chain is not valid for this "
                       "usage.\n");
        } // End switch

        printf("\nInfo status for the chain:\n");

        switch(pChainContext->TrustStatus.dwInfoStatus)
        {
            case 0:
                printf("No information status reported.\n");
                break;
            case CERT_TRUST_HAS_EXACT_MATCH_ISSUER :
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

// Free chain.

        CertFreeCertificateChain(pChainContext);
        printf("The chain is free.\n");
        /*printf("\nPress Enter to continue.");
        getchar();*/
    //} // end while loop

    //printf("\nThere are no more certificates in the store. \n");

//---------------------------------------------------------
// Free the chain engine.
    CertFreeCertificateChainEngine(hChainEngine);
    printf("The chain engine has been released.\n");


    if(pCertContext)
    {
        CertFreeCertificateContext(pCertContext);
    }

    if(hCertStore)
    {
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
        hCertStore = NULL;
    }

// Free memory for pszNameString.
    //if(pszNameString)
        //free(pszNameString);



} // end main

//-------------------------------------------------------------------
// This example uses the function MyHandleError, a simple error
// handling function to print an error message and exit
// the program.
// For most applications, replace this function with one
// that does more extensive error reporting.

void MyHandleError(char *s)
{
    fprintf(stderr,"An error occurred in running the program. \n");
    fprintf(stderr,"%s\n",s);
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // end MyHandleError
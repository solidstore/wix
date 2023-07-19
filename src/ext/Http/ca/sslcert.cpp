// Copyright (c) .NET Foundation and contributors. All rights reserved. Licensed under the Microsoft Reciprocal License. See LICENSE.TXT file in the project root for full license information.

#include "precomp.h"

static UINT SchedHttpSslCerts(
    __in WCA_TODO todoSched
);
static HRESULT WriteExistingSslCert(
    __in WCA_TODO action,
    __in_z LPCWSTR wzId,
    __in_z LPCWSTR wzHost,
    __in int iPort,
    __in int iHandleExisting,
    __in HTTP_SERVICE_CONFIG_SSL_SET* pSslSet,
    __inout_z LPWSTR* psczCustomActionData
);
static HRESULT WriteSslCert(
    __in WCA_TODO action,
    __in_z LPCWSTR wzId,
    __in_z LPCWSTR wzHost,
    __in int iPort,
    __in int iHandleExisting,
    __in_z LPCWSTR wzCertificateThumbprint,
    __in_z LPCWSTR wzCertificateRef,
    __in_z LPCWSTR wzAppId,
    __in_z_opt LPCWSTR wzCertificateStore,
    __inout_z LPWSTR* psczCustomActionData
);
static HRESULT EnsureAppId(
    __inout_z LPWSTR* psczAppId,
    __in_opt HTTP_SERVICE_CONFIG_SSL_SET* pExistingSslSet
);
static HRESULT StringFromGuid(
    __in REFGUID rguid,
    __inout_z LPWSTR* psczGuid
);
static HRESULT AddSslCert(
    __in_z LPCWSTR wzId,
    __in_z LPWSTR wzHost,
    __in int iPort,
    __in BYTE rgbCertificateThumbprint[],
    __in DWORD cbCertificateThumbprint,
    __in GUID* pAppId,
    __in_z LPWSTR wzSslCertStore
);
static HRESULT GetSslCert(
    __in_z LPWSTR wzHost,
    __in int nPort,
    __out HTTP_SERVICE_CONFIG_SSL_SET** ppSet
);
static HRESULT RemoveSslCert(
    __in_z LPCWSTR wzId,
    __in_z LPWSTR wzHost,
    __in int iPort
);
static HRESULT SetSslCertSetKey(
    __in HTTP_SERVICE_CONFIG_SSL_KEY* pKey,
    __in_z LPWSTR wzHost,
    __in int iPort
);
static HRESULT FindExistingCertificate(
    __in LPCWSTR wzName,
    __in DWORD dwStoreLocation,
    __in LPCWSTR wzStore,
    __out BYTE** prgbCertificate,
    __out DWORD* pcbCertificate
);

LPCWSTR vcsWixHttpSslCertQuery =
L"SELECT `WixHttpSslCert`, `Host`, `Port`, `Thumbprint`, `Certificate_`, `AppId`, `Store`, `HandleExisting`, `Component_` "
L"FROM `Wix4HttpSslCert`";
enum eWixHttpSslCertQuery { hurqId = 1, hurqHost, hurqPort, hurqCertificateThumbprint, hurqCertificateRef, hurqAppId, hurqCertificateStore, hurqHandleExisting, hurqComponent };

#define msierrCERTFailedOpen                   26351

/******************************************************************
 SchedWixHttpSslCertsInstall - immediate custom action entry
   point to prepare adding URL reservations.

********************************************************************/
extern "C" UINT __stdcall SchedHttpSslCertsInstall(
    __in MSIHANDLE hInstall
)
{
    HRESULT hr = S_OK;

    hr = WcaInitialize(hInstall, "SchedHttpSslCertsInstall");
    ExitOnFailure(hr, "Failed to initialize");

    hr = SchedHttpSslCerts(WCA_TODO_INSTALL);

LExit:
    return WcaFinalize(FAILED(hr) ? ERROR_INSTALL_FAILURE : ERROR_SUCCESS);
}

/******************************************************************
 SchedWixHttpSslCertsUninstall - immediate custom action entry
   point to prepare removing URL reservations.

********************************************************************/
extern "C" UINT __stdcall SchedHttpSslCertsUninstall(
    __in MSIHANDLE hInstall
)
{
    HRESULT hr = S_OK;

    hr = WcaInitialize(hInstall, "SchedHttpSslCertsUninstall");
    ExitOnFailure(hr, "Failed to initialize");

    hr = SchedHttpSslCerts(WCA_TODO_UNINSTALL);

LExit:
    return WcaFinalize(FAILED(hr) ? ERROR_INSTALL_FAILURE : ERROR_SUCCESS);
}

/******************************************************************
 ExecHttpSslCerts - deferred custom action entry point to
   register and remove URL reservations.

********************************************************************/
extern "C" UINT __stdcall ExecHttpSslCerts(
    __in MSIHANDLE hInstall
)
{
    HRESULT hr = S_OK;
    BOOL fHttpInitialized = FALSE;
    LPWSTR sczCustomActionData = NULL;
    LPWSTR wz = NULL;
    int iTodo = WCA_TODO_UNKNOWN;
    LPWSTR sczId = NULL;
    LPWSTR sczHost = NULL;
    int iPort = 0;
    eHandleExisting handleExisting = heIgnore;
    LPWSTR sczCertificateThumbprint = NULL;
    LPWSTR sczCertificateRef = NULL;
    LPWSTR sczAppId = NULL;
    LPWSTR sczCertificateStore = NULL;

    BOOL fRollback = ::MsiGetMode(hInstall, MSIRUNMODE_ROLLBACK);
    BOOL fRemove = FALSE;
    BOOL fAdd = FALSE;
    BOOL fFailOnExisting = FALSE;

    GUID guidAppId = { };
    BYTE* pbCertificateThumbprint = NULL;
    DWORD cbCertificateThumbprint = 0;

    // Initialize.
    hr = WcaInitialize(hInstall, "ExecHttpSslCerts");
    ExitOnFailure(hr, "Failed to initialize");

    hr = HRESULT_FROM_WIN32(::HttpInitialize(HTTPAPI_VERSION_1, HTTP_INITIALIZE_CONFIG, NULL));
    ExitOnFailure(hr, "Failed to initialize HTTP Server configuration");

    fHttpInitialized = TRUE;

    hr = WcaGetProperty(L"CustomActionData", &sczCustomActionData);
    ExitOnFailure(hr, "Failed to get CustomActionData");
    WcaLog(LOGMSG_TRACEONLY, "CustomActionData: %ls", sczCustomActionData);

    wz = sczCustomActionData;
    while (wz && *wz)
    {
        // Extract the custom action data and if rolling back, swap INSTALL and UNINSTALL.
        hr = WcaReadIntegerFromCaData(&wz, &iTodo);
        ExitOnFailure(hr, "Failed to read todo from custom action data");

        hr = WcaReadStringFromCaData(&wz, &sczId);
        ExitOnFailure(hr, "Failed to read Id from custom action data");

        hr = WcaReadStringFromCaData(&wz, &sczHost);
        ExitOnFailure(hr, "Failed to read Host from custom action data");

        hr = WcaReadIntegerFromCaData(&wz, &iPort);
        ExitOnFailure(hr, "Failed to read Port from custom action data");

        hr = WcaReadIntegerFromCaData(&wz, reinterpret_cast<int*>(&handleExisting));
        ExitOnFailure(hr, "Failed to read HandleExisting from custom action data");

        hr = WcaReadStringFromCaData(&wz, &sczCertificateThumbprint);
        ExitOnFailure(hr, "Failed to read CertificateThumbprint from custom action data");

        hr = WcaReadStringFromCaData(&wz, &sczCertificateRef);
        ExitOnFailure(hr, "Failed to read CertificateRef from custom action data");

        hr = WcaReadStringFromCaData(&wz, &sczAppId);
        ExitOnFailure(hr, "Failed to read AppId from custom action data");

        hr = WcaReadStringFromCaData(&wz, &sczCertificateStore);
        ExitOnFailure(hr, "Failed to read CertificateStore from custom action data");

        switch (iTodo)
        {
        case WCA_TODO_INSTALL:
        case WCA_TODO_REINSTALL:
            fRemove = heReplace == handleExisting || fRollback;
            fAdd = !fRollback || (*sczCertificateThumbprint || *sczCertificateRef);
            fFailOnExisting = heFail == handleExisting && !fRollback;
            break;

        case WCA_TODO_UNINSTALL:
            fRemove = !fRollback;
            fAdd = fRollback && (*sczCertificateThumbprint || *sczCertificateRef);
            fFailOnExisting = FALSE;
            break;
        }

        if (fRemove)
        {
            hr = RemoveSslCert(sczId, sczHost, iPort);
            if (S_OK == hr)
            {
                WcaLog(LOGMSG_STANDARD, "Removed SSL certificate '%ls' for hostname: %ls:%d", sczId, sczHost, iPort);
            }
            else if (FAILED(hr))
            {
                if (fRollback)
                {
                    WcaLogError(hr, "Failed to remove SSL certificate to rollback '%ls' for hostname: %ls:%d", sczId, sczHost, iPort);
                }
                else
                {
                    ExitOnFailure(hr, "Failed to remove SSL certificate '%ls' for hostname: %ls:%d", sczId, sczHost, iPort);
                }
            }
        }

        if (fAdd)
        {
            WcaLog(LOGMSG_STANDARD, "Adding SSL certificate '%ls' for hostname: %ls:%d", sczId, sczHost, iPort);

            // if we have been provided a thumbprint, then use that
            if (*sczCertificateThumbprint)
            {
                hr = StrAllocHexDecode(sczCertificateThumbprint, &pbCertificateThumbprint, &cbCertificateThumbprint);
                ExitOnFailure(hr, "Failed to convert thumbprint to bytes for SSL certificate '%ls' for hostname: %ls:%d", sczId, sczHost, iPort);
            }

            // if we have been provided with a cerificate ref, use that to find an existing certificate
            if (*sczCertificateRef)
            {
                hr = FindExistingCertificate(sczCertificateRef, CERT_SYSTEM_STORE_LOCAL_MACHINE, sczCertificateStore, &pbCertificateThumbprint, &cbCertificateThumbprint);
                ExitOnFailure(hr, "Failed to convert thumbprint to bytes for referenced SSL certificate '%ls'", sczCertificateRef);
                if (S_FALSE == hr)
                {
                    ExitOnFailure(HRESULT_FROM_WIN32(ERROR_NOT_FOUND), "Failed to find referenced SSL certificate '%ls'", sczCertificateRef);
                }

                hr = StrAllocHexEncode(pbCertificateThumbprint, cbCertificateThumbprint, &sczCertificateThumbprint);
                ExitOnFailure(hr, "Failed to convert thumbprint for referenced SSL certificate '%ls'", sczCertificateRef);
            }

            hr = ::IIDFromString(sczAppId, &guidAppId);
            ExitOnFailure(hr, "Failed to convert AppId '%ls' back to GUID for SSL certificate '%ls' for hostname: %ls:%d", sczAppId, sczId, sczHost, iPort);

            hr = AddSslCert(sczId, sczHost, iPort, pbCertificateThumbprint, cbCertificateThumbprint, &guidAppId, sczCertificateStore && *sczCertificateStore ? sczCertificateStore : L"MY");
            if (S_FALSE == hr && fFailOnExisting)
            {
                hr = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
            }

            if (S_OK == hr)
            {
                WcaLog(LOGMSG_STANDARD, "Added SSL certificate '%ls' for hostname: %ls:%d with thumbprint: %ls", sczId, sczHost, iPort, sczCertificateThumbprint);
            }
            else if (FAILED(hr))
            {
                if (fRollback)
                {
                    WcaLogError(hr, "Failed to add SSL certificate to rollback '%ls' for hostname: %ls:%d", sczId, sczHost, iPort);
                }
                else
                {
                    ExitOnFailure(hr, "Failed to add SSL certificate '%ls' for hostname: %ls:%d", sczId, sczHost, iPort);
                }
            }

            ReleaseNullMem(pbCertificateThumbprint);
        }
    }

LExit:
    ReleaseMem(pbCertificateThumbprint);
    ReleaseStr(sczCertificateStore);
    ReleaseStr(sczAppId);
    ReleaseStr(sczCertificateThumbprint);
    ReleaseStr(sczHost);
    ReleaseStr(sczId);
    ReleaseStr(sczCustomActionData);

    if (fHttpInitialized)
    {
        ::HttpTerminate(HTTP_INITIALIZE_CONFIG, NULL);
    }

    return WcaFinalize(FAILED(hr) ? ERROR_INSTALL_FAILURE : ERROR_SUCCESS);
}

static UINT SchedHttpSslCerts(
    __in WCA_TODO todoSched
)
{
    HRESULT hr = S_OK;
    //UINT er = ERROR_SUCCESS;
    BOOL fHttpInitialized = FALSE;
    DWORD cCertificates = 0;

    PMSIHANDLE hView = NULL;
    PMSIHANDLE hRec = NULL;
    PMSIHANDLE hQueryReq = NULL;
    PMSIHANDLE hAceView = NULL;

    LPWSTR sczCustomActionData = NULL;
    LPWSTR sczRollbackCustomActionData = NULL;

    LPWSTR sczId = NULL;
    LPWSTR sczComponent = NULL;
    WCA_TODO todoComponent = WCA_TODO_UNKNOWN;
    LPWSTR sczHost = NULL;
    int iPort = 0;
    LPWSTR sczCertificateThumbprint = NULL;
    LPWSTR sczCertificateRef = NULL;
    LPWSTR sczAppId = NULL;
    LPWSTR sczCertificateStore = NULL;
    int iHandleExisting = 0;

    HTTP_SERVICE_CONFIG_SSL_SET* pExistingSslSet = NULL;

    // Anything to do?
    hr = WcaTableExists(L"Wix4HttpSslCert");
    ExitOnFailure(hr, "Failed to check if the Wix4HttpSslCert table exists");
    if (S_FALSE == hr)
    {
        WcaLog(LOGMSG_STANDARD, "Wix4HttpSslCert table doesn't exist, so there are no URL reservations to configure");
        ExitFunction();
    }

    // Query and loop through all the SSL certificates.
    hr = WcaOpenExecuteView(vcsWixHttpSslCertQuery, &hView);
    ExitOnFailure(hr, "Failed to open view on the Wix4HttpSslCert table");

    hr = HRESULT_FROM_WIN32(::HttpInitialize(HTTPAPI_VERSION_1, HTTP_INITIALIZE_CONFIG, NULL));
    ExitOnFailure(hr, "Failed to initialize HTTP Server configuration");

    fHttpInitialized = TRUE;

    while (S_OK == (hr = WcaFetchRecord(hView, &hRec)))
    {
        hr = WcaGetRecordString(hRec, hurqId, &sczId);
        ExitOnFailure(hr, "Failed to get Wix4HttpSslCert.Wix4HttpSslCert");

        hr = WcaGetRecordString(hRec, hurqComponent, &sczComponent);
        ExitOnFailure(hr, "Failed to get Wix4HttpSslCert.Component_");

        // Figure out what we're doing for this reservation, treating reinstall the same as install.
        todoComponent = WcaGetComponentToDo(sczComponent);
        if ((WCA_TODO_REINSTALL == todoComponent ? WCA_TODO_INSTALL : todoComponent) != todoSched)
        {
            WcaLog(LOGMSG_STANDARD, "Component '%ls' action state (%d) doesn't match request (%d) for Wix4HttpSslCert '%ls'", sczComponent, todoComponent, todoSched, sczId);
            continue;
        }

        hr = WcaGetRecordFormattedString(hRec, hurqHost, &sczHost);
        ExitOnFailure(hr, "Failed to get Wix4HttpSslCert.Host");

        hr = WcaGetRecordFormattedInteger(hRec, hurqPort, &iPort);
        ExitOnFailure(hr, "Failed to get Wix4HttpSslCert.Port");

        hr = WcaGetRecordFormattedString(hRec, hurqCertificateThumbprint, &sczCertificateThumbprint);
        ExitOnFailure(hr, "Failed to get Wix4HttpSslCert.CertificateThumbprint");

        hr = WcaGetRecordString(hRec, hurqCertificateRef, &sczCertificateRef);
        ExitOnFailure(hr, "Failed to get Wix4HttpSslCert.CertificateRef");

        if (!sczHost || !*sczHost)
        {
            hr = E_INVALIDARG;
            ExitOnFailure(hr, "Require a Host value for Wix4HttpSslCert '%ls'", sczId);
        }

        if (!iPort)
        {
            hr = E_INVALIDARG;
            ExitOnFailure(hr, "Require a Port value for Wix4HttpSslCert '%ls'", sczId);
        }

        /*if (!sczCertificateThumbprint || !*sczCertificateThumbprint)
        {
            hr = E_INVALIDARG;
            ExitOnFailure(hr, "Require a CertificateThumbprint value for Wix4HttpSslCert '%ls'", sczId);
        }*/

        hr = WcaGetRecordFormattedString(hRec, hurqAppId, &sczAppId);
        ExitOnFailure(hr, "Failed to get AppId for Wix4HttpSslCert '%ls'", sczId);

        hr = WcaGetRecordFormattedString(hRec, hurqCertificateStore, &sczCertificateStore);
        ExitOnFailure(hr, "Failed to get CertificateStore for Wix4HttpSslCert '%ls'", sczId);

        hr = WcaGetRecordInteger(hRec, hurqHandleExisting, &iHandleExisting);
        ExitOnFailure(hr, "Failed to get HandleExisting for Wix4HttpSslCert '%ls'", sczId);

        hr = GetSslCert(sczHost, iPort, &pExistingSslSet);
        ExitOnFailure(hr, "Failed to get the existing SSL certificate for Wix4HttpSslCert '%ls'", sczId);

        hr = EnsureAppId(&sczAppId, pExistingSslSet);
        ExitOnFailure(hr, "Failed to ensure AppId for Wix4HttpSslCert '%ls'", sczId);

        hr = WriteExistingSslCert(todoComponent, sczId, sczHost, iPort, iHandleExisting, pExistingSslSet, &sczRollbackCustomActionData);
        ExitOnFailure(hr, "Failed to write rollback custom action data for Wix4HttpSslCert '%ls'", sczId);

        hr = WriteSslCert(todoComponent, sczId, sczHost, iPort, iHandleExisting, sczCertificateThumbprint, sczCertificateRef, sczAppId, sczCertificateStore, &sczCustomActionData);
        ExitOnFailure(hr, "Failed to write custom action data for Wix4HttpSslCert '%ls'", sczId);
        ++cCertificates;

        ReleaseNullMem(pExistingSslSet);
    }

    // Reaching the end of the list is not an error.
    if (E_NOMOREITEMS == hr)
    {
        hr = S_OK;
    }
    ExitOnFailure(hr, "Failure occurred while processing Wix4HttpSslCert table");

    // Schedule ExecHttpSslCerts if there's anything to do.
    if (cCertificates)
    {
        WcaLog(LOGMSG_STANDARD, "Scheduling SSL certificate (%ls)", sczCustomActionData);
        WcaLog(LOGMSG_STANDARD, "Scheduling rollback SSL certificate (%ls)", sczRollbackCustomActionData);

        if (WCA_TODO_INSTALL == todoSched)
        {
            hr = WcaDoDeferredAction(CUSTOM_ACTION_DECORATION(L"RollbackHttpSslCertsInstall"), sczRollbackCustomActionData, cCertificates * COST_HTTP_SSL);
            ExitOnFailure(hr, "Failed to schedule install SSL certificate rollback");
            hr = WcaDoDeferredAction(CUSTOM_ACTION_DECORATION(L"ExecHttpSslCertsInstall"), sczCustomActionData, cCertificates * COST_HTTP_SSL);
            ExitOnFailure(hr, "Failed to schedule install SSL certificate execution");
        }
        else
        {
            hr = WcaDoDeferredAction(CUSTOM_ACTION_DECORATION(L"RollbackHttpSslCertsUninstall"), sczRollbackCustomActionData, cCertificates * COST_HTTP_SSL);
            ExitOnFailure(hr, "Failed to schedule uninstall SSL certificate rollback");
            hr = WcaDoDeferredAction(CUSTOM_ACTION_DECORATION(L"ExecHttpSslCertsUninstall"), sczCustomActionData, cCertificates * COST_HTTP_SSL);
            ExitOnFailure(hr, "Failed to schedule uninstall SSL certificate execution");
        }
    }
    else
    {
        WcaLog(LOGMSG_STANDARD, "No SSL certificates scheduled");
    }

LExit:
    ReleaseMem(pExistingSslSet);
    ReleaseStr(sczCertificateStore);
    ReleaseStr(sczAppId);
    ReleaseStr(sczCertificateThumbprint);
    ReleaseStr(sczHost);
    ReleaseStr(sczComponent);
    ReleaseStr(sczId);
    ReleaseStr(sczRollbackCustomActionData);
    ReleaseStr(sczCustomActionData);

    if (fHttpInitialized)
    {
        ::HttpTerminate(HTTP_INITIALIZE_CONFIG, NULL);
    }

    return hr;
}

static HRESULT WriteExistingSslCert(
    __in WCA_TODO action,
    __in_z LPCWSTR wzId,
    __in_z LPCWSTR wzHost,
    __in int iPort,
    __in int iHandleExisting,
    __in HTTP_SERVICE_CONFIG_SSL_SET* pSslSet,
    __inout_z LPWSTR* psczCustomActionData
)
{
    HRESULT hr = S_OK;
    LPWSTR sczCertificateThumbprint = NULL;
    LPWSTR sczAppId = NULL;
    LPCWSTR wzCertificateStore = NULL;

    if (pSslSet)
    {
        hr = StrAllocHexEncode(reinterpret_cast<BYTE*>(pSslSet->ParamDesc.pSslHash), pSslSet->ParamDesc.SslHashLength, &sczCertificateThumbprint);
        ExitOnFailure(hr, "Failed to convert existing certificate thumbprint to hex for Wix4HttpSslCert '%ls'", wzId);

        hr = StringFromGuid(pSslSet->ParamDesc.AppId, &sczAppId);
        ExitOnFailure(hr, "Failed to copy existing AppId for Wix4HttpSslCert '%ls'", wzId);

        wzCertificateStore = pSslSet->ParamDesc.pSslCertStoreName;
    }

    hr = WriteSslCert(action, wzId, wzHost, iPort, iHandleExisting, sczCertificateThumbprint ? sczCertificateThumbprint : L"", NULL, sczAppId ? sczAppId : L"", wzCertificateStore ? wzCertificateStore : L"", psczCustomActionData);
    ExitOnFailure(hr, "Failed to write custom action data for Wix4HttpSslCert '%ls'", wzId);

LExit:
    ReleaseStr(sczAppId);
    ReleaseStr(sczCertificateThumbprint);

    return hr;
}

static HRESULT WriteSslCert(
    __in WCA_TODO action,
    __in_z LPCWSTR wzId,
    __in_z LPCWSTR wzHost,
    __in int iPort,
    __in int iHandleExisting,
    __in_z LPCWSTR wzCertificateThumbprint,
    __in_z LPCWSTR wzCertificateRef,
    __in_z LPCWSTR wzAppId,
    __in_z_opt LPCWSTR wzCertificateStore,
    __inout_z LPWSTR* psczCustomActionData
)
{
    HRESULT hr = S_OK;

    hr = WcaWriteIntegerToCaData(action, psczCustomActionData);
    ExitOnFailure(hr, "Failed to write action to custom action data");

    hr = WcaWriteStringToCaData(wzId, psczCustomActionData);
    ExitOnFailure(hr, "Failed to write id to custom action data");

    hr = WcaWriteStringToCaData(wzHost, psczCustomActionData);
    ExitOnFailure(hr, "Failed to write Host to custom action data");

    hr = WcaWriteIntegerToCaData(iPort, psczCustomActionData);
    ExitOnFailure(hr, "Failed to write Port to custom action data");

    hr = WcaWriteIntegerToCaData(iHandleExisting, psczCustomActionData);
    ExitOnFailure(hr, "Failed to write HandleExisting to custom action data");

    hr = WcaWriteStringToCaData(wzCertificateThumbprint ? wzCertificateThumbprint : L"", psczCustomActionData);
    ExitOnFailure(hr, "Failed to write CertificateThumbprint to custom action data");

    hr = WcaWriteStringToCaData(wzCertificateRef ? wzCertificateRef : L"", psczCustomActionData);
    ExitOnFailure(hr, "Failed to write CertificateRef to custom action data");

    hr = WcaWriteStringToCaData(wzAppId, psczCustomActionData);
    ExitOnFailure(hr, "Failed to write AppId to custom action data");

    hr = WcaWriteStringToCaData(wzCertificateStore ? wzCertificateStore : L"", psczCustomActionData);
    ExitOnFailure(hr, "Failed to write CertificateStore to custom action data");

LExit:
    return hr;
}

static HRESULT EnsureAppId(
    __inout_z LPWSTR* psczAppId,
    __in_opt HTTP_SERVICE_CONFIG_SSL_SET* pExistingSslSet
)
{
    HRESULT hr = S_OK;
    RPC_STATUS rs = RPC_S_OK;
    GUID guid = { };

    if (!psczAppId || !*psczAppId || !**psczAppId)
    {
        if (pExistingSslSet)
        {
            hr = StringFromGuid(pExistingSslSet->ParamDesc.AppId, psczAppId);
            ExitOnFailure(hr, "Failed to ensure AppId guid");
        }
        else
        {
            rs = ::UuidCreate(&guid);
            hr = HRESULT_FROM_RPC(rs);
            ExitOnRootFailure(hr, "Failed to create guid for AppId");

            hr = StringFromGuid(guid, psczAppId);
            ExitOnFailure(hr, "Failed to ensure AppId guid");
        }
    }

LExit:
    return hr;
}

static HRESULT StringFromGuid(
    __in REFGUID rguid,
    __inout_z LPWSTR* psczGuid
)
{
    HRESULT hr = S_OK;
    WCHAR wzGuid[39];

    if (!::StringFromGUID2(rguid, wzGuid, countof(wzGuid)))
    {
        hr = E_OUTOFMEMORY;
        ExitOnRootFailure(hr, "Failed to convert guid into string");
    }

    hr = StrAllocString(psczGuid, wzGuid, 0);
    ExitOnFailure(hr, "Failed to copy guid");

LExit:
    return hr;
}

static HRESULT AddSslCert(
    __in_z LPCWSTR /*wzId*/,
    __in_z LPWSTR wzHost,
    __in int iPort,
    __in BYTE rgbCertificateThumbprint[],
    __in DWORD cbCertificateThumbprint,
    __in GUID* pAppId,
    __in_z LPWSTR wzSslCertStore
)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;
    HTTP_SERVICE_CONFIG_SSL_SET set = { };
    SOCKADDR_STORAGE addr = { };

    set.KeyDesc.pIpPort = reinterpret_cast<PSOCKADDR>(&addr);
    SetSslCertSetKey(&set.KeyDesc, wzHost, iPort);
    set.ParamDesc.SslHashLength = cbCertificateThumbprint;
    set.ParamDesc.pSslHash = rgbCertificateThumbprint;
    set.ParamDesc.AppId = *pAppId;
    set.ParamDesc.pSslCertStoreName = wzSslCertStore;

    er = ::HttpSetServiceConfiguration(NULL, HttpServiceConfigSSLCertInfo, &set, sizeof(set), NULL);
    if (ERROR_ALREADY_EXISTS == er)
    {
        hr = S_FALSE;
    }
    else
    {
        hr = HRESULT_FROM_WIN32(er);
    }

    return hr;
}

static HRESULT GetSslCert(
    __in_z LPWSTR wzHost,
    __in int nPort,
    __out HTTP_SERVICE_CONFIG_SSL_SET** ppSet
)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;
    HTTP_SERVICE_CONFIG_SSL_QUERY query = { };
    HTTP_SERVICE_CONFIG_SSL_SET* pSet = NULL;
    ULONG cbSet = 0;
    SOCKADDR_STORAGE addr = { };

    *ppSet = NULL;

    query.QueryDesc = HttpServiceConfigQueryExact;
    query.KeyDesc.pIpPort = reinterpret_cast<PSOCKADDR>(&addr);
    SetSslCertSetKey(&query.KeyDesc, wzHost, nPort);

    er = ::HttpQueryServiceConfiguration(NULL, HttpServiceConfigSSLCertInfo, &query, sizeof(query), pSet, cbSet, &cbSet, NULL);
    if (ERROR_INSUFFICIENT_BUFFER == er)
    {
        pSet = reinterpret_cast<HTTP_SERVICE_CONFIG_SSL_SET*>(MemAlloc(cbSet, TRUE));
        ExitOnNull(pSet, hr, E_OUTOFMEMORY, "Failed to allocate query SSL certificate buffer");

        er = ::HttpQueryServiceConfiguration(NULL, HttpServiceConfigSSLCertInfo, &query, sizeof(query), pSet, cbSet, &cbSet, NULL);
    }

    if (ERROR_SUCCESS == er)
    {
        *ppSet = pSet;
        pSet = NULL;
    }
    else if (ERROR_FILE_NOT_FOUND == er)
    {
        hr = S_FALSE;
    }
    else
    {
        hr = HRESULT_FROM_WIN32(er);
    }

LExit:
    ReleaseMem(pSet);

    return hr;
}

static HRESULT RemoveSslCert(
    __in_z LPCWSTR /*wzId*/,
    __in_z LPWSTR wzHost,
    __in int iPort
)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;
    HTTP_SERVICE_CONFIG_SSL_SET set = { };
    SOCKADDR_STORAGE addr = { };

    set.KeyDesc.pIpPort = reinterpret_cast<PSOCKADDR>(&addr);
    SetSslCertSetKey(&set.KeyDesc, wzHost, iPort);

    er = ::HttpDeleteServiceConfiguration(NULL, HttpServiceConfigSSLCertInfo, &set, sizeof(set), NULL);
    if (ERROR_FILE_NOT_FOUND == er)
    {
        hr = S_FALSE;
    }
    else
    {
        hr = HRESULT_FROM_WIN32(er);
    }

    return hr;
}

static HRESULT SetSslCertSetKey(
    __in HTTP_SERVICE_CONFIG_SSL_KEY* pKey,
    __in_z LPWSTR wzHost,
    __in int iPort
)
{
    DWORD er = ERROR_SUCCESS;

    SOCKADDR_IN* pss = reinterpret_cast<SOCKADDR_IN*>(pKey->pIpPort);
    pss->sin_family = AF_INET;
    pss->sin_port = htons(static_cast<USHORT>(iPort));
    if (!InetPtonW(AF_INET, wzHost, &pss->sin_addr))
    {
        er = WSAGetLastError();
    }

    HRESULT hr = HRESULT_FROM_WIN32(er);
    return hr;
}

static HRESULT FindExistingCertificate(
    __in LPCWSTR wzName,
    __in DWORD dwStoreLocation,
    __in LPCWSTR wzStore,
    __out BYTE** ppbCertificateThumbprint,
    __out DWORD* pcbCertificateThumbprint
)
{
    HRESULT hr = S_FALSE;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BYTE* pbCertificateThumbprint = NULL;
    DWORD cbCertificateThumbprint = 0;

    hCertStore = ::CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, dwStoreLocation | CERT_STORE_READONLY_FLAG, wzStore);
    MessageExitOnNullWithLastError(hCertStore, hr, msierrCERTFailedOpen, "Failed to open certificate store.");

    // Loop through the certificate, looking for certificates that match our friendly name.
    pCertContext = CertFindCertificateInStore(hCertStore, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);
    while (pCertContext)
    {
        WCHAR wzFriendlyName[256] = { 0 };
        DWORD cbFriendlyName = sizeof(wzFriendlyName);

        if (::CertGetCertificateContextProperty(pCertContext, CERT_FRIENDLY_NAME_PROP_ID, reinterpret_cast<BYTE*>(wzFriendlyName), &cbFriendlyName))
        {
            LPCWSTR wzFound = wcsistr(wzFriendlyName, wzName);
            if (wzFound && wzFound == wzFriendlyName)
            {
                // If the certificate with matching friendly name is valid, let's use that.
                long lVerify = ::CertVerifyTimeValidity(NULL, pCertContext->pCertInfo);
                if (0 == lVerify)
                {
                    byte thumb[64] = { 0 };
                    cbCertificateThumbprint = sizeof(thumb);
                    if (!CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, thumb, &cbCertificateThumbprint))
                    {
                        ExitFunctionWithLastError(hr);
                    }

                    pbCertificateThumbprint = static_cast<BYTE*>(MemAlloc(cbCertificateThumbprint, FALSE));
                    ExitOnNull(pbCertificateThumbprint, hr, E_OUTOFMEMORY, "Failed to allocate memory to copy out exist certificate thumbprint.");

                    CopyMemory(pbCertificateThumbprint, thumb, cbCertificateThumbprint);
                    hr = S_OK;
                    break; // found a matching certificate, no more searching necessary
                }
            }
        }

        // Next certificate in the store.
        PCCERT_CONTEXT pNext = ::CertFindCertificateInStore(hCertStore, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, pCertContext);
        // old pCertContext is freed by CertFindCertificateInStore
        pCertContext = pNext;
    }

    *ppbCertificateThumbprint = pbCertificateThumbprint;
    *pcbCertificateThumbprint = cbCertificateThumbprint;
    pbCertificateThumbprint = NULL;

LExit:
    ReleaseMem(pbCertificateThumbprint);

    if (pCertContext)
    {
        ::CertFreeCertificateContext(pCertContext);
    }

    if (hCertStore)
    {
        ::CertCloseStore(hCertStore, 0);
    }

    return hr;
}

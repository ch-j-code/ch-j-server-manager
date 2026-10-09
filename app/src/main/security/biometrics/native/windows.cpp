#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincred.h>
#include <wincrypt.h>
#include <UserConsentVerifierInterop.h>
#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Security.Credentials.UI.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Data::Json;
using namespace Windows::Security::Credentials::UI;
struct Failure : std::runtime_error { using std::runtime_error::runtime_error; };
void fail(char const* code) { throw Failure(code); }
std::vector<BYTE> decode(hstring const& value) {
    DWORD size=0;
    if(!CryptStringToBinaryW(value.c_str(),static_cast<DWORD>(value.size()),CRYPT_STRING_BASE64|CRYPT_STRING_STRICT,nullptr,&size,nullptr,nullptr) || size!=32) fail("BIOMETRIC_INVALID_KEY");
    std::vector<BYTE> data(size);
    if(!CryptStringToBinaryW(value.c_str(),static_cast<DWORD>(value.size()),CRYPT_STRING_BASE64|CRYPT_STRING_STRICT,data.data(),&size,nullptr,nullptr)) fail("BIOMETRIC_INVALID_KEY");
    return data;
}
std::string encode(BYTE const* data,DWORD size) {
    DWORD count=0;check_bool(CryptBinaryToStringA(data,size,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,nullptr,&count));
    std::string out(count,'\0');check_bool(CryptBinaryToStringA(data,size,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,out.data(),&count));out.resize(count-1);return out;
}
void authenticate(JsonObject const& request) {
    HWND hwnd=reinterpret_cast<HWND>(std::stoull(to_string(request.GetNamedString(L"hwnd"))));
    DWORD owner=0;GetWindowThreadProcessId(hwnd,&owner);
    if(!IsWindow(hwnd) || owner!=static_cast<DWORD>(request.GetNamedNumber(L"pid"))) fail("BIOMETRIC_CANCELLED");
    auto interop=get_activation_factory<UserConsentVerifier,IUserConsentVerifierInterop>();
    IAsyncOperation<UserConsentVerificationResult> operation{nullptr};
    auto reason=request.GetNamedString(L"reason");
    check_hresult(interop->RequestVerificationForWindowAsync(hwnd,reinterpret_cast<HSTRING>(get_abi(reason)),guid_of<decltype(operation)>(),put_abi(operation)));
    auto result=operation.get();
    if(result==UserConsentVerificationResult::Verified) return; // Includes Hello PIN.
    if(result==UserConsentVerificationResult::Canceled) fail("BIOMETRIC_CANCELLED");
    if(result==UserConsentVerificationResult::DeviceBusy) fail("BIOMETRIC_DEVICE_UNAVAILABLE");
    if(result==UserConsentVerificationResult::RetriesExhausted) fail("BIOMETRIC_DEVICE_UNAVAILABLE");
    fail("BIOMETRIC_FAILED");
}
JsonObject run(JsonObject const& request) {
    auto op=request.GetNamedString(L"op");JsonObject response;response.SetNamedValue(L"ok",JsonValue::CreateBooleanValue(true));
    if(op==L"status") {
        auto result=UserConsentVerifier::CheckAvailabilityAsync().get();
        response.SetNamedValue(L"available",JsonValue::CreateBooleanValue(result==UserConsentVerifierAvailability::Available));
        response.SetNamedValue(L"code",JsonValue::CreateStringValue(result==UserConsentVerifierAvailability::Available?L"BIOMETRIC_AVAILABLE":result==UserConsentVerifierAvailability::NotConfiguredForUser?L"BIOMETRIC_NO_ENROLLMENT":result==UserConsentVerifierAvailability::DeviceBusy?L"BIOMETRIC_DEVICE_UNAVAILABLE":L"BIOMETRIC_UNAVAILABLE"));return response;
    }
    if(op==L"authenticate") {authenticate(request);return response;}
    auto entry=request.GetNamedString(L"entryId");if(entry.size()!=64 || std::wstring(entry).find_first_not_of(L"0123456789abcdef")!=std::wstring::npos)fail("BIOMETRIC_FAILED");
    auto target=L"CHJ.ServerManager.Vault.Biometry.v1:"+std::wstring(entry);
    DATA_BLOB entropy{static_cast<DWORD>(entry.size()*sizeof(wchar_t)),reinterpret_cast<BYTE*>(const_cast<wchar_t*>(entry.c_str()))};
    if(op==L"remove") {if(!CredDeleteW(target.c_str(),CRED_TYPE_GENERIC,0) && GetLastError()!=ERROR_NOT_FOUND)fail("BIOMETRIC_CREDENTIAL_FAILED");return response;}
    if(op==L"store") {
        auto bytes=decode(request.GetNamedString(L"key"));DATA_BLOB input{static_cast<DWORD>(bytes.size()),bytes.data()},output{};
        if(!CryptProtectData(&input,L"CH-J Vault",&entropy,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output)){SecureZeroMemory(bytes.data(),bytes.size());fail("BIOMETRIC_CREDENTIAL_FAILED");}
        SecureZeroMemory(bytes.data(),bytes.size());
        CREDENTIALW credential{};credential.Type=CRED_TYPE_GENERIC;credential.TargetName=target.data();credential.CredentialBlobSize=output.cbData;credential.CredentialBlob=output.pbData;credential.Persist=CRED_PERSIST_LOCAL_MACHINE;credential.UserName=const_cast<LPWSTR>(L"CH-J Server Manager");
        BOOL ok=CredWriteW(&credential,0);SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);if(!ok)fail("BIOMETRIC_CREDENTIAL_FAILED");return response;
    }
    if(op==L"retrieve") {
        authenticate(request);PCREDENTIALW credential=nullptr;
        if(!CredReadW(target.c_str(),CRED_TYPE_GENERIC,0,&credential))fail(GetLastError()==ERROR_NOT_FOUND?"BIOMETRIC_ENROLLMENT_INVALIDATED":"BIOMETRIC_CREDENTIAL_FAILED");
        DATA_BLOB input{credential->CredentialBlobSize,credential->CredentialBlob},output{};
        BOOL ok=CryptUnprotectData(&input,nullptr,&entropy,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output);CredFree(credential);
        if(!ok)fail("BIOMETRIC_CREDENTIAL_FAILED");
        if(output.cbData!=32){SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);fail("BIOMETRIC_INVALID_KEY");}
        auto encoded=encode(output.pbData,output.cbData);SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);
        response.SetNamedValue(L"key",JsonValue::CreateStringValue(to_hstring(encoded)));SecureZeroMemory(encoded.data(),encoded.size());return response;
    }
    fail("BIOMETRIC_FAILED");return response;
}
int main() {
    try {
        init_apartment(apartment_type::multi_threaded);
        std::string input;std::getline(std::cin,input);if(input.size()>4096)fail("BIOMETRIC_FAILED");
        auto request=JsonObject::Parse(to_hstring(input));SecureZeroMemory(input.data(),input.size());
        auto response=run(request);std::cout<<to_string(response.Stringify());return 0;
    } catch(Failure const& e) {std::cout<<"{\"ok\":false,\"code\":\""<<e.what()<<"\"}";return 1;}
      catch(...) {std::cout<<"{\"ok\":false,\"code\":\"BIOMETRIC_UNAVAILABLE\"}";return 1;}
}

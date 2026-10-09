import Foundation
import Security
import LocalAuthentication

struct Failure: Error { let code: String }
let service = "de.ch-j.servermanager.vault.biometry.v1"
func fail(_ code: String) throws -> Never { throw Failure(code: code) }
func authenticate(_ reason: String) throws {
    let context = LAContext()
    context.localizedFallbackTitle = "" // Master-password fallback is in the application.
    let semaphore = DispatchSemaphore(value: 0)
    var accepted = false
    var failure: Error?
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
        accepted = ok; failure = error; semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + 60) == .timedOut { context.invalidate(); try fail("BIOMETRIC_TIMEOUT") }
    if !accepted {
        let code = (failure as? LAError)?.code
        if code == .userCancel || code == .appCancel || code == .systemCancel { try fail("BIOMETRIC_CANCELLED") }
        if code == .biometryLockout { try fail("BIOMETRIC_DEVICE_UNAVAILABLE") }
        try fail("BIOMETRIC_FAILED")
    }
}
func keychainFailure(_ status: OSStatus) throws -> Never {
    if status == errSecUserCanceled { try fail("BIOMETRIC_CANCELLED") }
    if status == errSecItemNotFound { try fail("BIOMETRIC_ENROLLMENT_INVALIDATED") }
    if status == errSecNotAvailable || status == errSecInteractionNotAllowed { try fail("BIOMETRIC_DEVICE_UNAVAILABLE") }
    try fail("BIOMETRIC_CREDENTIAL_FAILED")
}
func run() throws -> [String: Any] {
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard input.count <= 4096, let request = try JSONSerialization.jsonObject(with: input) as? [String: Any], let op = request["op"] as? String else { try fail("BIOMETRIC_FAILED") }
    let reason = request["reason"] as? String ?? "Unlock CH-J Server Manager"
    if op == "status" {
        let context = LAContext(); var error: NSError?
        let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        let code = available ? "BIOMETRIC_AVAILABLE" : error?.code == LAError.biometryNotEnrolled.rawValue ? "BIOMETRIC_NO_ENROLLMENT" : error?.code == LAError.biometryLockout.rawValue ? "BIOMETRIC_DEVICE_UNAVAILABLE" : "BIOMETRIC_UNAVAILABLE"
        return ["ok": true, "available": available, "code": code]
    }
    if op == "authenticate" { try authenticate(reason); return ["ok": true] }
    guard let entry = request["entryId"] as? String, entry.count == 64, entry.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { try fail("BIOMETRIC_FAILED") }
    var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: entry]
    if op == "remove" {
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound { try keychainFailure(status) }
        return ["ok": true]
    }
    if op == "store" {
        guard let encoded = request["key"] as? String, var key = Data(base64Encoded: encoded), key.count == 32 else { try fail("BIOMETRIC_INVALID_KEY") }
        defer { key.resetBytes(in: 0..<key.count) }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryCurrentSet, &error) else { try fail("BIOMETRIC_UNAVAILABLE") }
        query[kSecAttrAccessControl as String] = access
        query[kSecValueData as String] = key
        query[kSecAttrSynchronizable as String] = false
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess { try keychainFailure(status) }
        return ["ok": true]
    }
    if op == "retrieve" {
        let context = LAContext(); context.localizedFallbackTitle = ""
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = reason
        query[kSecUseAuthenticationContext as String] = context
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status != errSecSuccess { try keychainFailure(status) }
        guard var key = result as? Data, key.count == 32 else { try fail("BIOMETRIC_INVALID_KEY") }
        defer { key.resetBytes(in: 0..<key.count) }
        return ["ok": true, "key": key.base64EncodedString()]
    }
    try fail("BIOMETRIC_FAILED")
}
do {
    let value = try run()
    FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: value)); exit(0)
} catch {
    let code = (error as? Failure)?.code ?? "BIOMETRIC_FAILED"
    let result = ["ok": false, "code": code] as [String: Any]
    if let data = try? JSONSerialization.data(withJSONObject: result) { FileHandle.standardOutput.write(data) }
    exit(1)
}

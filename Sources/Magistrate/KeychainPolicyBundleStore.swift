// Sources/Magistrate/KeychainPolicyBundleStore.swift
// Default rollback-resistant PolicyBundleStore backed by the iOS/macOS Keychain.
//
// The persisted record's `version` is the downgrade anchor, so it lives in the
// Keychain (survives relaunch; a `kSecAttrAccessibleAfterFirstUnlock` item is not
// world-readable and resists casual tampering) rather than a plain file. A fully
// rollback-proof anchor (a hardware monotonic counter) is a future hardening; this
// raises the bar to the platform secure store, matching the base SDK's own
// anchoring.

import Foundation
import Security

public struct KeychainPolicyBundleStore: PolicyBundleStore {
    private let service: String
    private let account: String

    /// - Parameters:
    ///   - service: Keychain service tag. Default namespaces the item to this
    ///     module; override to isolate multiple tenants/licenses in one app.
    ///   - account: Keychain account key within `service`.
    public init(service: String = "com.octetproof.policy.bundle",
                account: String = "active") {
        self.service = service
        self.account = account
    }

    public func load() -> PolicyBundleRecord? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else {
            return nil
        }
        return try? JSONDecoder().decode(PolicyBundleRecord.self, from: data)
    }

    public func save(_ record: PolicyBundleRecord) {
        guard let data = try? JSONEncoder().encode(record) else { return }
        let attrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        // Update in place if present, else add.
        let status = SecItemUpdate(baseQuery() as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var add = baseQuery()
            add.merge(attrs) { _, new in new }
            SecItemAdd(add as CFDictionary, nil)
        }
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

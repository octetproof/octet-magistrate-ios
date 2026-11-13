// Sources/Magistrate/BundleCache.swift
// The last-known-VALID bundle cache: an in-memory value with optional write-through
// to a persistent PolicyBundleStore. Factored out of Magistrate so the
// load-on-init + write-through behaviour is unit-testable without a started
// OctetSdk.

import Foundation

final class BundleCache: @unchecked Sendable {
    private let lock = NSLock()
    private var memory: PolicyBundleRecord?
    private let store: PolicyBundleStore?

    /// Seeds the in-memory value from the store (cross-launch load). With no store,
    /// the cache is in-memory only for the instance's lifetime.
    init(store: PolicyBundleStore?) {
        self.store = store
        self.memory = store?.load()
    }

    /// The current last-`VALID` record, or nil if none has been adopted / restored.
    func current() -> PolicyBundleRecord? {
        lock.lock(); defer { lock.unlock() }
        return memory
    }

    /// Adopt a freshly-verified bundle: update memory and write through to the
    /// store. The caller carries the anchor forward (`version ?? previous`) so a
    /// bundle whose version can't be read never regresses the downgrade anchor.
    func adopt(_ record: PolicyBundleRecord) {
        lock.lock()
        memory = record
        lock.unlock()
        store?.save(record)
    }
}

// FirebasePublicKeys.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import JWTKit
import Logging
import ServiceLifecycle

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Manages Firebase ID token signing keys for verification.
///
/// Firebase rotates its signing keys periodically (~daily). This actor
/// fetches the JWKS, exposes a ``verify(_:as:)`` method for incoming tokens,
/// and refreshes the key set based on the `Cache-Control: max-age` header
/// returned by Google's JWKS endpoint.
///
/// ## Lifecycle
///
/// Conforms to ``Service`` from `swift-service-lifecycle`. Registered into a
/// `swift-service-lifecycle` ServiceGroup, ``run()`` performs the initial
/// fetch and then loops indefinitely, sleeping until the next refresh deadline.
///
/// For one-shot use (tests, scripts) without a service loop, call
/// ``prefetch()`` directly before ``verify(_:as:)``.
///
/// ## Emulator
///
/// Pass `emulatorHost: "http://localhost:9099"` (or wherever your emulator runs)
/// to fetch keys from the Firebase Auth emulator instead of production.
public actor FirebasePublicKeys: Service {

    /// Production JWKS endpoint published by Google.
    public static let productionJWKSURL =
        "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"

    /// Default refresh interval if the JWKS response doesn't include a
    /// usable `Cache-Control: max-age` header. Conservative value below the
    /// typical ~1-day Firebase rotation cadence.
    public static let defaultRefreshInterval: Duration = .seconds(3600)

    /// Minimum allowed refresh interval (avoids hammering the JWKS endpoint
    /// if upstream returns a tiny `max-age`).
    public static let minimumRefreshInterval: Duration = .seconds(60)

    private let projectId: String
    private let jwksURL: URL
    private let session: URLSession
    private let logger: Logger
    private var keys: JWTKeyCollection
    private var lastRefreshAt: Date?
    private var nextRefreshAfter: Duration

    // MARK: - Init

    /// Create a key set for production Firebase.
    public init(
        projectId: String,
        emulatorHost: String? = nil,
        session: URLSession = .shared,
        logger: Logger = Logger(label: "firebase.auth.keys")
    ) {
        self.projectId = projectId
        if let host = emulatorHost {
            // Auth emulator exposes JWKS at /www.googleapis.com/securetoken@system.gserviceaccount.com
            // when using the standard Auth emulator URL. Strip trailing slash for safety.
            let base = host.hasSuffix("/") ? String(host.dropLast()) : host
            self.jwksURL = URL(string: "\(base)/www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")!
        } else {
            self.jwksURL = URL(string: Self.productionJWKSURL)!
        }
        self.session = session
        self.logger = logger
        self.keys = JWTKeyCollection()
        self.nextRefreshAfter = Self.defaultRefreshInterval
    }

    /// Create a key set with a pre-populated `JWTKeyCollection` (for tests).
    /// `run()` is a no-op; ``verify(_:as:)`` works immediately.
    public init(testProjectId: String, preloadedKeys: JWTKeyCollection) {
        self.projectId = testProjectId
        self.jwksURL = URL(string: Self.productionJWKSURL)!
        self.session = .shared
        self.logger = Logger(label: "firebase.auth.keys.test")
        self.keys = preloadedKeys
        self.nextRefreshAfter = Self.defaultRefreshInterval
        self.lastRefreshAt = Date()
    }

    // MARK: - Service conformance

    public func run() async throws {
        try await prefetch()
        try await cancelWhenGracefulShutdown {
            while !Task.isCancelled {
                let sleepFor = await self.nextRefreshAfter
                try await Task.sleep(for: sleepFor)
                await self.refreshAndHandleErrors()
            }
        }
    }

    /// Wraps `prefetch()` and resets the refresh interval on failure. Isolated
    /// so the actor can mutate `nextRefreshAfter` from inside `run()`'s loop.
    private func refreshAndHandleErrors() async {
        do {
            try await prefetch()
        } catch {
            logger.warning(
                "JWKS refresh failed; will retry after default interval",
                metadata: ["error": "\(error)"]
            )
            nextRefreshAfter = Self.defaultRefreshInterval
        }
    }

    // MARK: - Fetch

    /// Fetch the JWKS once and replace the in-memory key collection.
    ///
    /// Updates ``nextRefreshAfter`` from the response's `Cache-Control` header.
    public func prefetch() async throws {
        var request = URLRequest(url: jwksURL)
        request.httpMethod = "GET"
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw FirebaseAuthError.jwksFetchFailed("HTTP \(code)")
        }
        guard let json = String(data: data, encoding: .utf8) else {
            throw FirebaseAuthError.jwksFetchFailed("Response is not valid UTF-8")
        }

        // Replace key collection wholesale so retired keys disappear.
        let next = JWTKeyCollection()
        do {
            _ = try await next.add(jwksJSON: json)
        } catch {
            throw FirebaseAuthError.jwksFetchFailed("JWKS parse error: \(error)")
        }
        self.keys = next
        self.lastRefreshAt = Date()
        self.nextRefreshAfter = Self.parseRefreshInterval(from: http)
        logger.info(
            "Refreshed Firebase JWKS",
            metadata: ["nextRefreshSeconds": "\(nextRefreshAfter.components.seconds)"]
        )
    }

    // MARK: - Verify

    /// Verify a token and return the parsed payload.
    ///
    /// - Parameter token: The raw JWT string (without `Bearer ` prefix).
    /// - Returns: A verified `FirebaseIDToken`.
    /// - Throws: `JWTError` from JWTKit on signature/claim verification failure,
    ///   or ``FirebaseAuthError/audienceMismatch(expected:actual:)`` if the
    ///   token's audience doesn't match the configured project ID.
    public func verify(_ token: String) async throws -> FirebaseIDToken {
        let payload: FirebaseIDToken = try await keys.verify(token, as: FirebaseIDToken.self)
        try payload.verify(projectId: projectId)
        return payload
    }

    // MARK: - Internals

    /// Parse the refresh interval from a JWKS response's `Cache-Control: max-age=N`.
    /// Falls back to ``defaultRefreshInterval`` when absent or unparseable.
    /// Clamped to ``minimumRefreshInterval`` minimum.
    static func parseRefreshInterval(from response: HTTPURLResponse) -> Duration {
        guard let cacheControl = response.value(forHTTPHeaderField: "Cache-Control") else {
            return defaultRefreshInterval
        }
        for part in cacheControl.split(separator: ",") {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("max-age=") {
                let value = trimmed.dropFirst("max-age=".count)
                if let seconds = Int64(value) {
                    let candidate = Duration.seconds(seconds)
                    return candidate.components.seconds < minimumRefreshInterval.components.seconds
                        ? minimumRefreshInterval
                        : candidate
                }
            }
        }
        return defaultRefreshInterval
    }
}

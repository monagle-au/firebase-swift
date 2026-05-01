// FirebaseAuthError.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

/// Errors thrown by Firebase token verification or JWKS fetching.
public enum FirebaseAuthError: Error, Sendable, CustomStringConvertible {
    /// The token's `aud` (audience) claim is empty or malformed.
    case malformedAudience
    /// The token's `iss` (issuer) claim doesn't match the expected Firebase issuer URL.
    case invalidIssuer(expected: String, actual: String)
    /// The token's `aud` (audience) claim doesn't match the configured project ID.
    case audienceMismatch(expected: String, actual: String)
    /// The token's `sub` (subject) claim is empty or longer than 255 characters.
    case invalidSubject
    /// The token has not been verified against any signing key (no keys loaded).
    case noKeysAvailable
    /// JWKS fetch failed (network or parsing error).
    case jwksFetchFailed(String)

    public var description: String {
        switch self {
        case .malformedAudience:
            return "Firebase ID token has empty or malformed audience claim"
        case .invalidIssuer(let expected, let actual):
            return "Firebase ID token issuer mismatch (expected \(expected), got \(actual))"
        case .audienceMismatch(let expected, let actual):
            return "Firebase ID token audience mismatch (expected \(expected), got \(actual))"
        case .invalidSubject:
            return "Firebase ID token subject is empty or exceeds 255 characters"
        case .noKeysAvailable:
            return "No Firebase public keys loaded; call prefetch() or run() first"
        case .jwksFetchFailed(let message):
            return "Failed to fetch Firebase JWKS: \(message)"
        }
    }
}

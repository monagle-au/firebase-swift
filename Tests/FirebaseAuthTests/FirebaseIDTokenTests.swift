// FirebaseIDTokenTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import JWTKit
@testable import FirebaseAuth

@Suite("FirebaseIDToken")
struct FirebaseIDTokenTests {

    // MARK: - Helpers

    private static let testProjectID = "test-project"

    /// Build a JWTKeyCollection with a freshly generated ES256 key pair.
    private func makeKeyCollection() async throws -> (collection: JWTKeyCollection, kid: JWKIdentifier) {
        let kid = JWKIdentifier(string: "test-kid-1")
        let key = ES256PrivateKey()
        let collection = JWTKeyCollection()
        try await collection.add(ecdsa: key, kid: kid)
        return (collection, kid)
    }

    /// Issue a Firebase-shaped token signed with the given collection's key.
    private func issueToken(
        with collection: JWTKeyCollection,
        kid: JWKIdentifier,
        projectId: String = testProjectID,
        expiresIn: TimeInterval = 3600,
        userID: String = "abc123",
        email: String? = "user@example.com"
    ) async throws -> String {
        let now = Date()
        let payload = FirebaseIDToken(
            issuer: .init(value: "https://securetoken.google.com/\(projectId)"),
            subject: .init(value: userID),
            audience: .init(value: [projectId]),
            issuedAt: .init(value: now),
            expires: .init(value: now.addingTimeInterval(expiresIn)),
            authTime: now,
            userID: userID,
            email: email,
            firebase: FirebaseIDToken.FirebaseClaims(signInProvider: "password")
        )
        return try await collection.sign(payload, kid: kid)
    }

    // MARK: - Tests

    @Test("verifies a freshly-signed valid token")
    func validTokenRoundTrip() async throws {
        let (collection, kid) = try await makeKeyCollection()
        let jwt = try await issueToken(with: collection, kid: kid)
        let parsed: FirebaseIDToken = try await collection.verify(jwt, as: FirebaseIDToken.self)
        try parsed.verify(projectId: Self.testProjectID)
        #expect(parsed.userID == "abc123")
        #expect(parsed.email == "user@example.com")
        #expect(parsed.firebase?.signInProvider == "password")
    }

    @Test("rejects an expired token")
    func rejectsExpired() async throws {
        let (collection, kid) = try await makeKeyCollection()
        let jwt = try await issueToken(with: collection, kid: kid, expiresIn: -60)
        await #expect(throws: (any Error).self) {
            _ = try await collection.verify(jwt, as: FirebaseIDToken.self)
        }
    }

    @Test("rejects a token whose issuer doesn't match the audience-derived URL")
    func rejectsBadIssuer() async throws {
        let (collection, kid) = try await makeKeyCollection()
        // Hand-craft a payload with mismatched iss/aud
        let now = Date()
        let payload = FirebaseIDToken(
            issuer: .init(value: "https://example.com/wrong"),
            subject: .init(value: "abc123"),
            audience: .init(value: [Self.testProjectID]),
            issuedAt: .init(value: now),
            expires: .init(value: now.addingTimeInterval(3600)),
            userID: "abc123"
        )
        let jwt = try await collection.sign(payload, kid: kid)
        await #expect(throws: (any Error).self) {
            _ = try await collection.verify(jwt, as: FirebaseIDToken.self)
        }
    }

    @Test("rejects a token whose audience doesn't match the configured project ID")
    func rejectsAudienceMismatch() async throws {
        let (collection, kid) = try await makeKeyCollection()
        let jwt = try await issueToken(with: collection, kid: kid, projectId: "different-project")
        let parsed: FirebaseIDToken = try await collection.verify(jwt, as: FirebaseIDToken.self)
        #expect(throws: FirebaseAuthError.self) {
            try parsed.verify(projectId: Self.testProjectID)
        }
    }

    @Test("rejects an empty subject")
    func rejectsEmptySubject() async throws {
        let (collection, kid) = try await makeKeyCollection()
        let now = Date()
        let payload = FirebaseIDToken(
            issuer: .init(value: "https://securetoken.google.com/\(Self.testProjectID)"),
            subject: .init(value: ""),
            audience: .init(value: [Self.testProjectID]),
            issuedAt: .init(value: now),
            expires: .init(value: now.addingTimeInterval(3600)),
            userID: ""
        )
        let jwt = try await collection.sign(payload, kid: kid)
        await #expect(throws: (any Error).self) {
            _ = try await collection.verify(jwt, as: FirebaseIDToken.self)
        }
    }

    @Test("rejects a token signed by an unknown key")
    func rejectsUnknownSigner() async throws {
        let (collection, _) = try await makeKeyCollection()
        // Sign with a different (unrelated) key
        let strangerKey = ES256PrivateKey()
        let strangerCollection = JWTKeyCollection()
        let strangerKid = JWKIdentifier(string: "unknown-kid")
        try await strangerCollection.add(ecdsa: strangerKey, kid: strangerKid)
        let jwt = try await issueToken(with: strangerCollection, kid: strangerKid)
        // Verifying with the original collection (which doesn't know that kid) should fail
        await #expect(throws: (any Error).self) {
            _ = try await collection.verify(jwt, as: FirebaseIDToken.self)
        }
    }
}

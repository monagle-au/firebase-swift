// FirebasePublicKeysTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import JWTKit
@testable import FirebaseAuth

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

@Suite("FirebasePublicKeys")
struct FirebasePublicKeysTests {

    @Test("parseRefreshInterval reads max-age from Cache-Control")
    func parseRefreshIntervalReadsMaxAge() throws {
        let url = URL(string: "https://example.com")!
        let response = HTTPURLResponse(
            url: url, statusCode: 200, httpVersion: nil,
            headerFields: ["Cache-Control": "public, max-age=3600, no-transform"]
        )!
        let interval = FirebasePublicKeys.parseRefreshInterval(from: response)
        #expect(interval.components.seconds == 3600)
    }

    @Test("parseRefreshInterval falls back to default when header is absent")
    func parseRefreshIntervalNoHeader() throws {
        let url = URL(string: "https://example.com")!
        let response = HTTPURLResponse(
            url: url, statusCode: 200, httpVersion: nil, headerFields: [:]
        )!
        let interval = FirebasePublicKeys.parseRefreshInterval(from: response)
        #expect(interval.components.seconds == FirebasePublicKeys.defaultRefreshInterval.components.seconds)
    }

    @Test("parseRefreshInterval clamps to minimum on tiny max-age")
    func parseRefreshIntervalClampsToMinimum() throws {
        let url = URL(string: "https://example.com")!
        let response = HTTPURLResponse(
            url: url, statusCode: 200, httpVersion: nil,
            headerFields: ["Cache-Control": "max-age=5"]
        )!
        let interval = FirebasePublicKeys.parseRefreshInterval(from: response)
        #expect(interval.components.seconds == FirebasePublicKeys.minimumRefreshInterval.components.seconds)
    }

    @Test("verify works against a preloaded test collection")
    func verifyWithPreloadedKeys() async throws {
        let kid = JWKIdentifier(string: "test-kid")
        let key = ES256PrivateKey()
        let collection = JWTKeyCollection()
        try await collection.add(ecdsa: key, kid: kid)

        let now = Date()
        let projectID = "preloaded-project"
        let payload = FirebaseIDToken(
            issuer: .init(value: "https://securetoken.google.com/\(projectID)"),
            subject: .init(value: "uid-1"),
            audience: .init(value: [projectID]),
            issuedAt: .init(value: now),
            expires: .init(value: now.addingTimeInterval(3600)),
            userID: "uid-1",
            email: "test@example.com"
        )
        let jwt = try await collection.sign(payload, kid: kid)

        let keys = FirebasePublicKeys(testProjectId: projectID, preloadedKeys: collection)
        let parsed = try await keys.verify(jwt)
        #expect(parsed.userID == "uid-1")
        #expect(parsed.email == "test@example.com")
    }
}

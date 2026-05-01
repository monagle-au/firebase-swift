// FirebaseIDToken.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import JWTKit

/// A parsed Firebase ID token.
///
/// Conforms to ``JWTPayload`` so it integrates with `JWTKit`'s verification
/// flow. Standard registered claims (`iss`, `sub`, `aud`, `iat`, `exp`) are
/// validated by `JWTKit`; Firebase-specific structural claims are validated
/// in ``verify(using:)`` (issuer URL format, subject length, etc.).
///
/// The ``verify(projectId:)`` method enforces the `aud` claim equals the
/// expected project ID — call this from your auth interceptor after
/// `JWTKeyCollection.verify(_:as:)` returns a token instance.
public struct FirebaseIDToken: JWTPayload, Sendable {

    /// Firebase-specific nested claims under the `firebase` key.
    public struct FirebaseClaims: Codable, Sendable {
        enum CodingKeys: String, CodingKey {
            case identities
            case signInProvider = "sign_in_provider"
            case signInSecondFactor = "sign_in_second_factor"
            case secondFactorIdentifier = "second_factor_identifier"
            case tenant
        }

        /// Map of provider name → list of identifiers (e.g. `["email": ["foo@bar.com"]]`).
        public let identities: [String: [String]]?
        /// The provider used to sign in (e.g. `"password"`, `"google.com"`, `"anonymous"`).
        public let signInProvider: String
        /// Second-factor type, if MFA was used.
        public let signInSecondFactor: String?
        /// Identifier of the second factor used.
        public let secondFactorIdentifier: String?
        /// Tenant ID for multi-tenant projects.
        public let tenant: String?

        public init(
            identities: [String: [String]]? = nil,
            signInProvider: String,
            signInSecondFactor: String? = nil,
            secondFactorIdentifier: String? = nil,
            tenant: String? = nil
        ) {
            self.identities = identities
            self.signInProvider = signInProvider
            self.signInSecondFactor = signInSecondFactor
            self.secondFactorIdentifier = secondFactorIdentifier
            self.tenant = tenant
        }
    }

    enum CodingKeys: String, CodingKey {
        case email, name, picture, firebase
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case issuedAt = "iat"
        case expires = "exp"
        case emailVerified = "email_verified"
        case userID = "user_id"
        case authTime = "auth_time"
        case phoneNumber = "phone_number"
    }

    /// Issuer (`iss`). Must be `https://securetoken.google.com/<projectId>`.
    public let issuer: IssuerClaim

    /// Issued-at time (`iat`). Must be in the past.
    public let issuedAt: IssuedAtClaim

    /// Expiration time (`exp`). Must be in the future.
    public let expires: ExpirationClaim

    /// Audience (`aud`). Must equal the Firebase project ID.
    public let audience: AudienceClaim

    /// Subject (`sub`). The Firebase user UID. 1–255 characters.
    public let subject: SubjectClaim

    /// Authentication time (`auth_time`). When the user actually authenticated.
    public let authTime: Date?

    /// The Firebase user UID (`user_id`). Mirrors `subject`; both are populated by Firebase.
    public let userID: String

    /// User's email address, if known.
    public let email: String?

    /// URL of the user's profile picture.
    public let picture: String?

    /// User's display name.
    public let name: String?

    /// Whether the user's email has been verified.
    public let emailVerified: Bool?

    /// User's phone number, if linked.
    public let phoneNumber: String?

    /// Firebase-specific nested claims.
    public let firebase: FirebaseClaims?

    public init(
        issuer: IssuerClaim,
        subject: SubjectClaim,
        audience: AudienceClaim,
        issuedAt: IssuedAtClaim,
        expires: ExpirationClaim,
        authTime: Date? = nil,
        userID: String,
        email: String? = nil,
        emailVerified: Bool? = nil,
        phoneNumber: String? = nil,
        name: String? = nil,
        picture: String? = nil,
        firebase: FirebaseClaims? = nil
    ) {
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        self.issuedAt = issuedAt
        self.expires = expires
        self.authTime = authTime
        self.userID = userID
        self.email = email
        self.emailVerified = emailVerified
        self.phoneNumber = phoneNumber
        self.name = name
        self.picture = picture
        self.firebase = firebase
    }

    // MARK: - JWTPayload

    /// JWTKit calls this during verification. Validates Firebase-structural
    /// claims (issuer URL format, subject length) and not-expired.
    ///
    /// Audience validation against your project ID is performed separately
    /// via ``verify(projectId:)`` — this protocol method has no project ID
    /// to compare against.
    public func verify(using _: some JWTAlgorithm) async throws {
        try expires.verifyNotExpired()

        guard let aud = audience.value.first, !aud.isEmpty else {
            throw FirebaseAuthError.malformedAudience
        }

        let expectedIssuer = "https://securetoken.google.com/\(aud)"
        guard issuer.value == expectedIssuer else {
            throw FirebaseAuthError.invalidIssuer(expected: expectedIssuer, actual: issuer.value)
        }

        guard !subject.value.isEmpty, subject.value.count <= 255 else {
            throw FirebaseAuthError.invalidSubject
        }
    }

    // MARK: - Project ID enforcement

    /// Verify the `aud` claim matches the expected Firebase project ID.
    ///
    /// Call this after `JWTKeyCollection.verify(_:as:)` succeeds. The
    /// `verify(using:)` protocol method already validates the issuer URL
    /// format (which embeds `aud`) but doesn't check `aud` against your
    /// configured project ID.
    public func verify(projectId expected: String) throws {
        guard let actual = audience.value.first, actual == expected else {
            throw FirebaseAuthError.audienceMismatch(
                expected: expected,
                actual: audience.value.first ?? ""
            )
        }
    }
}

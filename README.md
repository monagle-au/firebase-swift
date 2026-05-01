# firebase-swift

Server-side Firebase ID token verification for Swift. Built on `vapor/jwt-kit`.

There is no first-party Firebase Admin SDK for Swift — this package provides
the slice that server-side Swift apps actually need: parse a Firebase ID
token presented by an authenticated client, verify the signature against
Google's published JWKS, and check the standard Firebase claims (issuer,
audience, expiry, subject).

## Usage

```swift
import FirebaseAuth
import ServiceLifecycle

let keys = FirebasePublicKeys(projectId: "my-project-id")

// Run as a service so JWKS refreshes automatically when Google rotates keys.
let group = ServiceGroup(
    services: [keys, /* … your other services … */],
    gracefulShutdownSignals: [.sigterm, .sigint],
    logger: logger
)
try await group.run()

// In your auth interceptor:
let token = try await keys.verify(rawJWT)
print(token.userID, token.email ?? "<no email>")
```

For one-shot use (tests, scripts) without the service loop:

```swift
let keys = FirebasePublicKeys(projectId: "my-project-id")
try await keys.prefetch()
let token = try await keys.verify(rawJWT)
```

## Emulator

Pass `emulatorHost` to point JWKS fetch at the local Firebase Auth emulator:

```swift
let keys = FirebasePublicKeys(
    projectId: "demo-project",
    emulatorHost: "http://localhost:9099"
)
```

## What this package does

- `FirebaseIDToken: JWTPayload` — typed parse of standard Firebase ID token claims, including the nested `firebase.identities` / `sign_in_provider` / `tenant` block.
- `FirebasePublicKeys` actor — fetches and refreshes JWKS, exposes `verify(_:)`. Conforms to `Service` from `swift-service-lifecycle` for clean integration with server frameworks.
- Refresh interval respects the `Cache-Control: max-age` header on the JWKS response (clamped to a minimum to avoid hammering Google on aberrant short max-ages).

## What this package does not do

- **No gRPC or HTTP middleware.** Apps wire `FirebasePublicKeys.verify(_:)` into their own interceptors so they can do app-specific user lookup after verification (e.g. mapping the Firebase UID to your internal account ID).
- **No service-account auth (signing tokens).** This is verification only — for server-to-Firestore-or-other-Google-API auth from a Swift backend, you'll want a separate Google service-account JWT signing helper.
- **No Firestore client.** See above.

## Requirements

- Swift 6.0+
- macOS 15+

## License

MIT.

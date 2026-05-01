// swift-tools-version: 6.3
// Package.swift
// Copyright 2026 Monagle Pty Ltd

import PackageDescription

let package = Package(
    name: "firebase-swift",
    platforms: [
        .macOS(.v15),
    ],
    products: [
        .library(name: "FirebaseAuth", targets: ["FirebaseAuth"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/jwt-kit.git", exact: "5.4.1"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
        .package(url: "https://github.com/swift-server/swift-service-lifecycle.git", from: "2.8.0"),
    ],
    targets: [
        .target(
            name: "FirebaseAuth",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ServiceLifecycle", package: "swift-service-lifecycle"),
            ]
        ),
        .testTarget(
            name: "FirebaseAuthTests",
            dependencies: [
                "FirebaseAuth",
                .product(name: "JWTKit", package: "jwt-kit"),
            ]
        ),
    ]
)

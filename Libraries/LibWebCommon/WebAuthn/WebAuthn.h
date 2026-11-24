/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/Optional.h>
#include <AK/String.h>
#include <AK/Variant.h>
#include <AK/Vector.h>

namespace Web::WebAuthn {

// The DOMExceptions a ceremony rejects with, other than an abort signal's reason.
enum class Error : u8 {
    NotAllowed,
    NotSupported,
    InvalidState,
    Security,
    Type,
};

// https://w3c.github.io/webauthn/#enumdef-userverificationrequirement
enum class UserVerificationRequirement : u8 {
    Required,
    Preferred,
    Discouraged,
};

// https://w3c.github.io/webauthn/#enumdef-residentkeyrequirement
enum class ResidentKeyRequirement : u8 {
    Discouraged,
    Preferred,
    Required,
};

// The members of PublicKeyCredentialCreationOptions that only credential creation uses.
struct CreationOptions {
    String rp_name;
    ByteBuffer user_id;
    String user_name;
    String user_display_name;
    // The COSEAlgorithmIdentifiers of the "public-key" entries of pubKeyCredParams.
    Vector<i32> algorithms;
    ResidentKeyRequirement resident_key { ResidentKeyRequirement::Discouraged };
};

// The options of navigator.credentials.create() or get(), as the renderer reports them.
struct Request {
    ByteBuffer challenge;
    Optional<String> rp_id;
    // The ids of excludeCredentials when creating, or of allowCredentials when getting.
    Vector<ByteBuffer> credentials;
    // Whether allowCredentials is not empty, but holds no descriptor of a supported credential type.
    bool allows_only_unsupported_credentials { false };
    UserVerificationRequirement user_verification { UserVerificationRequirement::Preferred };
    Optional<u32> timeout;
    Optional<CreationOptions> creation;
};

// A request that the browser process has validated against the requesting document.
struct AuthenticatorRequest {
    String origin;
    String rp_id;
    ByteBuffer client_data_json;
    Vector<ByteBuffer> credentials;
    UserVerificationRequirement user_verification { UserVerificationRequirement::Preferred };
    u32 timeout { 0 };
    Optional<CreationOptions> creation;
};

// An AuthenticatorAttestationResponse when creating (attestation_object and public_key), or an
// AuthenticatorAssertionResponse when getting (signature and user_handle).
struct Response {
    ByteBuffer client_data_json;
    ByteBuffer raw_id;
    ByteBuffer authenticator_data;
    ByteBuffer attestation_object;
    ByteBuffer public_key;
    ByteBuffer signature;
    Optional<ByteBuffer> user_handle;
};

using Result = Variant<Response, Error>;

}

#include <LibWebCommon/WebAuthn/WebAuthnCodecs.h>

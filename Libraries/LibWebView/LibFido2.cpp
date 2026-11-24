/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/AnyOf.h>
#include <AK/ScopeGuard.h>
#include <LibCrypto/Hash/Hash.h>
#include <LibWebView/LibFido2.h>
#include <LibWebView/WebAuthn.h>
#include <cbor.h>
#include <fido.h>
#include <fido/es256.h>
#include <openssl/x509.h>

namespace WebView::WebAuthn {

using Web::WebAuthn::CreationOptions;
using Web::WebAuthn::ResidentKeyRequirement;
using Web::WebAuthn::UserVerificationRequirement;

// https://w3c.github.io/webauthn/#sctn-authenticator-data
static constexpr size_t rp_id_hash_size = 32;
static constexpr size_t flags_offset = 32;
static constexpr size_t aaguid_offset = 37;
static constexpr size_t aaguid_size = 16;
static constexpr size_t attested_credential_data_minimum_size = aaguid_offset + aaguid_size + 2;
static constexpr u8 user_present_flag = 1 << 0;
static constexpr u8 user_verified_flag = 1 << 2;
static constexpr u8 attested_credential_data_flag = 1 << 6;

static constexpr size_t maximum_user_handle_size = 64;

static void initialize()
{
    fido_init(FIDO_DISABLE_U2F_FALLBACK);
}

static ByteBuffer copy_bytes(unsigned char const* data, size_t size)
{
    return MUST(ByteBuffer::copy(data, size));
}

static StringView string_view(char const* string)
{
    return string ? StringView { string, strlen(string) } : StringView {};
}

Vector<SecurityKey> enumerate_security_keys()
{
    initialize();
    constexpr size_t maximum_devices = 64;
    auto* devices = fido_dev_info_new(maximum_devices);
    if (!devices)
        return {};
    ScopeGuard release_devices = [&] { fido_dev_info_free(&devices, maximum_devices); };

    size_t count = 0;
    if (fido_dev_info_manifest(devices, maximum_devices, &count) != FIDO_OK)
        return {};

    Vector<SecurityKey> keys;
    for (size_t i = 0; i < count; ++i) {
        auto const* device = fido_dev_info_ptr(devices, i);
        auto path = String::from_utf8(string_view(fido_dev_info_path(device)));
        if (path.is_error() || path.value().is_empty())
            continue;
        auto manufacturer = string_view(fido_dev_info_manufacturer_string(device));
        auto product = string_view(fido_dev_info_product_string(device));
        auto name = String::from_utf8_with_replacement_character(ByteString::formatted("{} {}", manufacturer.is_empty() ? "Security key"sv : manufacturer, product));
        keys.append({ path.release_value(), MUST(name.trim_ascii_whitespace()) });
    }
    return keys;
}

static Outcome authenticator_error(int status)
{
    switch (status) {
    case FIDO_ERR_PIN_REQUIRED:
        return PinStatus::Required;
    case FIDO_ERR_PIN_INVALID:
    case FIDO_ERR_PIN_AUTH_INVALID:
        return PinStatus::Invalid;
    case FIDO_ERR_CREDENTIAL_EXCLUDED:
        // https://w3c.github.io/webauthn/#sctn-createCredential
        // 22. If any authenticator indicates an "InvalidStateError", ... throw an "InvalidStateError" DOMException.
        return Error::InvalidState;
    default:
        // NB: No other authenticator error may be told apart from the user declining, so as not to reveal anything
        //     about the credentials on the authenticator.
        return Error::NotAllowed;
    }
}

// Runs a blocking authenticator operation that a cancellation interrupts.
template<typename Operation>
static int run_cancelable(fido_dev_t* device, Cancellation* cancellation, Operation operation)
{
    if (!cancellation)
        return operation();
    int status = FIDO_ERR_KEEPALIVE_CANCEL;
    cancellation->run_interruptibly([&] { status = operation(); }, [device] { (void)fido_dev_cancel(device); });
    return cancellation->is_canceled() ? FIDO_ERR_KEEPALIVE_CANCEL : status;
}

static bool is_valid_authenticator_data(ReadonlyBytes bytes, StringView rp_id, bool require_user_verification, bool creating)
{
    if (bytes.size() < aaguid_offset)
        return false;
    auto rp_id_hash = Crypto::Hash::digest(Crypto::Hash::HashKind::SHA256, rp_id.bytes());
    if (bytes.slice(0, rp_id_hash_size) != rp_id_hash.bytes())
        return false;
    auto flags = bytes[flags_offset];
    if (!(flags & user_present_flag))
        return false;
    if (require_user_verification && !(flags & user_verified_flag))
        return false;
    if (creating && (!(flags & attested_credential_data_flag) || bytes.size() < attested_credential_data_minimum_size))
        return false;
    return true;
}

// https://w3c.github.io/webauthn/#sctn-none-attestation
static ByteBuffer none_attestation_object(ByteBuffer& authenticator_data)
{
    // https://w3c.github.io/webauthn/#sctn-createCredential
    // 22.4.2.1.3. If credentialCreationData.attestationConveyancePreferenceOption’s value is "none": Replace
    //             potentially uniquely identifying information with non-identifying versions of the same:
    //             If the aaguid in the attested credential data is 16 zero bytes, ... Otherwise, replace the aaguid
    //             with 16 zero bytes and set the fmt to "none" and attStmt to an empty CBOR map.
    // NB: Attestation is always "none", as no attestation statements are returned.
    authenticator_data.bytes().slice(aaguid_offset, aaguid_size).fill(0);

    auto* object = cbor_new_definite_map(3);
    VERIFY(object);
    ScopeGuard release_object = [&] { cbor_decref(&object); };
    auto add = [&](char const* name, cbor_item_t* value) {
        auto* key = cbor_build_string(name);
        VERIFY(key && value);
        auto added = cbor_map_add(object, { key, value });
        cbor_decref(&key);
        cbor_decref(&value);
        VERIFY(added);
    };
    add("fmt", cbor_build_string("none"));
    add("attStmt", cbor_new_definite_map(0));
    add("authData", cbor_build_bytestring(authenticator_data.data(), authenticator_data.size()));

    unsigned char* serialized = nullptr;
    size_t capacity = 0;
    auto size = cbor_serialize_alloc(object, &serialized, &capacity);
    VERIFY(size > 0 && serialized);
    ScopeGuard release_serialized = [&] { free(serialized); };
    return copy_bytes(serialized, size);
}

static bool supports_resident_keys(fido_dev_t* device)
{
    auto* info = fido_cbor_info_new();
    if (!info)
        return false;
    ScopeGuard release_info = [&] { fido_cbor_info_free(&info); };
    if (fido_dev_get_cbor_info(device, info) != FIDO_OK)
        return false;
    auto* names = fido_cbor_info_options_name_ptr(info);
    auto const* values = fido_cbor_info_options_value_ptr(info);
    for (size_t i = 0; i < fido_cbor_info_options_len(info); ++i) {
        if (string_view(names[i]) == "rk"sv)
            return values[i];
    }
    return false;
}

static Optional<ByteBuffer> der_encoded_public_key(fido_cred_t const* credential)
{
    auto* key = es256_pk_new();
    if (!key)
        return {};
    ScopeGuard release_key = [&] { es256_pk_free(&key); };
    if (es256_pk_from_ptr(key, fido_cred_pubkey_ptr(credential), fido_cred_pubkey_len(credential)) != FIDO_OK)
        return {};
    auto* public_key = es256_pk_to_EVP_PKEY(key);
    if (!public_key)
        return {};
    ScopeGuard release_public_key = [&] { EVP_PKEY_free(public_key); };
    unsigned char* der = nullptr;
    auto der_length = i2d_PUBKEY(public_key, &der);
    ScopeGuard release_der = [&] { OPENSSL_free(der); };
    if (der_length <= 0)
        return {};
    return copy_bytes(der, der_length);
}

static Outcome make_credential(fido_dev_t* device, AuthenticatorRequest const& request, CreationOptions const& options, char const* pin, ReadonlyBytes client_data_hash, bool require_user_verification, Cancellation* cancellation)
{
    auto* credential = fido_cred_new();
    if (!credential)
        return Error::NotAllowed;
    ScopeGuard release_credential = [&] { fido_cred_free(&credential); };

    auto resident_keys_supported = supports_resident_keys(device);
    if (options.resident_key == ResidentKeyRequirement::Required && !resident_keys_supported)
        return Error::NotAllowed;
    auto use_resident_key = options.resident_key == ResidentKeyRequirement::Required
        || (options.resident_key == ResidentKeyRequirement::Preferred && resident_keys_supported);

    auto rp_id = request.rp_id.to_byte_string();
    auto rp_name = options.rp_name.to_byte_string();
    auto user_name = options.user_name.to_byte_string();
    auto user_display_name = options.user_display_name.to_byte_string();
    if (fido_cred_set_type(credential, COSE_ES256) != FIDO_OK
        || fido_cred_set_clientdata_hash(credential, client_data_hash.data(), client_data_hash.size()) != FIDO_OK
        || fido_cred_set_rp(credential, rp_id.characters(), rp_name.characters()) != FIDO_OK
        || fido_cred_set_user(credential, options.user_id.data(), options.user_id.size(), user_name.characters(), user_display_name.characters(), nullptr) != FIDO_OK
        || fido_cred_set_rk(credential, use_resident_key ? FIDO_OPT_TRUE : FIDO_OPT_FALSE) != FIDO_OK
        || fido_cred_set_uv(credential, !pin && require_user_verification ? FIDO_OPT_TRUE : FIDO_OPT_OMIT) != FIDO_OK)
        return Error::NotAllowed;
    if (use_resident_key && fido_dev_supports_cred_prot(device))
        (void)fido_cred_set_prot(credential, FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID);
    for (auto const& id : request.credentials) {
        if (fido_cred_exclude(credential, id.data(), id.size()) != FIDO_OK)
            return Error::NotAllowed;
    }

    auto status = run_cancelable(device, cancellation, [&] { return fido_dev_make_cred(device, credential, pin); });
    if (status != FIDO_OK)
        return authenticator_error(status);

    auto authenticator_data = copy_bytes(fido_cred_authdata_raw_ptr(credential), fido_cred_authdata_raw_len(credential));
    if (!is_valid_authenticator_data(authenticator_data, rp_id, require_user_verification, true))
        return Error::NotAllowed;
    auto public_key = der_encoded_public_key(credential);
    if (!public_key.has_value())
        return Error::NotAllowed;

    auto attestation_object = none_attestation_object(authenticator_data);

    Vector<Account> accounts;
    accounts.append({
        .response = {
            .client_data_json = request.client_data_json,
            .raw_id = copy_bytes(fido_cred_id_ptr(credential), fido_cred_id_len(credential)),
            .authenticator_data = move(authenticator_data),
            .attestation_object = move(attestation_object),
            .public_key = public_key.release_value(),
            .signature = {},
            .user_handle = {},
        },
        .name = options.user_name,
    });
    return accounts;
}

static Outcome get_assertion(fido_dev_t* device, AuthenticatorRequest const& request, char const* pin, ReadonlyBytes client_data_hash, bool require_user_verification, Cancellation* cancellation)
{
    auto* assertion = fido_assert_new();
    if (!assertion)
        return Error::NotAllowed;
    ScopeGuard release_assertion = [&] { fido_assert_free(&assertion); };

    auto rp_id = request.rp_id.to_byte_string();
    if (fido_assert_set_rp(assertion, rp_id.characters()) != FIDO_OK
        || fido_assert_set_clientdata_hash(assertion, client_data_hash.data(), client_data_hash.size()) != FIDO_OK
        || fido_assert_set_up(assertion, FIDO_OPT_TRUE) != FIDO_OK
        || fido_assert_set_uv(assertion, !pin && require_user_verification ? FIDO_OPT_TRUE : FIDO_OPT_OMIT) != FIDO_OK)
        return Error::NotAllowed;
    for (auto const& id : request.credentials) {
        if (fido_assert_allow_cred(assertion, id.data(), id.size()) != FIDO_OK)
            return Error::NotAllowed;
    }

    auto status = run_cancelable(device, cancellation, [&] { return fido_dev_get_assert(device, assertion, pin); });
    if (status != FIDO_OK)
        return authenticator_error(status);

    Vector<Account> accounts;
    for (size_t i = 0; i < fido_assert_count(assertion); ++i) {
        ReadonlyBytes authenticator_data { fido_assert_authdata_raw_ptr(assertion, i), fido_assert_authdata_raw_len(assertion, i) };
        ReadonlyBytes id { fido_assert_id_ptr(assertion, i), fido_assert_id_len(assertion, i) };
        if (id.is_empty() || !is_valid_authenticator_data(authenticator_data, rp_id, require_user_verification, false))
            return Error::NotAllowed;
        if (!request.credentials.is_empty() && !any_of(request.credentials, [&](auto const& allowed) { return allowed.bytes() == id; }))
            return Error::NotAllowed;

        // https://w3c.github.io/webauthn/#sctn-discover-from-external-source
        // NB: A user handle is required for discoverable credentials, which are what an empty allowCredentials finds.
        ReadonlyBytes user_handle { fido_assert_user_id_ptr(assertion, i), fido_assert_user_id_len(assertion, i) };
        if (user_handle.size() > maximum_user_handle_size || (request.credentials.is_empty() && user_handle.is_empty()))
            return Error::NotAllowed;

        auto name = string_view(fido_assert_user_name(assertion, i));
        accounts.append({
            .response = {
                .client_data_json = request.client_data_json,
                .raw_id = copy_bytes(id.data(), id.size()),
                .authenticator_data = copy_bytes(authenticator_data.data(), authenticator_data.size()),
                .attestation_object = {},
                .public_key = {},
                .signature = copy_bytes(fido_assert_sig_ptr(assertion, i), fido_assert_sig_len(assertion, i)),
                .user_handle = user_handle.is_empty() ? Optional<ByteBuffer> {} : copy_bytes(user_handle.data(), user_handle.size()),
            },
            .name = name.is_empty() ? "Security key account"_string : String::from_utf8_with_replacement_character(name),
        });
    }
    if (accounts.is_empty())
        return Error::NotAllowed;
    return accounts;
}

Outcome perform(AuthenticatorRequest const& request, String const& device_path, String const& pin, Cancellation& cancellation)
{
    if (cancellation.is_canceled())
        return Error::NotAllowed;
    initialize();
    auto* device = fido_dev_new();
    if (!device)
        return Error::NotAllowed;
    ScopeGuard release_device = [&] {
        (void)fido_dev_close(device);
        fido_dev_free(&device);
    };
    if (fido_dev_set_timeout(device, static_cast<int>(request.timeout)) != FIDO_OK)
        return Error::NotAllowed;
    auto path = device_path.to_byte_string();
    if (fido_dev_open(device, path.characters()) != FIDO_OK || !fido_dev_is_fido2(device))
        return Error::NotAllowed;
    return perform_on_open_device(device, request, pin, &cancellation);
}

Outcome perform_on_open_device(fido_dev_t* device, AuthenticatorRequest const& request, String const& pin, Cancellation* cancellation)
{
    if (cancellation && cancellation->is_canceled())
        return Error::NotAllowed;

    auto creating = request.creation.has_value();
    auto require_user_verification = request.user_verification == UserVerificationRequirement::Required
        || (request.user_verification == UserVerificationRequirement::Preferred && (fido_dev_has_pin(device) || fido_dev_has_uv(device)));
    if (pin.is_empty() && fido_dev_has_pin(device) && (creating || require_user_verification))
        return PinStatus::Required;

    auto pin_string = pin.to_byte_string();
    auto const* pin_characters = pin.is_empty() ? nullptr : pin_string.characters();
    auto client_data_hash = Crypto::Hash::digest(Crypto::Hash::HashKind::SHA256, request.client_data_json);
    if (creating)
        return make_credential(device, request, *request.creation, pin_characters, client_data_hash.bytes(), require_user_verification, cancellation);
    return get_assertion(device, request, pin_characters, client_data_hash.bytes(), require_user_verification, cancellation);
}

}

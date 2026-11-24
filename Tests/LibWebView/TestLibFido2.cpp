/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ConditionVariable.h>
#include <AK/ScopeGuard.h>
#include <AK/Time.h>
#include <LibCrypto/Hash/Hash.h>
#include <LibTest/TestCase.h>
#include <LibThreading/Thread.h>
#include <LibURL/Parser.h>
#include <LibWebView/LibFido2.h>
#include <cbor.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

namespace WebAuthn = WebView::WebAuthn;
using WebView::WebAuthn::Account;
using WebView::WebAuthn::AuthenticatorRequest;
using WebView::WebAuthn::Cancellation;
using WebView::WebAuthn::Outcome;
using WebView::WebAuthn::PinStatus;
using WebView::WebAuthn::Request;
using WebView::WebAuthn::Response;

namespace {

void add(cbor_item_t* map, cbor_item_t* key, cbor_item_t* value)
{
    VERIFY(key && value);
    VERIFY(cbor_map_add(map, { key, value }));
    cbor_decref(&key);
    cbor_decref(&value);
}

void add(cbor_item_t* map, char const* key, cbor_item_t* value)
{
    add(map, cbor_build_string(key), value);
}

ByteBuffer serialize(cbor_item_t* value)
{
    unsigned char* serialized = nullptr;
    size_t capacity = 0;
    auto length = cbor_serialize_alloc(value, &serialized, &capacity);
    VERIFY(length);
    auto bytes = MUST(ByteBuffer::copy(serialized, length));
    free(serialized);
    cbor_decref(&value);
    return bytes;
}

class Authenticator {
public:
    explicit Authenticator(bool has_pin = false)
        : m_has_pin(has_pin)
    {
        key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
        VERIFY(key);
        device = fido_dev_new();
        VERIFY(device);
        current = this;
        fido_dev_io_t io {
            [](char const*) -> void* { return current; },
            [](void*) { },
            [](void*, unsigned char*, size_t, int) -> int { return -1; },
            [](void*, unsigned char const*, size_t) -> int { return -1; }
        };
        fido_dev_transport_t transport { receive, transmit };
        VERIFY(fido_dev_set_io_functions(device, &io) == FIDO_OK);
        VERIFY(fido_dev_set_transport_functions(device, &transport) == FIDO_OK);
        VERIFY(fido_dev_open(device, "virtual") == FIDO_OK);
    }

    ~Authenticator()
    {
        (void)fido_dev_close(device);
        fido_dev_free(&device);
        EVP_PKEY_free(key);
        current = nullptr;
    }

    fido_dev_t* device { nullptr };
    EVP_PKEY* key { nullptr };
    bool exclude { false };
    bool wrong_rp_hash { false };
    bool user_present { true };
    size_t user_id_length { 1 };
    ByteBuffer hash;

    // Holds requests until they are canceled, ignoring cancels that arrive before them as a real key does.
    bool hold_until_canceled { false };
    Mutex mutex;
    ConditionVariable condition { mutex };
    bool request_is_starting { false };
    size_t cancels { 0 };
    bool canceled_after_request { false };

private:
    static int transmit(fido_dev_t* device, u8 command, unsigned char const* data, size_t length)
    {
        auto& self = *static_cast<Authenticator*>(fido_dev_io_handle(device));
        if (command == 0x06) {
            self.reply = MUST(ByteBuffer::copy(data, length));
            self.reply.append(Array<u8, 9> { 0, 0, 0, 1, 2, 1, 0, 0, 4 });
            return 0;
        }
        if (command == 0x11) {
            MutexLocker locker { self.mutex };
            ++self.cancels;
            self.condition.broadcast();
            return 0;
        }
        VERIFY(command == 0x10 && length > 0);
        if (data[0] == 0x04) {
            auto* info = cbor_new_definite_map(3);
            auto* versions = cbor_new_definite_array(1);
            auto* version = cbor_build_string("FIDO_2_0");
            VERIFY(cbor_array_push(versions, version));
            cbor_decref(&version);
            add(info, cbor_build_uint8(1), versions);
            Array<u8, 16> aaguid {};
            add(info, cbor_build_uint8(3), cbor_build_bytestring(aaguid.data(), aaguid.size()));
            auto* options = cbor_new_definite_map(3);
            add(options, "rk", cbor_build_bool(true));
            add(options, "up", cbor_build_bool(true));
            add(options, "clientPin", cbor_build_bool(self.m_has_pin));
            add(info, cbor_build_uint8(4), options);
            self.set_reply(serialize(info));
            return 0;
        }
        VERIFY(data[0] == 0x01 || data[0] == 0x02);
        if (self.hold_until_canceled) {
            MutexLocker locker { self.mutex };
            self.request_is_starting = true;
            self.condition.broadcast();
            while (self.cancels == 0)
                VERIFY(self.condition.wait_for(AK::Duration::from_seconds(5)));
            auto cancels_before_request = self.cancels;
            while (self.cancels == cancels_before_request) {
                if (!self.condition.wait_for(AK::Duration::from_seconds(5)))
                    return -1;
            }
            self.canceled_after_request = true;
            self.reply = MUST(ByteBuffer::copy("\x2d"sv.bytes()));
            return 0;
        }
        cbor_load_result loaded {};
        auto* request = cbor_load(data + 1, length - 1, &loaded);
        VERIFY(request && cbor_isa_map(request));
        ScopeGuard release_request = [&] { cbor_decref(&request); };
        auto* entries = cbor_map_handle(request);
        for (size_t i = 0; i < cbor_map_size(request); ++i) {
            auto hash_key = data[0] == 0x01 ? 1 : 2;
            if (cbor_get_int(entries[i].key) == static_cast<u64>(hash_key)) {
                auto* value = entries[i].value;
                self.hash = MUST(ByteBuffer::copy(cbor_bytestring_handle(value), cbor_bytestring_length(value)));
            }
        }
        if (self.exclude) {
            self.reply = MUST(ByteBuffer::copy("\x19"sv.bytes()));
            return 0;
        }
        auto authdata = self.authenticator_data(data[0] == 0x01);
        auto* response = cbor_new_definite_map(data[0] == 0x01 ? 3 : 4);
        if (data[0] == 0x01) {
            add(response, cbor_build_uint8(1), cbor_build_string("none"));
            add(response, cbor_build_uint8(2), cbor_build_bytestring(authdata.data(), authdata.size()));
            add(response, cbor_build_uint8(3), cbor_new_definite_map(0));
        } else {
            auto* credential = cbor_new_definite_map(2);
            Array<u8, 3> id { 1, 2, 3 };
            add(credential, "id", cbor_build_bytestring(id.data(), id.size()));
            add(credential, "type", cbor_build_string("public-key"));
            add(response, cbor_build_uint8(1), credential);
            add(response, cbor_build_uint8(2), cbor_build_bytestring(authdata.data(), authdata.size()));
            auto signature = self.sign(authdata);
            add(response, cbor_build_uint8(3), cbor_build_bytestring(signature.data(), signature.size()));
            auto* user = cbor_new_definite_map(2);
            auto user_id = MUST(ByteBuffer::create_zeroed(self.user_id_length));
            if (!user_id.is_empty())
                user_id[0] = 4;
            add(user, "id", cbor_build_bytestring(user_id.data(), user_id.size()));
            add(user, "name", cbor_build_string("Test user"));
            add(response, cbor_build_uint8(4), user);
        }
        self.set_reply(serialize(response));
        return 0;
    }

    static int receive(fido_dev_t* device, u8, unsigned char* data, size_t length, int)
    {
        auto& self = *static_cast<Authenticator*>(fido_dev_io_handle(device));
        VERIFY(self.reply.size() <= length);
        __builtin_memcpy(data, self.reply.data(), self.reply.size());
        return self.reply.size();
    }

    void set_reply(ByteBuffer const& bytes)
    {
        reply = MUST(ByteBuffer::copy("\0"sv.bytes()));
        reply.append(bytes);
    }

    ByteBuffer authenticator_data(bool creating)
    {
        auto digest = Crypto::Hash::digest(Crypto::Hash::HashKind::SHA256, "example.com"sv.bytes());
        auto result = MUST(ByteBuffer::copy(digest.bytes()));
        if (wrong_rp_hash)
            result[0] ^= 0xff;
        result.append(Array<u8, 5> { static_cast<u8>((user_present ? 1 : 0) | (creating ? 0x40 : 0)), 0, 0, 0, 1 });
        if (!creating)
            return result;
        Array<u8, 16> aaguid;
        aaguid.fill(0x55);
        result.append(aaguid);
        result.append(Array<u8, 5> { 0, 3, 1, 2, 3 });
        Array<u8, 65> public_key {};
        size_t public_key_length = 0;
        VERIFY(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, public_key.data(), public_key.size(), &public_key_length));
        VERIFY(public_key_length == public_key.size());
        auto* cose = cbor_new_definite_map(5);
        add(cose, cbor_build_uint8(1), cbor_build_uint8(2));
        add(cose, cbor_build_uint8(3), cbor_build_negint8(6));
        add(cose, cbor_build_negint8(0), cbor_build_uint8(1));
        add(cose, cbor_build_negint8(1), cbor_build_bytestring(public_key.data() + 1, 32));
        add(cose, cbor_build_negint8(2), cbor_build_bytestring(public_key.data() + 33, 32));
        auto encoded_cose = serialize(cose);
        result.append(encoded_cose);
        return result;
    }

    ByteBuffer sign(ReadonlyBytes authenticator_data)
    {
        auto* context = EVP_MD_CTX_new();
        VERIFY(context);
        ScopeGuard release_context = [&] { EVP_MD_CTX_free(context); };
        VERIFY(EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, key) == 1);
        VERIFY(EVP_DigestSignUpdate(context, authenticator_data.data(), authenticator_data.size()) == 1);
        VERIFY(EVP_DigestSignUpdate(context, hash.data(), hash.size()) == 1);
        size_t length = 0;
        VERIFY(EVP_DigestSignFinal(context, nullptr, &length) == 1);
        auto signature = MUST(ByteBuffer::create_uninitialized(length));
        VERIFY(EVP_DigestSignFinal(context, signature.data(), &length) == 1);
        signature.resize(length);
        return signature;
    }

    ByteBuffer reply;
    bool m_has_pin { false };
    static thread_local Authenticator* current;
};

thread_local Authenticator* Authenticator::current = nullptr;

AuthenticatorRequest options(bool creating)
{
    Request request {
        .challenge = MUST(ByteBuffer::copy("\x01\x02\x03"sv.bytes())),
        .rp_id = "example.com"_string,
        .credentials = {},
        .allows_only_unsupported_credentials = false,
        .user_verification = Web::WebAuthn::UserVerificationRequirement::Discouraged,
        .timeout = {},
        .creation = {},
    };
    if (creating) {
        request.creation = Web::WebAuthn::CreationOptions {
            .rp_name = "Test"_string,
            .user_id = MUST(ByteBuffer::copy("\x04"sv.bytes())),
            .user_name = "user"_string,
            .user_display_name = "User"_string,
            .algorithms = { -7 },
            .resident_key = Web::WebAuthn::ResidentKeyRequirement::Required,
        };
    }
    auto prepared = WebView::WebAuthn::prepare_request(request, URL::Parser::basic_parse("https://example.com/"sv)->origin());
    VERIFY(prepared.has<AuthenticatorRequest>());
    return move(prepared.get<AuthenticatorRequest>());
}

Optional<Response> response_of(Outcome& outcome)
{
    if (!outcome.has<Vector<Account>>())
        return {};
    return move(outcome.get<Vector<Account>>().first().response);
}

void expect_outcome(Outcome const& outcome, Variant<WebAuthn::Error, PinStatus> expected)
{
    auto matches = expected.visit([&](auto value) {
        using T = decltype(value);
        return outcome.has<T>() && outcome.get<T>() == value;
    });
    EXPECT(matches);
}

}

TEST_CASE(webauthn_libfido2_registration_and_assertion)
{
    Authenticator authenticator;
    auto creation = options(true);
    auto outcome = WebView::WebAuthn::perform_on_open_device(authenticator.device, creation, {});
    auto credential = response_of(outcome);
    EXPECT(credential.has_value());
    if (!credential.has_value())
        return;
    EXPECT_EQ(credential->raw_id.bytes(), "\x01\x02\x03"sv.bytes());
    auto expected_hash = Crypto::Hash::digest(Crypto::Hash::HashKind::SHA256, creation.client_data_json);
    EXPECT_EQ(authenticator.hash.bytes(), expected_hash.bytes());
    for (size_t i = 37; i < 53; ++i)
        EXPECT_EQ(credential->authenticator_data[i], 0);

    unsigned char const* der_pointer = credential->public_key.data();
    auto* key = d2i_PUBKEY(nullptr, &der_pointer, credential->public_key.size());
    EXPECT(key);
    if (!key)
        return;
    ScopeGuard release_key = [&] { EVP_PKEY_free(key); };

    outcome = WebView::WebAuthn::perform_on_open_device(authenticator.device, options(false), {});
    auto assertion = response_of(outcome);
    EXPECT(assertion.has_value());
    if (!assertion.has_value())
        return;
    auto* context = EVP_MD_CTX_new();
    VERIFY(context);
    ScopeGuard release_context = [&] { EVP_MD_CTX_free(context); };
    EXPECT_EQ(EVP_DigestVerifyInit(context, nullptr, EVP_sha256(), nullptr, key), 1);
    EXPECT_EQ(EVP_DigestVerifyUpdate(context, assertion->authenticator_data.data(), assertion->authenticator_data.size()), 1);
    EXPECT_EQ(EVP_DigestVerifyUpdate(context, authenticator.hash.data(), authenticator.hash.size()), 1);
    EXPECT_EQ(EVP_DigestVerifyFinal(context, assertion->signature.data(), assertion->signature.size()), 1);
    EXPECT(assertion->user_handle.has_value() && assertion->user_handle->bytes() == "\x04"sv.bytes());
}

TEST_CASE(webauthn_libfido2_rejects_bad_authenticator_responses)
{
    Authenticator authenticator;
    auto check_error = [&](AuthenticatorRequest const& request, WebAuthn::Error error) {
        expect_outcome(WebView::WebAuthn::perform_on_open_device(authenticator.device, request, {}), error);
    };
    authenticator.exclude = true;
    check_error(options(true), WebAuthn::Error::InvalidState);
    authenticator.exclude = false;
    authenticator.wrong_rp_hash = true;
    check_error(options(false), WebAuthn::Error::NotAllowed);
    authenticator.wrong_rp_hash = false;
    authenticator.user_present = false;
    check_error(options(false), WebAuthn::Error::NotAllowed);
    authenticator.user_present = true;
    auto request = options(false);
    request.credentials.append(MUST(ByteBuffer::copy("\x02"sv.bytes())));
    check_error(request, WebAuthn::Error::NotAllowed);
    request = options(false);
    authenticator.user_id_length = 0;
    check_error(request, WebAuthn::Error::NotAllowed);
    authenticator.user_id_length = 65;
    check_error(request, WebAuthn::Error::NotAllowed);
}

TEST_CASE(webauthn_libfido2_requires_pin_and_honors_cancellation)
{
    Authenticator authenticator(true);
    auto request = options(true);
    expect_outcome(WebView::WebAuthn::perform_on_open_device(authenticator.device, request, {}), PinStatus::Required);
    EXPECT(authenticator.hash.is_empty());
    auto cancellation = Cancellation::create();
    cancellation->cancel();
    expect_outcome(WebView::WebAuthn::perform_on_open_device(authenticator.device, request, "1234"_string, cancellation.ptr()), WebAuthn::Error::NotAllowed);
    EXPECT(authenticator.hash.is_empty());
}

TEST_CASE(webauthn_libfido2_cancels_operation_in_progress)
{
    Authenticator authenticator;
    authenticator.hold_until_canceled = true;
    auto request = options(false);
    auto cancellation = Cancellation::create();
    Optional<Outcome> outcome;
    auto ceremony = Threading::Thread::construct("WebAuthnTest"sv, [&] -> intptr_t {
        outcome = WebView::WebAuthn::perform_on_open_device(authenticator.device, request, {}, cancellation.ptr());
        return 0;
    });
    ceremony->start();
    {
        MutexLocker locker { authenticator.mutex };
        while (!authenticator.request_is_starting)
            authenticator.condition.wait();
    }
    // NB: The request has not reached the authenticator yet, so the first cancel is lost.
    cancellation->cancel();
    (void)ceremony->join();
    EXPECT(authenticator.canceled_after_request);
    EXPECT(outcome.has_value());
    if (outcome.has_value())
        expect_outcome(*outcome, WebAuthn::Error::NotAllowed);
}

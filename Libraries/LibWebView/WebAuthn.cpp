/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Base64.h>
#include <AK/StringBuilder.h>
#include <AK/Time.h>
#include <AK/Utf8View.h>
#include <LibThreading/Thread.h>
#include <LibURL/Parser.h>
#include <LibWebCommon/SecureContexts/AbstractOperations.h>
#include <LibWebView/WebAuthn.h>

namespace WebView::WebAuthn {

bool Cancellation::is_canceled() const
{
    MutexLocker locker { m_mutex };
    return m_canceled;
}

void Cancellation::cancel()
{
    MutexLocker locker { m_mutex };
    m_canceled = true;
    m_condition.broadcast();
}

void Cancellation::run_interruptibly(Function<void()> const& operation, Function<void()> const& interrupt)
{
    {
        MutexLocker locker { m_mutex };
        if (m_canceled)
            return;
        m_operation_is_running = true;
    }

    // NB: An interrupt that arrives before the operation reaches the authenticator is lost, so it repeats until the
    //     operation returns. It runs on its own thread so that canceling never waits on device I/O.
    auto interrupter = Threading::Thread::construct("WebAuthnCancel"sv, [&] -> intptr_t {
        MutexLocker locker { m_mutex };
        m_condition.wait_while([&] { return m_operation_is_running && !m_canceled; });
        while (m_operation_is_running) {
            locker.unlock();
            interrupt();
            locker.lock();
            if (m_operation_is_running)
                (void)m_condition.wait_for(AK::Duration::from_milliseconds(100));
        }
        return 0;
    });
    interrupter->start();

    operation();

    {
        MutexLocker locker { m_mutex };
        m_operation_is_running = false;
        m_condition.broadcast();
    }
    (void)interrupter->join();
}

// https://w3c.github.io/webauthn/#sctn-timeout-recommended-range
static constexpr u32 minimum_timeout = 300'000;
static constexpr u32 maximum_timeout = 600'000;
static constexpr u32 default_timeout = 300'000;

// https://html.spec.whatwg.org/multipage/browsers.html#is-a-registrable-domain-suffix-of-or-is-equal-to
static bool is_a_registrable_domain_suffix_of_or_is_equal_to(URL::Host const& host_suffix, URL::Host const& original_host)
{
    auto ends_with_dot_prefixed = [](StringView string, StringView suffix) {
        return string.length() > suffix.length() && string.ends_with(suffix) && string[string.length() - suffix.length() - 1] == '.';
    };

    // 4. If hostSuffix does not equal originalHost, then:
    if (host_suffix != original_host) {
        // 1. If hostSuffix or originalHost is not a domain, then return false.
        if (!host_suffix.is_domain() || !original_host.is_domain())
            return false;
        auto suffix = host_suffix.serialize();

        // 2. If hostSuffix, prefixed by U+002E (.), does not match the end of originalHost, then return false.
        if (!ends_with_dot_prefixed(original_host.serialize(), suffix))
            return false;

        // 3. If any of the following are true:
        //     * hostSuffix equals hostSuffix's public suffix; or
        //     * hostSuffix, prefixed by U+002E (.), matches the end of originalHost's public suffix,
        //    then return false. [URL]
        if (suffix == host_suffix.public_suffix())
            return false;
        if (auto public_suffix = original_host.public_suffix(); !public_suffix.has_value() || ends_with_dot_prefixed(*public_suffix, suffix))
            return false;
    }

    // 5. Return true.
    return true;
}

// https://w3c.github.io/webauthn/#ccdtostring
static void append_ccd_string(StringBuilder& encoded, StringView string)
{
    // 2. Append 0x22 (") to encoded.
    encoded.append('"');

    // 4. For each code point in the resulting string, if the code point:
    for (auto code_point : Utf8View { string }) {
        // is in the set {U+0020, U+0021, U+0023–U+005B, U+005D–U+10FFFF}
        //     Append the UTF-8 encoding of that code point to encoded.
        if (code_point == 0x20 || code_point == 0x21 || (code_point >= 0x23 && code_point <= 0x5b) || code_point >= 0x5d)
            encoded.append_code_point(code_point);
        // is U+0022
        //     Append 0x5c22 (\") to encoded.
        else if (code_point == '"')
            encoded.append("\\\""sv);
        // is U+005C
        //     Append 0x5c5c (\\) to encoded.
        else if (code_point == '\\')
            encoded.append("\\\\"sv);
        // otherwise
        //     Append 0x5c75 (\u) to encoded, followed by four, lower-case hex digits that, when interpreted as a
        //     base-16 number, represent that code point.
        else
            encoded.appendff("\\u{:04x}", code_point);
    }

    // 5. Append 0x22 (") to encoded.
    encoded.append('"');
}

// https://w3c.github.io/webauthn/#clientdatajson-serialization
static ByteBuffer serialize_client_data(StringView type, StringView challenge, StringView origin)
{
    // 1. Let result be an empty byte string.
    StringBuilder result;

    // 2. Append 0x7b2274797065223a ({"type":) to result.
    result.append("{\"type\":"sv);

    // 3. Append CCDToString(type) to result.
    append_ccd_string(result, type);

    // 4. Append 0x2c226368616c6c656e6765223a (,"challenge":) to result.
    result.append(",\"challenge\":"sv);

    // 5. Append CCDToString(challenge) to result.
    append_ccd_string(result, challenge);

    // 6. Append 0x2c226f726967696e223a (,"origin":) to result.
    result.append(",\"origin\":"sv);

    // 7. Append CCDToString(origin) to result.
    append_ccd_string(result, origin);

    // 8. Append 0x2c2263726f73734f726967696e223a (,"crossOrigin":) to result.
    result.append(",\"crossOrigin\":"sv);

    // 9. If crossOrigin is not present, or is false:
    //     1. Append 0x66616c7365 (false) to result.
    // NB: Only top-level documents can run ceremonies, so crossOrigin is always false and topOrigin is never present.
    result.append("false"sv);

    // 12. Create a temporary copy of the CollectedClientData and remove the fields type, challenge, origin,
    //     crossOrigin (if present), and topOrigin (if present).
    // 13. If no fields remain in the temporary copy then:
    //     1. Append 0x7d (}) to result.
    result.append('}');

    // 15. The result of the serialization is the value of result.
    return MUST(result.to_byte_buffer());
}

// https://w3c.github.io/webauthn/#sctn-createCredential
// https://w3c.github.io/webauthn/#sctn-discover-from-external-source
// NB: These are the steps of [[Create]], and of [[DiscoverFromExternalSource]] where the same, that rely on what the
//     browser knows of the requesting document. The renderer has run the other steps that come before them.
Variant<AuthenticatorRequest, Error> prepare_request(Request const& request, URL::Origin const& origin)
{
    // 4. If pkOptions.timeout is present, check if its value lies within a reasonable range as defined by the client
    //    and if not, correct it to the closest value lying within that range. Set a timer lifetimeTimer to this
    //    adjusted value. If pkOptions.timeout is not present, then set lifetimeTimer to a client-specific default.
    auto timeout = clamp(request.timeout.value_or(default_timeout), minimum_timeout, maximum_timeout);

    // 6. Let callerOrigin be origin. If callerOrigin is an opaque origin, throw a "NotAllowedError" DOMException.
    if (origin.is_opaque())
        return Error::NotAllowed;

    // NB: The API is only exposed in secure contexts, which a renderer that asks from elsewhere has not respected.
    if (Web::SecureContexts::is_origin_potentially_trustworthy(origin) != Web::SecureContexts::Trustworthiness::PotentiallyTrustworthy)
        return Error::Security;

    // 7. Let effectiveDomain be the callerOrigin’s effective domain. If effective domain is not a valid domain, then
    //    throw a "SecurityError" DOMException.
    // NB: The effective domain of a tuple origin without a domain is its host.
    auto const& effective_domain = origin.host();
    if (!effective_domain.is_domain())
        return Error::Security;

    // 8. If pkOptions.rp.id
    //    is present
    //        If pkOptions.rp.id is not a registrable domain suffix of and is not equal to effectiveDomain, and if the
    //        client does not support related origin requests, throw a "SecurityError" DOMException.
    //    is not present
    //        Set pkOptions.rp.id to effectiveDomain.
    auto rp_id = effective_domain.serialize();
    if (request.rp_id.has_value()) {
        auto rp_host = URL::Parser::parse_host(*request.rp_id);
        if (request.rp_id->is_empty() || !rp_host.has_value() || !is_a_registrable_domain_suffix_of_or_is_equal_to(*rp_host, effective_domain))
            return Error::Security;
        rp_id = rp_host->serialize();
    }

    if (request.creation.has_value()) {
        // NB: The renderer has run these steps already, but the browser does not rely on it having done so.
        // 5. If the length of pkOptions.user.id is not between 1 and 64 bytes (inclusive) then throw a TypeError.
        auto user_id_size = request.creation->user_id.size();
        if (user_id_size < 1 || user_id_size > 64)
            return Error::Type;

        // NB: Only ES256 credentials are created, so no authenticator supports the other algorithms.
        static constexpr i32 es256 = -7;
        if (!request.creation->algorithms.contains_slow(es256))
            return Error::NotSupported;
    }

    // https://w3c.github.io/webauthn/#sctn-issuing-cred-request-to-authenticator
    // 1. If options.allowCredentials is not empty:
    //     ...
    //     3. If allowCredentialDescriptorList is empty, return false.
    // NB: No authenticator holds a credential of an unsupported type, so none is eligible, and the ceremony ends as if
    //     its timer expired.
    if (request.allows_only_unsupported_credentials)
        return Error::NotAllowed;

    // 13. Let collectedClientData be a new CollectedClientData instance whose fields are:
    //     type
    //         The string "webauthn.create".
    //     challenge
    //         The base64url encoding of pkOptions.challenge.
    //     origin
    //         The serialization of callerOrigin.
    // 14. Let clientDataJSON be the JSON-compatible serialization of client data constructed from collectedClientData.
    auto type = request.creation.has_value() ? "webauthn.create"sv : "webauthn.get"sv;
    auto challenge = MUST(encode_base64url(request.challenge, AK::OmitPadding::Yes));

    return AuthenticatorRequest {
        .origin = origin.serialize(),
        .rp_id = move(rp_id),
        .client_data_json = serialize_client_data(type, challenge, origin.serialize()),
        .credentials = request.credentials,
        .user_verification = request.user_verification,
        .timeout = timeout,
        .creation = request.creation,
    };
}

#ifndef LADYBIRD_HAS_LIBFIDO2
Vector<SecurityKey> enumerate_security_keys() { return {}; }
Outcome perform(AuthenticatorRequest const&, String const&, String const&, Cancellation&) { return Error::NotAllowed; }
#endif

}

/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/HostClassBuilder.h>
#include <LibJS/Runtime/VM.h>
#include <LibWeb/CredentialManagement/CredentialsContainer.h>
#include <LibWeb/DOM/AbortSignal.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/HTML/EventLoop/EventLoop.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/Page/Page.h>
#include <LibWebCommon/WebAuthn/WebAuthn.h>

GC_UNTRACED_CAPTURE(Web::WebAuthn::Response);

namespace Web::CredentialManagement {

// The layouts of RequestAbi, CreationOptionsAbi and ResponseAbi in Bindings/Rust/src/credential_management/webauthn.rs.
struct WebAuthnCreationOptionsABI {
    ReadonlyBytes rp_name;
    ReadonlyBytes user_id;
    ReadonlyBytes user_name;
    ReadonlyBytes user_display_name;
    ReadonlySpan<i32> algorithms;
    WebAuthn::ResidentKeyRequirement resident_key;
};

struct WebAuthnRequestABI {
    ReadonlyBytes challenge;
    bool has_rp_id;
    ReadonlyBytes rp_id;
    ReadonlySpan<ReadonlyBytes> credentials;
    bool allows_only_unsupported_credentials;
    WebAuthn::UserVerificationRequirement user_verification;
    bool has_timeout;
    u32 timeout;
    WebAuthnCreationOptionsABI const* creation;
};

struct WebAuthnResponseABI {
    ReadonlyBytes client_data_json;
    ReadonlyBytes raw_id;
    ReadonlyBytes authenticator_data;
    ReadonlyBytes attestation_object;
    ReadonlyBytes public_key;
    ReadonlyBytes signature;
    bool has_user_handle;
    ReadonlyBytes user_handle;
};

using WebAuthnSteps = void (*)(JSVM*, GC::Cell*, WebAuthn::Error, WebAuthnResponseABI const*);

static String string_from_utf8(ReadonlyBytes bytes)
{
    return MUST(String::from_utf8(StringView { bytes }));
}

static WebAuthn::Request request_from_abi(WebAuthnRequestABI const& options)
{
    WebAuthn::Request request {
        .challenge = MUST(ByteBuffer::copy(options.challenge)),
        .rp_id = {},
        .credentials = {},
        .allows_only_unsupported_credentials = options.allows_only_unsupported_credentials,
        .user_verification = options.user_verification,
        .timeout = {},
        .creation = {},
    };
    if (options.has_rp_id)
        request.rp_id = string_from_utf8(options.rp_id);
    if (options.has_timeout)
        request.timeout = options.timeout;
    for (auto id : options.credentials)
        request.credentials.append(MUST(ByteBuffer::copy(id)));
    if (auto const* creation = options.creation) {
        request.creation = WebAuthn::CreationOptions {
            .rp_name = string_from_utf8(creation->rp_name),
            .user_id = MUST(ByteBuffer::copy(creation->user_id)),
            .user_name = string_from_utf8(creation->user_name),
            .user_display_name = string_from_utf8(creation->user_display_name),
            .algorithms = {},
            .resident_key = creation->resident_key,
        };
        request.creation->algorithms.append(creation->algorithms.data(), creation->algorithms.size());
    }
    return request;
}

static void run_steps(WebAuthnSteps steps, GC::Cell& request, WebAuthn::Result const& result)
{
    auto* vm = JS::HostABI::vm_to_abi(JS::VM::the());
    result.visit(
        [&](WebAuthn::Response const& response) {
            WebAuthnResponseABI abi {
                .client_data_json = response.client_data_json,
                .raw_id = response.raw_id,
                .authenticator_data = response.authenticator_data,
                .attestation_object = response.attestation_object,
                .public_key = response.public_key,
                .signature = response.signature,
                .has_user_handle = response.user_handle.has_value(),
                .user_handle = response.user_handle.has_value() ? response.user_handle->bytes() : ReadonlyBytes {},
            };
            steps(vm, &request, WebAuthn::Error::NotAllowed, &abi);
        },
        [&](WebAuthn::Error error) {
            steps(vm, &request, error, nullptr);
        });
}

extern "C" {
CredentialsContainer* web_rust_credentials_container_create(JSVM*);
void web_credentials_request_public_key(HTML::Window*, GC::Cell*, DOM::AbortSignal*, WebAuthnRequestABI const*, WebAuthnSteps);

void web_credentials_request_public_key(HTML::Window* window, GC::Cell* request, DOM::AbortSignal* signal, WebAuthnRequestABI const* options, WebAuthnSteps steps)
{
    window->page().request_webauthn(window->associated_document().id(), request_from_abi(*options),
        GC::create_function(GC::Heap::the(), GC::captures(GC::Ref { *window }, GC::Ref { *request }, steps), [](auto& window, auto& request, auto& steps, WebAuthn::Result result) {
            HTML::queue_global_task(HTML::Task::Source::UserInteraction, HTML::relevant_global_object(*window),
                GC::create_function(GC::Heap::the(), GC::captures(request, steps, move(result)), [](auto& request, auto& steps, auto& result) {
                    run_steps(steps, *request, result);
                }));
        }),
        signal);
}
}

GC::Ref<CredentialsContainer> CredentialsContainer::create()
{
    return *web_rust_credentials_container_create(JS::HostABI::vm_to_abi(JS::VM::the()));
}

}

/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "HeadlessTest.h"
#include "ReportServer.h"
#include <AK/LexicalPath.h>
#include <AK/NumericLimits.h>
#include <LibGfx/SystemTheme.h>
#include <LibTest/TestCase.h>
#include <LibURL/Parser.h>
#include <LibWebView/HeadlessWebView.h>
#include <LibWebView/Utilities.h>
#include <LibWebView/WebAuthn.h>

namespace WebAuthn = WebView::WebAuthn;
using WebView::WebAuthn::AuthenticatorRequest;
using WebView::WebAuthn::Request;
using WebView::WebAuthn::Response;

namespace {

Request request()
{
    return { .challenge = MUST(ByteBuffer::copy("\x01\x02\x03"sv.bytes())), .rp_id = "example.com"_string, .credentials = {}, .allows_only_unsupported_credentials = false, .user_verification = Web::WebAuthn::UserVerificationRequirement::Preferred, .timeout = {}, .creation = {} };
}

Variant<AuthenticatorRequest, WebAuthn::Error> prepare(Request const& request, StringView url)
{
    return WebView::WebAuthn::prepare_request(request, URL::Parser::basic_parse(url)->origin());
}

void expect_error(Request const& request, StringView url, WebAuthn::Error error)
{
    auto result = prepare(request, url);
    EXPECT(result.has<WebAuthn::Error>());
    if (result.has<WebAuthn::Error>())
        EXPECT_EQ(result.get<WebAuthn::Error>(), error);
}

}

TEST_CASE(webauthn_validates_relying_party_domains)
{
    auto options = request();
    for (auto rp : { "com"sv, "evil.com"sv, "notexample.com"sv, "example.com.evil.com"sv, "https://example.com"sv, ""sv }) {
        options.rp_id = MUST(String::from_utf8(rp));
        expect_error(options, "https://login.example.com/"sv, WebAuthn::Error::Security);
    }
    options.rp_id = "github.io"_string;
    expect_error(options, "https://user.github.io/"sv, WebAuthn::Error::Security);
    options.rp_id = "co.uk"_string;
    expect_error(options, "https://example.co.uk/"sv, WebAuthn::Error::Security);
    options.rp_id = "example.com"_string;
    expect_error(options, "http://example.com/"sv, WebAuthn::Error::Security);
    expect_error(options, "https://127.0.0.1/"sv, WebAuthn::Error::Security);
    expect_error(options, "data:text/html,test"sv, WebAuthn::Error::NotAllowed);

    EXPECT(prepare(options, "https://login.example.com/"sv).has<AuthenticatorRequest>());
    options.rp_id = "localhost"_string;
    EXPECT(prepare(options, "http://localhost:8000/"sv).has<AuthenticatorRequest>());
    options.rp_id = {};
    auto defaulted = prepare(options, "https://login.example.com/"sv);
    EXPECT(defaulted.has<AuthenticatorRequest>());
    if (defaulted.has<AuthenticatorRequest>())
        EXPECT_EQ(defaulted.get<AuthenticatorRequest>().rp_id, "login.example.com"sv);
}

TEST_CASE(webauthn_constructs_client_data_from_trusted_origin)
{
    auto options = request();
    auto result = prepare(options, "https://login.example.com:8443/"sv);
    EXPECT(result.has<AuthenticatorRequest>());
    if (!result.has<AuthenticatorRequest>())
        return;
    auto const& prepared = result.get<AuthenticatorRequest>();
    EXPECT_EQ(StringView { prepared.client_data_json }, R"({"type":"webauthn.get","challenge":"AQID","origin":"https://login.example.com:8443","crossOrigin":false})"sv);
    EXPECT_EQ(prepared.origin, "https://login.example.com:8443"sv);
}

TEST_CASE(webauthn_clamps_timeouts)
{
    auto options = request();
    auto timeout_for = [&](Optional<u32> timeout) {
        options.timeout = timeout;
        return prepare(options, "https://example.com/"sv).get<AuthenticatorRequest>().timeout;
    };
    EXPECT_EQ(timeout_for({}), 300000u);
    EXPECT_EQ(timeout_for(0), 300000u);
    EXPECT_EQ(timeout_for(1), 300000u);
    EXPECT_EQ(timeout_for(450000), 450000u);
    EXPECT_EQ(timeout_for(NumericLimits<u32>::max()), 600000u);
}

TEST_CASE(webauthn_validates_creation_constraints)
{
    auto options = request();
    options.creation = Web::WebAuthn::CreationOptions {
        .rp_name = "Example"_string,
        .user_id = {},
        .user_name = "user"_string,
        .user_display_name = "User"_string,
        .algorithms = { -7 },
        .resident_key = Web::WebAuthn::ResidentKeyRequirement::Discouraged,
    };
    expect_error(options, "https://example.com/"sv, WebAuthn::Error::Type);
    options.creation->user_id = MUST(ByteBuffer::create_zeroed(65));
    expect_error(options, "https://example.com/"sv, WebAuthn::Error::Type);
    options.creation->user_id = MUST(ByteBuffer::copy("\x04"sv.bytes()));
    options.creation->algorithms = { -257 };
    expect_error(options, "https://example.com/"sv, WebAuthn::Error::NotSupported);
    options.creation->algorithms = { -257, -7 };
    auto result = prepare(options, "https://example.com/"sv);
    EXPECT(result.has<AuthenticatorRequest>());
    if (result.has<AuthenticatorRequest>())
        EXPECT(StringView { result.get<AuthenticatorRequest>().client_data_json }.starts_with(R"({"type":"webauthn.create",)"sv));
}

TEST_CASE(webauthn_rejects_allow_list_of_only_unsupported_credentials)
{
    auto options = request();
    options.allows_only_unsupported_credentials = true;
    expect_error(options, "https://example.com/"sv, WebAuthn::Error::NotAllowed);
    options.rp_id = "evil.com"_string;
    expect_error(options, "https://example.com/"sv, WebAuthn::Error::Security);
}

#ifndef AK_OS_WINDOWS
TEST_CASE(webauthn_browser_bridge_and_cancellation)
{
    Test::HeadlessTestEnvironment environment { "TestWebAuthn"sv };
    auto app = TRY_OR_FAIL(environment.create_application());
    ReportServerTest::ReportServer server;
    server.respond_with({ .status = 200, .body = "{}", .extra_headers = {} });

    auto theme_path = LexicalPath::join(WebView::s_ladybird_resource_root, "themes"sv, "Default.ini"sv);
    auto theme = TRY_OR_FAIL(Gfx::load_system_theme(theme_path.string()));
    auto view = WebView::HeadlessWebView::create(move(theme), { 800, 600 });
    size_t loads = 0;
    view->on_load_finish = [&](auto const&) { ++loads; };
    Core::EventLoop::current().spin_until([&] { return loads == 1; });
    auto endpoint = server.endpoint();
    auto url = URL::Parser::basic_parse(ByteString::formatted("http://localhost{}", endpoint.substring_view("http://127.0.0.1"sv.length()))).release_value();
    view->load_from_browser_ui(url);
    Core::EventLoop::current().spin_until([&] { return loads == 2; });
    view->set_has_system_focus(true);

    Optional<Utf16String> title;
    view->on_title_change = [&](auto const& value) { title = value; };
    size_t requests = 0;
    size_t canceled = 0;
    AuthenticatorRequest options;
    Function<void(WebAuthn::Result)> completion;
    view->on_request_webauthn = [&](AuthenticatorRequest request, Function<void(WebAuthn::Result)> done) -> Function<void()> {
        options = move(request);
        completion = move(done);
        ++requests;
        return [&] { ++canceled; completion = {}; };
    };
    view->run_javascript(R"(
        globalThis.challenge = new Uint8Array([1, 2, 3]);
        navigator.credentials.create({publicKey: {
            challenge, rp: {name: "Test", id: "localhost"},
            user: {id: new Uint8Array([4]), name: "user", displayName: "User"},
            pubKeyCredParams: [{type: "public-key", alg: -7}]
        }}).then(c => {
            const client = JSON.parse(new TextDecoder().decode(c.response.clientDataJSON));
            document.title = c instanceof PublicKeyCredential && c.response instanceof AuthenticatorAttestationResponse
                && c.type === "public-key" && c.id === "AQID" && c.authenticatorAttachment === "cross-platform"
                && new Uint8Array(c.rawId)[2] === 3 && c.response.getTransports()[0] === "usb"
                && c.response.getPublicKeyAlgorithm() === -7 && client.challenge === "AQID" ? "created" : "bad";
        }).catch(e => document.title = e.name);
        challenge.fill(9);
    )"_string);
    Core::EventLoop::current().spin_until([&] { return requests == 1 || title.has_value(); });
    VERIFY(requests == 1);
    EXPECT(StringView { options.client_data_json }.contains(R"("challenge":"AQID")"sv));
    auto bytes = [](std::initializer_list<u8> values) { return MUST(ByteBuffer::copy(values.begin(), values.size())); };
    auto respond = move(completion);
    respond(Response {
        .client_data_json = options.client_data_json,
        .raw_id = bytes({ 1, 2, 3 }),
        .authenticator_data = bytes({ 4, 5, 6 }),
        .attestation_object = bytes({ 0xa0 }),
        .public_key = bytes({ 7, 8, 9 }),
        .signature = {},
        .user_handle = {},
    });
    Core::EventLoop::current().spin_until([&] { return title.has_value(); });
    EXPECT_EQ(title, "created"sv);

    title.clear();
    view->run_javascript(R"(
        navigator.credentials.get({publicKey: {challenge: new Uint8Array([1]), rpId: "localhost"}})
        .then(c => document.title = c.response instanceof AuthenticatorAssertionResponse
            && new Uint8Array(c.response.signature)[0] === 4 && c.response.userHandle === null ? "asserted" : "bad")
        .catch(e => document.title = e.name);
    )"_string);
    Core::EventLoop::current().spin_until([&] { return requests == 2 || title.has_value(); });
    VERIFY(requests == 2);
    respond = move(completion);
    respond(Response {
        .client_data_json = options.client_data_json,
        .raw_id = bytes({ 1, 2, 3 }),
        .authenticator_data = bytes({ 1, 2, 3 }),
        .attestation_object = {},
        .public_key = {},
        .signature = bytes({ 4, 5, 6 }),
        .user_handle = {},
    });
    Core::EventLoop::current().spin_until([&] { return title.has_value(); });
    EXPECT_EQ(title, "asserted"sv);

    title.clear();
    auto cancellations_before_abort = canceled;
    view->run_javascript(R"(
        globalThis.controller = new AbortController();
        globalThis.reason = {};
        navigator.credentials.get({signal: controller.signal, publicKey: {challenge: new Uint8Array([1]), rpId: "localhost"}})
        .catch(e => document.title = e === reason ? "aborted" : "bad");
    )"_string);
    Core::EventLoop::current().spin_until([&] { return requests == 3; });
    auto late_response = move(completion);
    view->run_javascript("controller.abort(reason)"_string);
    Core::EventLoop::current().spin_until([&] { return title.has_value(); });
    EXPECT_EQ(title, "aborted"sv);
    EXPECT_EQ(canceled, cancellations_before_abort + 1);
    late_response(WebAuthn::Error::NotAllowed);

    view->run_javascript(R"(
        navigator.credentials.get({publicKey: {challenge: new Uint8Array([1]), rpId: "localhost"}}).catch(() => {});
    )"_string);
    Core::EventLoop::current().spin_until([&] { return requests == 4; });
    auto cancellations_before_navigation = canceled;
    view->load_html("<title>navigated</title>"sv);
    Core::EventLoop::current().spin_until([&] { return canceled > cancellations_before_navigation; });
}
#endif

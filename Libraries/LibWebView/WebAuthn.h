/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/AtomicRefCounted.h>
#include <AK/ConditionVariable.h>
#include <AK/Function.h>
#include <AK/Mutex.h>
#include <AK/String.h>
#include <AK/Variant.h>
#include <AK/Vector.h>
#include <LibURL/Origin.h>
#include <LibWebCommon/WebAuthn/WebAuthn.h>
#include <LibWebView/Export.h>

namespace WebView::WebAuthn {

using Web::WebAuthn::AuthenticatorRequest;
using Web::WebAuthn::Error;
using Web::WebAuthn::Request;
using Web::WebAuthn::Response;
using Web::WebAuthn::Result;

// Cancels a ceremony from any thread, interrupting the authenticator operation it is blocked on.
class WEBVIEW_API Cancellation final : public AtomicRefCounted<Cancellation> {
public:
    static NonnullRefPtr<Cancellation> create() { return adopt_ref(*new Cancellation); }

    bool is_canceled() const;
    void cancel();

    // Runs the blocking operation, unless the ceremony is already canceled. Once it is canceled, the interrupt runs
    // on another thread until the operation returns.
    void run_interruptibly(Function<void()> const& operation, Function<void()> const& interrupt);

private:
    Cancellation() = default;

    mutable Mutex m_mutex;
    ConditionVariable m_condition { m_mutex };
    bool m_canceled { false };
    bool m_operation_is_running { false };
};

struct SecurityKey {
    String path;
    String name;
};

struct Account {
    Response response;
    String name;
};

enum class PinStatus : u8 {
    Required,
    Invalid,
};

// The credential that was created, or the accounts the user may sign in to.
using Outcome = Variant<Vector<Account>, Error, PinStatus>;

// The origin must come from the browser's canonical document, not from WebContent.
WEBVIEW_API Variant<AuthenticatorRequest, Error> prepare_request(Request const&, URL::Origin const&);

// Blocking authenticator operations. Call only on a worker thread.
WEBVIEW_API Vector<SecurityKey> enumerate_security_keys();
WEBVIEW_API Outcome perform(AuthenticatorRequest const&, String const& device_path, String const& pin, Cancellation&);

}

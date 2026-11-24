/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWebView/WebAuthn.h>
#include <fido.h>

namespace WebView::WebAuthn {

// Runs the request on a device the caller has opened. The request must have come from prepare_request().
WEBVIEW_API Outcome perform_on_open_device(fido_dev_t*, AuthenticatorRequest const&, String const& pin, Cancellation* = nullptr);

}

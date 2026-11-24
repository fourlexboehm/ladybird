/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Function.h>
#include <LibWebCommon/WebAuthn/WebAuthn.h>

class QWidget;

namespace Ladybird {

// Shows a prompt that runs the request on a security key the user picks, and returns a function that dismisses it.
Function<void()> request_webauthn(QWidget*, Web::WebAuthn::AuthenticatorRequest, Function<void(Web::WebAuthn::Result)>);

}

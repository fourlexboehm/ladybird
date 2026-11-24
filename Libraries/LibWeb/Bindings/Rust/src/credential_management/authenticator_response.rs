/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! AuthenticatorResponse, https://w3c.github.io/webauthn/#authenticatorresponse

use core::ops::Deref;

use libjs_rust::api::{ArrayBuffer, Gc, ThrowCompletionOr, Trace, Value};

use super::authenticator_assertion_response::AuthenticatorAssertionResponse;
use super::authenticator_attestation_response::AuthenticatorAttestationResponse;
use crate::bindings::conversions::ToJs;
use crate::bindings::interface::{Inherits, Ref, Wrappable};
use crate::bindings::{CallContext, WebIdlResult};

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct AuthenticatorResponse {
    client_data_json: Gc<ArrayBuffer>,
}

impl Wrappable for AuthenticatorResponse {}

impl AuthenticatorResponse {
    pub(crate) fn new(client_data_json: Gc<ArrayBuffer>) -> Self {
        Self { client_data_json }
    }

    pub(crate) fn client_data_json(&self, _: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(self.client_data_json)
    }
}

#[derive(Clone, Copy, Trace)]
#[gc(crate = libjs_rust)]
#[expect(clippy::enum_variant_names, reason = "the variants are named after the interfaces")]
#[expect(dead_code, reason = "the base interface is never instantiated directly")]
pub(crate) enum AnyAuthenticatorResponse {
    AuthenticatorResponse(Ref<AuthenticatorResponse>),
    AuthenticatorAttestationResponse(Ref<AuthenticatorAttestationResponse>),
    AuthenticatorAssertionResponse(Ref<AuthenticatorAssertionResponse>),
}

impl Deref for AnyAuthenticatorResponse {
    type Target = AuthenticatorResponse;

    fn deref(&self) -> &AuthenticatorResponse {
        match self {
            Self::AuthenticatorResponse(response) => response,
            Self::AuthenticatorAttestationResponse(response) => response.parent(),
            Self::AuthenticatorAssertionResponse(response) => response.parent(),
        }
    }
}

impl ToJs for AnyAuthenticatorResponse {
    fn to_js(self, cx: &CallContext) -> ThrowCompletionOr<Value> {
        match self {
            Self::AuthenticatorResponse(response) => response.to_js(cx),
            Self::AuthenticatorAttestationResponse(response) => response.to_js(cx),
            Self::AuthenticatorAssertionResponse(response) => response.to_js(cx),
        }
    }
}

/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! PublicKeyCredential, https://w3c.github.io/webauthn/#publickeycredential

use ak::Utf16String;
use libjs_rust::api::{ArrayBuffer, Gc, MarkedVec, Trace, Value};

use super::authenticator_response::AnyAuthenticatorResponse;
use super::credential::Credential;
use crate::bindings::conversions::{BufferSource, UsvString, record_to_js};
use crate::bindings::interface::{Inherits, Wrappable};
use crate::bindings::promise::{WebIdlPromise, create_rejected_promise_from_exception, create_resolved_promise};
use crate::bindings::{CallContext, Exception, WebIdlResult};

pub(crate) struct PublicKeyCredentialParameters {
    pub(crate) alg: i32,
    pub(crate) r#type: Utf16String,
}

pub(crate) struct PublicKeyCredentialEntity {
    pub(crate) name: Utf16String,
}

pub(crate) struct PublicKeyCredentialRpEntity {
    pub(crate) parent: PublicKeyCredentialEntity,
    pub(crate) id: Option<Utf16String>,
}

pub(crate) struct PublicKeyCredentialUserEntity {
    pub(crate) parent: PublicKeyCredentialEntity,
    pub(crate) display_name: Utf16String,
    pub(crate) id: BufferSource,
}

pub(crate) struct AuthenticatorSelectionCriteria {
    pub(crate) authenticator_attachment: Option<Utf16String>,
    pub(crate) require_resident_key: bool,
    pub(crate) resident_key: Option<Utf16String>,
    pub(crate) user_verification: Utf16String,
}

#[derive(Clone, Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct PublicKeyCredentialDescriptor {
    pub(crate) id: BufferSource,
    #[gc(untraced)]
    #[allow(dead_code, reason = "transport hints are not implemented")]
    pub(crate) transports: Option<Vec<Utf16String>>,
    #[gc(untraced)]
    pub(crate) r#type: Utf16String,
}

pub(crate) struct AuthenticationExtensionsClientInputs {}

#[derive(Clone)]
pub(crate) struct AuthenticationExtensionsClientOutputs {}

#[expect(
    dead_code,
    reason = "attestation preferences, extensions and hints are not implemented"
)]
pub(crate) struct PublicKeyCredentialCreationOptions<'vm> {
    pub(crate) attestation: Utf16String,
    pub(crate) attestation_formats: Vec<Utf16String>,
    pub(crate) authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub(crate) challenge: BufferSource,
    pub(crate) exclude_credentials: MarkedVec<'vm, PublicKeyCredentialDescriptor>,
    pub(crate) extensions: Option<AuthenticationExtensionsClientInputs>,
    pub(crate) hints: Vec<Utf16String>,
    pub(crate) pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub(crate) rp: PublicKeyCredentialRpEntity,
    pub(crate) timeout: Option<u32>,
    pub(crate) user: PublicKeyCredentialUserEntity,
}

#[expect(dead_code, reason = "extensions and hints are not implemented")]
pub(crate) struct PublicKeyCredentialRequestOptions<'vm> {
    pub(crate) allow_credentials: MarkedVec<'vm, PublicKeyCredentialDescriptor>,
    pub(crate) challenge: BufferSource,
    pub(crate) extensions: Option<AuthenticationExtensionsClientInputs>,
    pub(crate) hints: Vec<Utf16String>,
    pub(crate) rp_id: Option<Utf16String>,
    pub(crate) timeout: Option<u32>,
    pub(crate) user_verification: Utf16String,
}

#[expect(dead_code, reason = "credential signals are not implemented")]
pub(crate) struct UnknownCredentialOptions {
    pub(crate) credential_id: Utf16String,
    pub(crate) rp_id: Utf16String,
}

#[expect(dead_code, reason = "credential signals are not implemented")]
pub(crate) struct AllAcceptedCredentialsOptions {
    pub(crate) all_accepted_credential_ids: Vec<Utf16String>,
    pub(crate) rp_id: Utf16String,
    pub(crate) user_id: Utf16String,
}

#[expect(dead_code, reason = "credential signals are not implemented")]
pub(crate) struct CurrentUserDetailsOptions {
    pub(crate) display_name: Utf16String,
    pub(crate) name: Utf16String,
    pub(crate) rp_id: Utf16String,
    pub(crate) user_id: Utf16String,
}

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct PublicKeyCredential {
    credential: Credential,
    raw_id: Gc<ArrayBuffer>,
    response: AnyAuthenticatorResponse,
    #[gc(untraced)]
    authenticator_attachment: Option<Utf16String>,
    #[gc(untraced)]
    client_extension_results: AuthenticationExtensionsClientOutputs,
}

impl Wrappable for PublicKeyCredential {}

impl Inherits<Credential> for PublicKeyCredential {
    fn parent(&self) -> &Credential {
        &self.credential
    }
}

fn resolved_boolean(cx: &CallContext, value: bool) -> WebIdlPromise {
    create_resolved_promise(cx.vm(), cx.realm(), Value::from_bool(value))
}

fn unsupported_signal(cx: &CallContext) -> WebIdlPromise {
    create_rejected_promise_from_exception(
        cx.vm(),
        cx.realm(),
        Exception::Dom(
            "NotSupportedError",
            Utf16String::from_ascii(b"WebAuthn credential signals are not available yet."),
        ),
    )
}

impl PublicKeyCredential {
    pub(crate) fn new(
        id: UsvString,
        raw_id: Gc<ArrayBuffer>,
        response: AnyAuthenticatorResponse,
        authenticator_attachment: Option<Utf16String>,
        client_extension_results: AuthenticationExtensionsClientOutputs,
    ) -> Self {
        Self {
            credential: Credential::new(id, "public-key"),
            raw_id,
            response,
            authenticator_attachment,
            client_extension_results,
        }
    }

    pub(crate) fn raw_id(&self, _: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(self.raw_id)
    }

    pub(crate) fn response(&self, _: &mut CallContext) -> WebIdlResult<AnyAuthenticatorResponse> {
        Ok(self.response)
    }

    pub(crate) fn authenticator_attachment(&self, _: &mut CallContext) -> WebIdlResult<Option<Utf16String>> {
        Ok(self.authenticator_attachment.clone())
    }

    pub(crate) fn get_client_extension_results(
        &self,
        _: &mut CallContext,
    ) -> WebIdlResult<AuthenticationExtensionsClientOutputs> {
        Ok(self.client_extension_results.clone())
    }

    pub(crate) fn is_conditional_mediation_available(cx: &mut CallContext) -> WebIdlResult<WebIdlPromise> {
        Ok(resolved_boolean(cx, false))
    }

    pub(crate) fn is_user_verifying_platform_authenticator_available(
        cx: &mut CallContext,
    ) -> WebIdlResult<WebIdlPromise> {
        Ok(resolved_boolean(cx, false))
    }

    pub(crate) fn get_client_capabilities(cx: &mut CallContext) -> WebIdlResult<WebIdlPromise> {
        let capabilities = [
            "conditionalCreate",
            "conditionalGet",
            "hybridTransport",
            "passkeyPlatformAuthenticator",
            "relatedOrigins",
            "signalAllAcceptedCredentials",
            "signalCurrentUserDetails",
            "signalUnknownCredential",
            "userVerifyingPlatformAuthenticator",
        ]
        .into_iter()
        .map(|capability| (Utf16String::from_utf8(capability), false))
        .collect();
        let value = record_to_js(cx, capabilities, |supported| Ok(Value::from_bool(supported)))?;
        Ok(create_resolved_promise(cx.vm(), cx.realm(), value))
    }

    pub(crate) fn signal_unknown_credential(
        cx: &mut CallContext,
        _: UnknownCredentialOptions,
    ) -> WebIdlResult<WebIdlPromise> {
        Ok(unsupported_signal(cx))
    }

    pub(crate) fn signal_all_accepted_credentials(
        cx: &mut CallContext,
        _: AllAcceptedCredentialsOptions,
    ) -> WebIdlResult<WebIdlPromise> {
        Ok(unsupported_signal(cx))
    }

    pub(crate) fn signal_current_user_details(
        cx: &mut CallContext,
        _: CurrentUserDetailsOptions,
    ) -> WebIdlResult<WebIdlPromise> {
        Ok(unsupported_signal(cx))
    }
}

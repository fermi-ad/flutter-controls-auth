import 'dart:async';
import 'dart:js_interop';

import 'package:openid_client/openid_client.dart';
import 'package:web/web.dart' hide Credential, Client;

import 'openid_common.dart';

const _stateKey = 'openid_client:state';
const _codeVerifierKey = 'openid_client:code_verifier';
const _redirectUriKey = 'openid_client:redirect_uri';

/// Computes a clean redirect URI from the current browser location by stripping
/// the fragment and any query parameters (which may include leftover auth
/// response values from a previous redirect).
Uri _baseRedirectUri() => Uri.parse(
  window.location.href,
).removeFragment().replace(queryParameters: <String, String>{});

Future<Credential> authenticate(
  Client client, {
  List<String> scopes = const [],
}) async {
  // Generate our own code verifier so we can persist it across the redirect.
  // The library's browser Authenticator hardcodes the implicit flow, which
  // exposes tokens in the URL fragment and is deprecated by OAuth 2.1.
  // Authorization Code + PKCE with S256 is the recommended best practice.
  //
  // NOTE: The KeyCloak client must have the app's origin listed in its
  // "Web Origins" setting so the browser can POST to the token endpoint.

  final codeVerifier = generateCodeVerifier();
  final redirectUri = _baseRedirectUri();
  final flow = Flow.authorizationCodeWithPKCE(
    client,
    scopes: mergeScopes(scopes),
    codeVerifier: codeVerifier,
  )..redirectUri = redirectUri;

  // Persist the state, code verifier, and redirect URI so they survive the
  // browser redirect. The redirect URI is stored to guarantee an exact match
  // during the token exchange (OAuth 2.0 requires it).

  window.localStorage.setItem(_stateKey, flow.state);
  window.localStorage.setItem(_codeVerifierKey, codeVerifier);
  window.localStorage.setItem(_redirectUriKey, redirectUri.toString());

  // Redirect the browser to the authorization endpoint.

  window.location.href = flow.authenticationUri.toString();

  // The page will navigate away; this future never completes.

  return Completer<Credential>().future;
}

Future<Credential?> getRedirectResult(
  Client client, {
  List<String> scopes = const [],
}) async {
  final uri = Uri.parse(window.location.href);
  final params = uri.queryParameters;

  // The authorization code is delivered as a query parameter after the
  // redirect from the authorization server.

  if (!params.containsKey('code')) return null;

  // Retrieve the persisted PKCE values.

  final savedState = window.localStorage.getItem(_stateKey);
  final savedVerifier = window.localStorage.getItem(_codeVerifierKey);
  final savedRedirectUri = window.localStorage.getItem(_redirectUriKey);

  if (savedState == null || savedVerifier == null || savedRedirectUri == null) {
    return null;
  }

  // Clean up stored values immediately to prevent replay.

  window.localStorage.removeItem(_stateKey);
  window.localStorage.removeItem(_codeVerifierKey);
  window.localStorage.removeItem(_redirectUriKey);

  // Reconstruct the PKCE flow with the original code verifier and the exact
  // redirect URI that was used in the authorization request. OAuth 2.0
  // requires the redirect_uri in the token exchange to match exactly.

  final flow = Flow.authorizationCodeWithPKCE(
    client,
    scopes: mergeScopes(scopes),
    state: savedState,
    codeVerifier: savedVerifier,
  )..redirectUri = Uri.parse(savedRedirectUri);

  // Strip the authorization response parameters from the browser URL so they
  // are not leaked in the address bar or browser history.

  window.history.replaceState(''.toJS, '', savedRedirectUri);

  // Exchange the authorization code for tokens.

  return flow.callback(params.cast());
}

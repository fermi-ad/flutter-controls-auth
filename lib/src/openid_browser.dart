import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';

import 'package:openid_client/openid_client.dart';
import 'package:web/web.dart' hide Credential, Client;

import 'openid_common.dart';

const _stateKey = 'openid_client:state';
const _codeVerifierKey = 'openid_client:code_verifier';
const _redirectUriKey = 'openid_client:redirect_uri';

/// Builds the `localStorage` key used to cache a credential. The key is
/// namespaced under `controls:credential` and qualified by [audience] (empty
/// string when `null`) and the sorted, space-joined [scopes] so that tokens
/// for different resource servers or scope sets are stored independently.
String _credentialKey(String? audience, List<String> scopes) {
  final sortedScopes = ([...scopes]..sort()).join(' ');

  return 'controls:credential:${audience ?? ''}:$sortedScopes';
}

/// Persists [credential] in `localStorage` under a key derived from
/// [audience] and [scopes]. The raw token-response map is JSON-encoded so
/// that it survives page reloads and is readable by any app on the same
/// origin.
void saveCredential(
  Credential credential, {
  String? audience,
  List<String> scopes = const [],
}) {
  final response = credential.response;

  if (response == null) return;

  final key = _credentialKey(audience, scopes);

  window.localStorage.setItem(key, jsonEncode(response));
}

/// Loads a previously cached [Credential] from `localStorage` for the given
/// [audience] and [scopes]. Returns `null` when no entry exists, the stored
/// JSON is malformed, or the access token has already expired.
///
/// Expiry is checked against the `expires_at` field (Unix seconds) written
/// by [saveCredential]. A 30-second clock-skew buffer is applied so that a
/// token that is about to expire is treated as expired and will be refreshed
/// before it is actually invalid.
Credential? loadCredential(
  Client client, {
  String? audience,
  List<String> scopes = const [],
}) {
  final key = _credentialKey(audience, scopes);
  final raw = window.localStorage.getItem(key);

  if (raw == null) return null;

  try {
    final Map<String, dynamic> response = (jsonDecode(raw) as Map)
        .cast<String, dynamic>();

    // Reject tokens that have already expired (with a 30-second buffer).
    final expiresAt = response['expires_at'];

    if (expiresAt is num) {
      final expiry = DateTime.fromMillisecondsSinceEpoch(
        (expiresAt * 1000).toInt(),
      );

      if (DateTime.now().isAfter(
        expiry.subtract(const Duration(seconds: 30)),
      )) {
        window.localStorage.removeItem(key);
        return null;
      }
    }

    return client.createCredential(
      accessToken: response['access_token'] as String? ?? '',
      idToken: response['id_token'] as String?,
      refreshToken: response['refresh_token'] as String?,
      tokenType: response['token_type'] as String? ?? 'Bearer',
    );
  } catch (_) {
    // Corrupt entry — remove it so the next call triggers a fresh login.
    window.localStorage.removeItem(key);
    return null;
  }
}

/// Removes the cached credential for [audience] + [scopes] from
/// `localStorage`, e.g. on logout.
void clearCredential({String? audience, List<String> scopes = const []}) {
  window.localStorage.removeItem(_credentialKey(audience, scopes));
}

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

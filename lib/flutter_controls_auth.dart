/// Provides authentication services to Flutter apps.
///
/// Note: application authors don't directly use this package; these
/// widgets and types are used by our other packages.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:developer' as dev;

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:openid_client/openid_client.dart';
import 'package:toastification/toastification.dart' show toastification;
import 'src/openid_browser.dart'
    if (dart.library.io) 'src/openid_io.dart'
    as oid;
import 'src/message_boxes.dart' show errorBox, infoBox;

export 'package:openid_client/openid_client.dart' show Credential, UserInfo;
export 'src/message_boxes.dart' show errorBox, infoBox, warningBox;

/// Defines the authorization information required by the application. This
/// is the one structure that applications will use.
class AuthInfo {
  final String realm;
  final String clientId;

  /// The OAuth 2.0 audience (resource server) this app targets. When `null`
  /// (the default) only realm-wide roles are available in the token. Set this
  /// to a Keycloak client ID to receive that client's roles in
  /// `resource_access`.
  final String? audience;

  const AuthInfo({
    this.realm = "acnetconsole",
    required this.clientId,
    this.audience,
  });
}

String _base64UrlDecode(String base64Url) {
  String normalized = base64Url.replaceAll('-', '+').replaceAll('_', '/');

  switch (normalized.length % 4) {
    case 2:
      normalized += '==';
    case 3:
      normalized += '=';
  }

  return utf8.decode(base64Decode(normalized));
}

// Parses the `exp` claim from a JWT access token and returns the expiry as a
// [DateTime]. Returns `null` if the token is absent, malformed, or has no
// `exp` claim.
DateTime? _jwtExpiry(String? jwt) {
  try {
    if (jwt?.split('.') case [_, final payload, _]) {
      final dec = jsonDecode(_base64UrlDecode(payload));

      if (dec case {'exp': final num exp}) {
        return DateTime.fromMillisecondsSinceEpoch(
          (exp * 1000).toInt(),
          isUtc: true,
        );
      }
    }
  } catch (_) {}
  return null;
}

// Extracts the roles from the JWT. Although the application has access to the
// JWT, the app shouldn't have to know how to properly extract the roles. This
// function pulls the roles defined for the entire realm and for the current
// application.

Set<String> _extractRolesFromJwt(String? jwt, String? clientId) {
  // Initialize the set of roles.

  final Set<String> roles = {};

  try {
    // The JWT is made up of three fields separated by periods. This
    // conditional checks that the JWT is well-formed and extracts the payload,
    // which is the second field.

    if (jwt?.split('.') case [_, final payloadBase64Url, _]) {
      // The payload is a base64url-encoded JSON string.

      final dec = jsonDecode(_base64UrlDecode(payloadBase64Url));

      // If the client ID isn't defined, there are no client-specific roles to
      // extract.

      if (clientId != null) {
        if (dec case {
          'resource_access': final Map<String, dynamic> resourceAccess,
        }) {
          if (resourceAccess[clientId] case {'roles': final List rolesList}) {
            roles.addAll(rolesList.map((v) => v.toString()));
          }
        }
      }

      if (dec case {'realm_access': {'roles': final List rolesList}}) {
        roles.addAll(rolesList.map((v) => v.toString()));
      }
    }
  } catch (_) {}
  return roles;
}

class _AuthCredentials extends InheritedWidget {
  final Credential? credentials;
  final UserInfo? userInfo;
  final Set<String> roles;

  const _AuthCredentials({
    required this.credentials,
    required this.userInfo,
    required this.roles,
    required super.child,
  });

  @override
  bool updateShouldNotify(covariant _AuthCredentials oldWidget) =>
      oldWidget.credentials != credentials || oldWidget.userInfo != userInfo;
}

/// Provides authentication services.
///
/// Place this widget near the root of your application (inside
/// [ToastificationWrapper] if you use toastification). Pass your [AuthInfo]
/// directly — there is no separate `initAuth()` call required.
///
/// The widget renders immediately with no network calls. Keycloak is only
/// contacted when the user explicitly calls [requestLogin], or on web when
/// the page load is the post-login redirect carrying an authorization code.
/// If Keycloak is unreachable, an [errorBox] toast is shown at that point;
/// the app continues to function for unprivileged use.
///
/// Example:
/// ```dart
/// AuthService(
///   authInfo: AuthInfo(clientId: 'my-app'),
///   child: MyApp(),
/// )
/// ```
class AuthService extends StatefulWidget {
  final AuthInfo authInfo;
  final Widget child;

  /// Overrides the OpenID [Client] used for token operations. Only set this
  /// in tests — production code always passes `null` so that [_AuthState]
  /// performs real [Issuer.discover()] on first use.
  @visibleForTesting
  final Client? oidClient;

  /// Overrides the [http.Client] used for token-endpoint requests. Only set
  /// this in tests — production code always passes `null` so that
  /// [_AuthState] uses the default [http.Client].
  @visibleForTesting
  final http.Client? httpClient;

  /// Overrides the browser/native login flow. Only set this in tests.
  @visibleForTesting
  final Future<Credential> Function(Client client)? authenticateForTest;

  const AuthService({
    required this.authInfo,
    required this.child,
    super.key,
    this.oidClient,
    this.httpClient,
    this.authenticateForTest,
  });

  @override
  State<AuthService> createState() => _AuthState();

  static Credential? getCreds(BuildContext context) => context
      .dependOnInheritedWidgetOfExactType<_AuthCredentials>()
      ?.credentials;

  /// Returns the Access Token (JWT) containing authorization roles and claims.
  static String? getJwt(BuildContext context) =>
      context
              .dependOnInheritedWidgetOfExactType<_AuthCredentials>()
              ?.credentials
              ?.response?['access_token']
          as String?;

  static bool inRole(BuildContext context, String name) =>
      context
          .dependOnInheritedWidgetOfExactType<_AuthCredentials>()
          ?.roles
          .contains(name) ??
      false;

  static UserInfo? getUserInfo(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<_AuthCredentials>()?.userInfo;

  /// Returns the expiry time of the JWT access token, or `null` if the user
  /// is not logged in, the token is absent, or the token has no `exp` claim.
  static DateTime? getJwtExpiry(BuildContext context) =>
      _jwtExpiry(getJwt(context));

  static Future<void> requestLogin(BuildContext context) async =>
      await context.findAncestorStateOfType<_AuthState>()?.requestLogin();

  static Future<void> requestLogout(BuildContext context) async =>
      await context.findAncestorStateOfType<_AuthState>()?.requestLogout();
}

class _AuthState extends State<AuthService> {
  // ---------------------------------------------------------------------------
  // Instance state
  // ---------------------------------------------------------------------------

  static const List<String> _scopes = ['roles'];

  // How far before token expiry to fire the renewal timer.
  static const _renewalLeadTime = Duration(minutes: 2);

  Credential? _credential;
  UserInfo? _userInfo;

  // Cached role set — recomputed only when _credential changes, not on every
  // build() call.
  Set<String> _roles = const {};

  // Lazily set on first successful Issuer.discover(); reused for all
  // subsequent login attempts.
  Client? _client;

  // Background renewal timer — cancelled on logout / dispose.
  Timer? _renewalTimer;

  // Reused for all renewal requests and closed on dispose when state created it.
  late final http.Client _renewalHttpClient;
  bool _ownsRenewalHttpClient = false;

  // Monotonically increasing counter. Incremented on every logout so that
  // any in-flight _renewToken() call can detect that the session it was
  // renewing is no longer active and discard its result.
  int _sessionGeneration = 0;

  AuthInfo get _info => widget.authInfo;

  bool get _authenticated => _credential != null;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    final injectedHttpClient = widget.httpClient;
    if (injectedHttpClient != null) {
      _renewalHttpClient = injectedHttpClient;
    } else {
      _renewalHttpClient = http.Client();
      _ownsRenewalHttpClient = true;
    }
    _initialize();
  }

  @override
  void dispose() {
    _sessionGeneration++;
    _renewalTimer?.cancel();
    if (_ownsRenewalHttpClient) _renewalHttpClient.close();
    super.dispose();
  }

  // Runs at startup with zero network calls unless a redirect code is present.
  Future<void> _initialize() async {
    // On web: if this page load is the post-login redirect (URL contains
    // ?code=...), we must exchange the code immediately — it expires quickly.
    // In every other case we skip discovery entirely and let the app render.
    if (!oid.hasRedirectCode()) {
      // No redirect code. Check localStorage for a cached token (no network).
      // We need a Client to reconstruct the Credential object, but we can
      // build a stub issuer from the well-known URL without fetching it —
      // loadCredential only needs the client to call client.createCredential(),
      // which is a pure local operation. However, the openid_client library
      // requires a real Issuer, so we must discover lazily here only if cached.
      //
      // Simpler: just skip the cache check at startup and let the user log in
      // normally. The cache is an optimisation for web SSO; on native there is
      // no cache at all. If the user has a cached token the login flow will
      // find it via loadCredential() inside _ensureClient().
      return;
    }

    // Redirect code present — must discover and exchange now.
    final client = await _ensureClient();
    if (client == null || !mounted) return;

    try {
      final redirectCred = await oid.getRedirectResult(client, scopes: _scopes);
      if (!mounted) return;

      if (redirectCred != null) {
        oid.saveCredential(
          redirectCred,
          audience: _info.audience,
          scopes: _scopes,
        );
        setState(() => _setCredential(redirectCred, showToast: true));
      }
    } catch (e) {
      dev.log('redirect token exchange failed: $e', name: 'auth');
      if (mounted) _showAuthError(e);
    }
  }

  /// Ensures [_client] is set, performing [Issuer.discover()] if needed.
  /// Returns the client on success, or `null` if discovery fails (in which
  /// case an error toast has already been shown).
  Future<Client?> _ensureClient() async {
    // Allow tests to inject a pre-built Client, bypassing network discovery.
    if (widget.oidClient != null) return _client = widget.oidClient;
    if (_client != null) return _client;

    final uri = Uri.parse('https://ad-auth.fnal.gov/realms/${_info.realm}/');
    const tmo = Duration(seconds: 5);

    try {
      final issuer = await Issuer.discover(uri).timeout(tmo);
      _client = Client(issuer, _info.clientId);
      return _client;
    } catch (e) {
      dev.log('OpenID discovery failed: $e', name: 'auth');
      if (mounted) _showAuthError(e);
      return null;
    }
  }

  void _showAuthError(Object e) {
    // Schedule the toast after the current build frame completes. Dismiss any
    // queued toasts first so the error isn't buried. scheduleFrame() is
    // required on desktop: Flutter won't render a new frame without user input
    // when idle, so the postFrameCallback would never fire.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) {
        toastification.dismissAll(delayForAnimation: false);
        errorBox(
          context,
          'Authentication Unavailable',
          'Could not reach the authentication service. '
              'Some features may be disabled.',
          duration: const Duration(seconds: 8),
        );
      }
    });
    WidgetsBinding.instance.scheduleFrame();
  }

  // Sets _credential, _userInfo, and _roles together so they're always in sync.
  // Must be called inside setState(). Pass [showToast] = true only on an
  // explicit user-initiated login — silent background renewals should not
  // re-announce the user.
  void _setCredential(Credential cred, {bool showToast = false}) {
    _credential = cred;
    _userInfo = _tryExtractUserInfo(cred);
    _roles = _extractRolesFromJwt(
      cred.response?['access_token'] as String?,
      _info.clientId,
    );
    _scheduleRenewal(cred);

    if (showToast) {
      // Show the login toast after the frame that triggered this setState().
      // scheduleFrame() is required on desktop: Flutter won't render a new
      // frame without user input when idle, so the postFrameCallback would
      // never fire.
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted && _userInfo != null) {
          infoBox(
            context,
            'Notice',
            'You are logged in as ${_userInfo!.name ?? "UNKNOWN"}.',
          );
        }
      });
      WidgetsBinding.instance.scheduleFrame();
    }
  }

  /// Seeds the widget with [cred] as if the user had just logged in.
  /// Only call this from tests — it bypasses the normal login flow.
  @visibleForTesting
  void setCredentialForTest(Credential cred) => _setCredential(cred);

  // Clears credential state together. Must be called inside setState().
  void _clearCredential() {
    // Bump the generation so any in-flight _renewToken() discards its result.
    _sessionGeneration++;
    _renewalTimer?.cancel();
    _renewalTimer = null;
    _credential = null;
    _userInfo = null;
    _roles = const {};
  }

  // ---------------------------------------------------------------------------
  // Token renewal
  // ---------------------------------------------------------------------------

  // Arms (or re-arms) the background renewal timer based on the access token's
  // `exp` claim. Fires [_renewalLeadTime] before expiry. If the token has no
  // `exp` claim, or expiry is already past (or too close), the timer is not
  // set — the user will simply need to log in again.
  void _scheduleRenewal(Credential cred) {
    _renewalTimer?.cancel();
    _renewalTimer = null;

    final jwt = cred.response?['access_token'] as String?;
    final expiry = _jwtExpiry(jwt);

    if (expiry == null) return;

    final fireAt = expiry.subtract(_renewalLeadTime);
    final delay = fireAt.difference(DateTime.now().toUtc());

    if (delay <= Duration.zero) {
      // Token is already expired or too close to expiry — attempt renewal now.
      _renewToken(cred);
    } else {
      dev.log(
        'renewal scheduled in ${delay.inSeconds}s '
        '(token expires at ${expiry.toIso8601String()})',
        name: 'auth',
      );

      _renewalTimer = Timer(delay, () => _renewToken(cred));
    }
  }

  // Exchanges the refresh token for a new access token via Keycloak's token
  // endpoint. On success the new credential is persisted and state is updated.
  // On failure the credential is left in place until it expires, at which
  // point it is cleared so that requestLogin() can recover.
  Future<void> _renewToken(Credential cred) async {
    // Capture the session generation before any await so we can detect a
    // logout that occurs while the HTTP request is in flight.
    final generation = _sessionGeneration;

    final refreshToken = cred.response?['refresh_token'] as String?;

    if (refreshToken == null) {
      dev.log('no refresh token available — skipping renewal', name: 'auth');
      return;
    }

    final client = await _ensureClient();

    if (client == null || _sessionGeneration != generation) return;

    final tokenEndpoint = client.issuer.metadata.tokenEndpoint;

    if (tokenEndpoint == null) {
      dev.log('token endpoint not available — skipping renewal', name: 'auth');
      return;
    }

    dev.log('renewing token in background', name: 'auth');

    try {
      final response = await _renewalHttpClient.post(
        tokenEndpoint,
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: {
          'grant_type': 'refresh_token',
          'client_id': _info.clientId,
          'refresh_token': refreshToken,
        },
      );

      // If the session was invalidated (logout) while we were waiting, discard
      // the response entirely — do not restore credentials or touch storage.
      if (_sessionGeneration != generation) return;

      if (response.statusCode != 200) {
        dev.log(
          'token renewal failed: HTTP ${response.statusCode}',
          name: 'auth',
        );
        if (mounted) _handleRenewalFailure(cred, generation);
        return;
      }

      final Map<String, dynamic> body = (jsonDecode(response.body) as Map)
          .cast<String, dynamic>();

      // Validate the complete provider payload before constructing or saving a
      // credential. A 200 response can still be malformed and must not replace
      // the last usable credential with partial or unusable state.
      final accessToken = body['access_token'];
      if (accessToken is! String || accessToken.isEmpty) {
        throw const FormatException(
          'Token renewal response has no access_token',
        );
      }

      final rawExpiresIn = body['expires_in'];
      final expiresInSeconds = switch (rawExpiresIn) {
        null => null,
        num value when value >= 0 => value.toInt(),
        String value => int.tryParse(value),
        _ => null,
      };
      if (rawExpiresIn != null && expiresInSeconds == null) {
        throw const FormatException(
          'Token renewal response has invalid expires_in',
        );
      }

      // Some providers omit id_token during a refresh. Keep the previous one
      // so relying parties do not lose identity claims on an otherwise valid
      // access-token renewal.
      final oldIdToken = cred.response?['id_token'];
      final idToken = body['id_token'] is String
          ? body['id_token'] as String
          : oldIdToken is String
          ? oldIdToken
          : null;
      final returnedRefreshToken = body['refresh_token'];
      if (returnedRefreshToken != null && returnedRefreshToken is! String) {
        throw const FormatException(
          'Token renewal response has invalid refresh_token',
        );
      }

      final newCred = client.createCredential(
        accessToken: accessToken,
        idToken: idToken,
        refreshToken: returnedRefreshToken as String? ?? refreshToken,
        tokenType: body['token_type'] as String? ?? 'Bearer',
        expiresIn: expiresInSeconds == null
            ? null
            : Duration(seconds: expiresInSeconds),
      );

      oid.saveCredential(newCred, audience: _info.audience, scopes: _scopes);

      if (!mounted) return;

      setState(() => _setCredential(newCred));

      dev.log('token renewed successfully', name: 'auth');
    } catch (e) {
      dev.log('token renewal error: $e', name: 'auth');
      if (mounted && _sessionGeneration == generation) {
        _handleRenewalFailure(cred, generation);
      }
    }
  }

  // Shows the renewal-error toast and schedules a post-expiry timer that
  // clears the (now-stale) credential so requestLogin() can recover.
  // [generation] must be the session generation captured before the HTTP
  // request so that a subsequent logout or successful renewal cancels the
  // clear timer.
  void _handleRenewalFailure(Credential cred, int generation) {
    final jwt = cred.response?['access_token'] as String?;
    final expiry = _jwtExpiry(jwt);

    _showRenewalError(expiry);

    final delay = expiry != null
        ? expiry.difference(DateTime.now().toUtc())
        : Duration.zero;

    // Schedule a clear at (or immediately after) token expiry so the widget
    // stops reporting the user as authenticated once the token is unusable.
    Timer(delay > Duration.zero ? delay : Duration.zero, () {
      if (!mounted || _sessionGeneration != generation) return;
      setState(_clearCredential);
    });
  }

  void _showRenewalError(DateTime? expiry) {
    final expiryMsg = expiry != null
        ? 'Current token expires at ${expiry.toLocal()}.'
        : 'Current token expiry is unknown.';

    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) {
        toastification.dismissAll(delayForAnimation: false);
        errorBox(
          context,
          'Token Renewal Failed',
          'Could not renew your session. $expiryMsg',
          duration: const Duration(seconds: 10),
        );
      }
    });
    WidgetsBinding.instance.scheduleFrame();
  }

  UserInfo? _tryExtractUserInfo(Credential cred) {
    try {
      return cred.idToken.claims;
    } catch (err) {
      dev.log('extracting userInfo from ID token failed: $err', name: 'auth');
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Login / logout
  // ---------------------------------------------------------------------------

  Future<void> requestLogin() async {
    if (_authenticated) return;

    final client = await _ensureClient();
    if (client == null || !mounted) return;

    // Check the localStorage cache before triggering a full login flow. A
    // cached, non-expired token means the user already authenticated in another
    // app on the same origin — no redirect needed.
    final cached = oid.loadCredential(
      client,
      audience: _info.audience,
      scopes: _scopes,
    );

    if (cached != null) {
      if (!mounted) return;
      setState(() => _setCredential(cached, showToast: true));
      return;
    }

    try {
      final creds =
          await (widget.authenticateForTest?.call(client) ??
              oid.authenticate(client, scopes: _scopes));
      if (!mounted) return;
      oid.saveCredential(creds, audience: _info.audience, scopes: _scopes);
      setState(() => _setCredential(creds, showToast: true));
    } catch (e) {
      dev.log('authentication failed: $e', name: 'auth');
    }
  }

  /// Requests the app's credentials be revoked.
  ///
  /// This method will clear out the local credentials, remove the cached
  /// token from localStorage, and request the server invalidate the token.
  Future<void> requestLogout() async {
    if (!_authenticated) return;

    final tmp = _credential!;

    oid.clearCredential(audience: _info.audience, scopes: _scopes);

    Future<void>.microtask(
      () async => await tmp.revoke().onError(
        (error, trace) => dev.log('revoke error: $error', name: 'auth'),
      ),
    );

    if (!mounted) return;
    setState(_clearCredential);
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) => _AuthCredentials(
    credentials: _credential,
    userInfo: _userInfo,
    roles: _roles,
    child: widget.child,
  );
}

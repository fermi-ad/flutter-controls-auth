/// Provides authentication services to Flutter apps.
///
/// Note: application authors don't directly use this package; these
/// widgets and types are used by our other packages.
library;

import 'dart:convert';
import 'dart:developer' as dev;

import 'package:flutter/material.dart';
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

  const AuthService({required this.authInfo, required this.child, super.key});

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

  Credential? _credential;
  UserInfo? _userInfo;

  // Cached role set — recomputed only when _credential changes, not on every
  // build() call.
  Set<String> _roles = const {};

  // Lazily set on first successful Issuer.discover(); reused for all
  // subsequent login attempts.
  Client? _client;

  AuthInfo get _info => widget.authInfo;

  bool get _authenticated => _credential != null;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    _initialize();
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
        setState(() => _setCredential(redirectCred));
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
    // Schedule the toast after the current build frame completes.
    // Dismiss any queued toasts first so the error isn't buried.
    // scheduleFrame() is required on desktop: Flutter won't render a new frame
    // without user input when idle, so the postFrameCallback would never fire.
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
  // Must be called inside setState(). Shows the "logged in" toast once.
  void _setCredential(Credential cred) {
    _credential = cred;
    _userInfo = _tryExtractUserInfo(cred);
    _roles = _extractRolesFromJwt(
      cred.response?['access_token'] as String?,
      _info.clientId,
    );

    // Show the login toast after the frame that triggered this setState().
    // scheduleFrame() is required on desktop: Flutter won't render a new frame
    // without user input when idle, so the postFrameCallback would never fire.
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

  // Clears credential state together. Must be called inside setState().
  void _clearCredential() {
    _credential = null;
    _userInfo = null;
    _roles = const {};
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
      setState(() => _setCredential(cached));
      return;
    }

    try {
      final creds = await oid.authenticate(client, scopes: _scopes);
      if (!mounted) return;
      oid.saveCredential(creds, audience: _info.audience, scopes: _scopes);
      setState(() => _setCredential(creds));
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

/// Provides authentication services to Flutter apps.
///
/// Note: application authors don't directly use this package; these
/// widgets and types are used by our other packages.
library;

import 'dart:convert';
import 'dart:async';
import 'dart:developer' as dev;

import 'package:flutter/material.dart';
import 'package:openid_client/openid_client.dart';
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
/// The widget renders immediately. While the OpenID discovery request is in
/// flight it shows [loadingWidget] (defaults to a centered
/// [CircularProgressIndicator]). If discovery fails it shows [errorBuilder],
/// which receives the error and a retry callback.
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

  /// Shown while the OpenID Connect discovery document is being fetched.
  /// Defaults to a centered [CircularProgressIndicator].
  final Widget? loadingWidget;

  /// Called when discovery fails (e.g. Keycloak is unreachable). Receives the
  /// error and a [retry] callback. Defaults to a simple error card with a
  /// Retry button.
  final Widget Function(Object error, VoidCallback retry)? errorBuilder;

  const AuthService({
    required this.authInfo,
    required this.child,
    this.loadingWidget,
    this.errorBuilder,
    super.key,
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

  static Future<void> requestLogin(BuildContext context) async =>
      await context.findAncestorStateOfType<_AuthState>()?.requestLogin();

  static Future<void> requestLogout(BuildContext context) async =>
      await context.findAncestorStateOfType<_AuthState>()?.requestLogout();
}

// Tracks whether the OpenID discovery + client setup has completed.
enum _InitStatus { loading, ready, error }

class _AuthState extends State<AuthService> {
  // ---------------------------------------------------------------------------
  // Instance state — replaces the old module-level globals
  // ---------------------------------------------------------------------------

  static const List<String> _scopes = ['roles'];

  _InitStatus _initStatus = _InitStatus.loading;
  Object? _initError;

  Credential? _credential;
  UserInfo? _userInfo;

  // Cached role set — recomputed only when _credential changes, not on every
  // build() call.
  Set<String> _roles = const {};

  // Set once discovery succeeds; used by requestLogin / requestLogout.
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

  Future<void> _initialize() async {
    final ai = _info;
    final uri = Uri.parse('https://ad-auth.fnal.gov/realms/${ai.realm}/');
    const tmo = Duration(seconds: 2);

    try {
      final issuer = await Issuer.discover(uri).timeout(tmo);
      final client = Client(issuer, ai.clientId);

      // Check the localStorage cache before triggering a full login flow.
      final cached = oid.loadCredential(
        client,
        audience: ai.audience,
        scopes: _scopes,
      );

      if (cached != null) {
        if (!mounted) return;
        setState(() {
          _client = client;
          _setCredential(cached);
          _initStatus = _InitStatus.ready;
        });
        return;
      }

      // Check whether this page load is the post-login redirect carrying an
      // authorization code. If so, exchange it for tokens and persist them.
      final redirectCred = await oid.getRedirectResult(client, scopes: _scopes);

      if (!mounted) return;

      if (redirectCred != null) {
        oid.saveCredential(
          redirectCred,
          audience: ai.audience,
          scopes: _scopes,
        );
        setState(() {
          _client = client;
          _setCredential(redirectCred);
          _initStatus = _InitStatus.ready;
        });
      } else {
        setState(() {
          _client = client;
          _initStatus = _InitStatus.ready;
        });
      }
    } catch (e) {
      dev.log('OpenID discovery failed: $e', name: 'auth');
      if (!mounted) return;
      setState(() {
        _initError = e;
        _initStatus = _InitStatus.error;
      });
    }
  }

  // Sets _credential, _userInfo, and _roles together so they're always in sync.
  // Must be called inside setState().
  void _setCredential(Credential cred) {
    _credential = cred;
    _userInfo = _tryExtractUserInfo(cred);
    _roles = _extractRolesFromJwt(
      cred.response?['access_token'] as String?,
      _info.clientId,
    );
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
    if (_authenticated || _client == null) return;

    try {
      final creds = await oid.authenticate(_client!, scopes: _scopes);
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
  Widget build(BuildContext context) {
    return switch (_initStatus) {
      _InitStatus.loading => _buildLoading(context),
      _InitStatus.error => _buildError(context),
      _InitStatus.ready => _buildReady(context),
    };
  }

  Widget _buildLoading(BuildContext context) =>
      widget.loadingWidget ??
      const Center(child: CircularProgressIndicator.adaptive());

  void _retry() {
    setState(() => _initStatus = _InitStatus.loading);
    _initialize();
  }

  Widget _buildError(BuildContext context) {
    if (widget.errorBuilder != null) {
      return widget.errorBuilder!(_initError!, _retry);
    }

    return Center(
      child: Card(
        margin: const EdgeInsets.all(24),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.cloud_off, size: 48, color: Colors.red),
              const SizedBox(height: 16),
              Text(
                'Authentication service unavailable',
                style: Theme.of(context).textTheme.titleMedium,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 8),
              Text(
                '$_initError',
                style: Theme.of(context).textTheme.bodySmall,
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                onPressed: _retry,
                icon: const Icon(Icons.refresh),
                label: const Text('Retry'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildReady(BuildContext context) {
    final theme = Theme.of(context);

    if (_userInfo != null) {
      Future.microtask(() {
        if (context.mounted) {
          toastification.show(
            context: context,
            type: .info,
            style: .minimal,
            title: Text(
              'Notice',
              style: theme.textTheme.titleMedium?.copyWith(color: Colors.black),
            ),
            description: Text(
              style: theme.textTheme.bodyMedium?.copyWith(
                color: Colors.black,
                fontWeight: .bold,
              ),
              'You are logged in as ${_userInfo!.name ?? "UNKNOWN"}.',
            ),
            alignment: .topRight,
            autoCloseDuration: const Duration(seconds: 4),
            showProgressBar: false,
            closeButton: const ToastCloseButton(showType: .always),
            closeOnClick: true,
            dragToClose: true,
          );
        }
      });
    }

    return _AuthCredentials(
      credentials: _credential,
      userInfo: _userInfo,
      roles: _roles,
      child: widget.child,
    );
  }
}

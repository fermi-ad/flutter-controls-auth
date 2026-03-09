/// Provides authentication services to Flutter apps.
///
/// Note: application authors don't directly use this package; these
/// widgets and types are used by our other packages.
library;

import 'dart:convert';
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:openid_client/openid_client.dart';
import 'src/openid_browser.dart'
    if (dart.library.io) 'src/openid_io.dart'
    as oid;

import 'dart:developer' as dev;

export 'package:openid_client/openid_client.dart' show Credential, UserInfo;

/// Defines a set of of scopes (or "roles").
typedef ScopeList = List<String>;

/// Defines the authorization information required by the application. This
/// is the one structure that applications will use.
class AuthInfo {
  final String realm;
  final String clientId;
  final List<String> scopes;

  const AuthInfo({
    this.realm = "acnetconsole",
    this.clientId = "flutter-client",
    this.scopes = const [],
  });
}

// These are global resources for the module. Applications cannot have more
// than one set of credentials.

Credential? _credentials;
Future<Credential?> Function() _authenticate = () async => null;
bool _authRequired = false;
String? _clientId;

Future<void> initAuth(AuthInfo ai) async {
  final uri = Uri.parse('https://ad-auth.fnal.gov/realms/${ai.realm}/');
  const Duration tmo = Duration(seconds: 2);

  _authRequired = true;
  _clientId = ai.clientId;

  final issuer = await Issuer.discover(uri).timeout(tmo);
  final Client client = Client(issuer, ai.clientId);

  _authenticate = () async {
    if (_credentials == null) {
      try {
        return oid.authenticate(client, scopes: ai.scopes).timeout(tmo);
      } on TimeoutException {
        dev.log('timeout communicating with KeyCloak', name: "auth");
        return null;
      }
    }
    return _credentials;
  };

  _credentials = await oid.getRedirectResult(client, scopes: ai.scopes);
}

String _base64UrlDecode(String base64Url) {
  String normalized = base64Url
      .replaceAll('-', '+') // Convert URL-safe characters back
      .replaceAll('_', '/');

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

Set<String> extractRolesFromJwt(String? jwt) {
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

      if (_clientId != null) {
        if (dec case {
          'resource_access': final Map<String, dynamic> resourceAccess,
        }) {
          if (resourceAccess[_clientId] case {'roles': final List rolesList}) {
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
  final Set<String>? _roles;

  _AuthCredentials({this.userInfo, required super.child})
    : credentials = _credentials,
      _roles = extractRolesFromJwt(
        _credentials?.idToken.toCompactSerialization(),
      );

  @override
  bool updateShouldNotify(covariant _AuthCredentials oldWidget) =>
      oldWidget.credentials != credentials || oldWidget.userInfo != userInfo;
}

/// Provides authentication services.
///
/// This widget should be placed near the Scaffold of an application to minimize
/// updates. Each update may trigger a new sign-on session. When this widget is
/// created, the application isn't automatically authenticated. To initiate
/// authentication, the [requestAuthentication] method should be called. This
/// allows an application to run with limited features when not authenticated.

class AuthService extends StatefulWidget {
  final Widget child;

  const AuthService({required this.child, super.key});

  @override
  State<AuthService> createState() => _AuthState();

  static bool get authRequired => _authRequired;

  static Credential? getCreds(BuildContext context) => context
      .dependOnInheritedWidgetOfExactType<_AuthCredentials>()
      ?.credentials;

  static String? getJwt(BuildContext context) => context
      .dependOnInheritedWidgetOfExactType<_AuthCredentials>()
      ?.credentials
      ?.idToken
      .toCompactSerialization();

  static bool inRole(BuildContext context, String name) =>
      context
          .dependOnInheritedWidgetOfExactType<_AuthCredentials>()
          ?._roles
          ?.contains(name) ??
      false;

  static UserInfo? getUserInfo(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<_AuthCredentials>()?.userInfo;

  static Future<void> requestLogin(BuildContext context) async =>
      await context.findAncestorStateOfType<_AuthState>()?.requestLogin();

  static Future<void> requestLogout(BuildContext context) async =>
      await context.findAncestorStateOfType<_AuthState>()?.requestLogout();
}

class _AuthState extends State<AuthService> {
  UserInfo? userInfo;

  bool get authenticated => _credentials != null;

  // Set-up a background process to retrieve the user's information.

  Future<void> getUserInfo() async {
    _credentials
        ?.getUserInfo()
        .then((value) => setState(() => userInfo = value))
        .catchError((err) => dev.log("userInfo returned $err"));
  }

  @override
  void initState() {
    super.initState();

    // If the credentials aren't `null`, then we can retrieve the user
    // information. Start a background task to access the user info.

    if (authenticated) {
      Future<void>.microtask(getUserInfo);
    }
  }

  Future<void> requestLogin() async {
    if (!authenticated) {
      final creds = await _authenticate();

      // If we successfully get credentials, try to get the user's
      // information.

      if (creds != null) {
        final user = await creds.getUserInfo();

        setState(() {
          _credentials = creds;
          userInfo = user;
        });
      }
    }
  }

  /// Requests the app's credentials be revoked.
  ///
  /// This method will clear out the local credentials and request the server
  /// invalid the authentication token.

  Future<void> requestLogout() async {
    if (authenticated) {
      final Credential tmp = _credentials!;

      Future<void>.microtask(
        () async => await tmp.revoke().onError(
          (error, trace) => dev.log("revoke error: $error"),
        ),
      );
      setState(() {
        _credentials = null;
        userInfo = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) =>
      _AuthCredentials(userInfo: userInfo, child: widget.child);
}

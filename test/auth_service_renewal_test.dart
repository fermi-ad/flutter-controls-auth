// Tests for the three auth-state defects identified in the code review:
//
//  P1-A  Logout during an in-flight token renewal must not restore credentials.
//  P1-B  A failed renewal must clear the credential once the token expires so
//        that requestLogin() can recover.
//  P2    A successful renewal must preserve expires_in so that the browser
//        credential cache can enforce expiry correctly.

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_controls_auth/flutter_controls_auth.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:openid_client/openid_client.dart';
import 'package:toastification/toastification.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a minimal [Issuer] + [Client] without any network calls.
Client _stubClient({
  String tokenEndpointUrl = 'https://auth.example.com/token',
  String clientId = 'test-client',
}) {
  final issuer = Issuer(
    OpenIdProviderMetadata.fromJson({
      'issuer': 'https://auth.example.com',
      'token_endpoint': tokenEndpointUrl,
      'authorization_endpoint': 'https://auth.example.com/auth',
      'jwks_uri': 'https://auth.example.com/.well-known/jwks.json',
      'response_types_supported': ['code'],
      'subject_types_supported': ['public'],
      'id_token_signing_alg_values_supported': ['RS256'],
    }),
  );
  return Client(issuer, clientId);
}

/// Encodes a minimal JWT with the given [expEpochSeconds] in the payload.
/// The signature is fake -- we only need the structure for _jwtExpiry().
String _makeJwt({required int expEpochSeconds}) {
  String b64(Map<String, dynamic> m) =>
      base64Url.encode(utf8.encode(jsonEncode(m))).replaceAll('=', '');

  final header = b64({'alg': 'RS256', 'typ': 'JWT'});
  final payload = b64({'sub': 'user1', 'exp': expEpochSeconds});
  return '$header.$payload.fakesig';
}

/// Returns a [Credential] whose access token expires [expiresIn] from now.
Credential _credWithExpiry(Client client, Duration expiresIn) {
  final expEpoch =
      DateTime.now().toUtc().add(expiresIn).millisecondsSinceEpoch ~/ 1000;
  return client.createCredential(
    accessToken: _makeJwt(expEpochSeconds: expEpoch),
    refreshToken: 'refresh-token-abc',
    tokenType: 'Bearer',
  );
}

/// Wraps [child] in the minimal widget tree required by [AuthService].
Widget _wrap(Widget child) =>
    MaterialApp(home: ToastificationWrapper(child: child));

// How far before expiry the renewal timer fires (must match production code).
const _renewalLeadTime = Duration(minutes: 2);

void main() {
  // ---------------------------------------------------------------------------
  // P1-A: Logout/renewal race
  // ---------------------------------------------------------------------------

  group('P1-A: logout during in-flight renewal', () {
    testWidgets(
      'credential stays null after logout even when renewal response arrives',
      (tester) async {
        // A Completer lets us hold the HTTP response until we choose to release
        // it, simulating a slow network call.
        final responseCompleter = Future<http.Response>.value(
          http.Response('', 200),
        );
        // We need a controllable future, so use a real Completer.
        final ctrl = Completer<http.Response>();
        final mockHttp = MockClient((_) => ctrl.future);
        final client = _stubClient();

        // Token expires in renewalLeadTime + 10 s, so the renewal timer fires
        // in 10 s (lead time before expiry).
        final cred = _credWithExpiry(
          client,
          _renewalLeadTime + const Duration(seconds: 10),
        );

        late BuildContext capturedCtx;

        await tester.pumpWidget(
          _wrap(
            AuthService(
              authInfo: const AuthInfo(clientId: 'test-client'),
              oidClient: client,
              httpClient: mockHttp,
              child: Builder(
                builder: (ctx) {
                  capturedCtx = ctx;
                  return const SizedBox.shrink();
                },
              ),
            ),
          ),
        );

        // Manually seed the credential (simulates a successful prior login).
        // ignore: invalid_use_of_protected_member
        final state =
            tester.state<State<StatefulWidget>>(find.byType(AuthService))
                as dynamic;
        state.setState(() => state.setCredentialForTest(cred));
        await tester.pump();

        // Advance time so the renewal timer fires (10 s into the future).
        await tester.pump(const Duration(seconds: 11));

        // The HTTP request is now in-flight (ctrl not yet resolved).
        // Log out while the request is pending.
        await AuthService.requestLogout(capturedCtx);
        await tester.pump();

        // Credential must be null immediately after logout.
        expect(AuthService.getJwt(capturedCtx), isNull);

        // Now resolve the HTTP response with a valid new token.
        final newExpEpoch =
            DateTime.now()
                .toUtc()
                .add(const Duration(hours: 1))
                .millisecondsSinceEpoch ~/
            1000;
        ctrl.complete(
          http.Response(
            jsonEncode({
              'access_token': _makeJwt(expEpochSeconds: newExpEpoch),
              'token_type': 'Bearer',
              'refresh_token': 'new-refresh',
              'expires_in': 3600,
            }),
            200,
            headers: {'content-type': 'application/json'},
          ),
        );

        // Let all microtasks and frames settle.
        await tester.pumpAndSettle();

        // Credential must still be null -- the renewal must not have restored it.
        expect(
          AuthService.getJwt(capturedCtx),
          isNull,
          reason: 'Renewal response after logout must not restore credentials',
        );

        // Suppress unused variable warning.
        expect(responseCompleter, isNotNull);
      },
    );
  });

  // ---------------------------------------------------------------------------
  // P1-B: Recovery after renewal failure
  // ---------------------------------------------------------------------------

  group('P1-B: recovery after renewal failure', () {
    testWidgets(
      'credential is cleared after token expiry following a failed renewal',
      (tester) async {
        final mockHttp = MockClient(
          (_) async => http.Response('Internal Server Error', 500),
        );
        final client = _stubClient();

        // Token expires in renewalLeadTime + 30 s.
        const tokenLifetime = Duration(seconds: 30);
        final cred = _credWithExpiry(client, _renewalLeadTime + tokenLifetime);

        late BuildContext capturedCtx;

        await tester.pumpWidget(
          _wrap(
            AuthService(
              authInfo: const AuthInfo(clientId: 'test-client'),
              oidClient: client,
              httpClient: mockHttp,
              child: Builder(
                builder: (ctx) {
                  capturedCtx = ctx;
                  return const SizedBox.shrink();
                },
              ),
            ),
          ),
        );

        // ignore: invalid_use_of_protected_member
        final state =
            tester.state<State<StatefulWidget>>(find.byType(AuthService))
                as dynamic;
        state.setState(() => state.setCredentialForTest(cred));
        await tester.pump();

        // Advance time to trigger the renewal timer.
        await tester.pump(const Duration(seconds: 31));
        await tester.pumpAndSettle();

        // Renewal failed (500) -- credential should still be set (token not yet
        // expired from the widget's perspective).
        expect(
          AuthService.getJwt(capturedCtx),
          isNotNull,
          reason:
              'Credential should remain set immediately after failed renewal',
        );

        // Advance time past the token's actual expiry.
        await tester.pump(
          _renewalLeadTime + tokenLifetime + const Duration(seconds: 1),
        );
        await tester.pumpAndSettle();

        // Now the credential must be cleared.
        expect(
          AuthService.getJwt(capturedCtx),
          isNull,
          reason: 'Credential must be cleared once the token has expired',
        );
      },
    );

    testWidgets(
      'requestLogin can recover after credential is cleared post-failure',
      (tester) async {
        final mockHttp = MockClient(
          (_) async => http.Response('Internal Server Error', 500),
        );
        final client = _stubClient();

        const tokenLifetime = Duration(seconds: 30);
        final cred = _credWithExpiry(client, _renewalLeadTime + tokenLifetime);

        late BuildContext capturedCtx;

        await tester.pumpWidget(
          _wrap(
            AuthService(
              authInfo: const AuthInfo(clientId: 'test-client'),
              oidClient: client,
              httpClient: mockHttp,
              child: Builder(
                builder: (ctx) {
                  capturedCtx = ctx;
                  return const SizedBox.shrink();
                },
              ),
            ),
          ),
        );

        // ignore: invalid_use_of_protected_member
        final state =
            tester.state<State<StatefulWidget>>(find.byType(AuthService))
                as dynamic;
        state.setState(() => state.setCredentialForTest(cred));
        await tester.pump();

        // Trigger renewal failure.
        await tester.pump(const Duration(seconds: 31));
        await tester.pumpAndSettle();

        // Advance past expiry so the post-expiry clear fires.
        await tester.pump(
          _renewalLeadTime + tokenLifetime + const Duration(seconds: 1),
        );
        await tester.pumpAndSettle();

        // After the clear, getCreds() must return null so requestLogin() can
        // proceed (it short-circuits only when _authenticated == true).
        expect(
          AuthService.getCreds(capturedCtx),
          isNull,
          reason:
              'requestLogin() should be able to proceed after credential clear',
        );
      },
    );
  });

  // ---------------------------------------------------------------------------
  // P2: expires_in preserved in renewed credential
  // ---------------------------------------------------------------------------

  group('P2: expires_in preserved in renewed credential', () {
    test(
      'createCredential with expiresIn writes expires_in to response map',
      () {
        final client = _stubClient();
        const expiresIn = Duration(seconds: 3600);

        final cred = client.createCredential(
          accessToken: 'some.access.token',
          tokenType: 'Bearer',
          expiresIn: expiresIn,
        );

        expect(
          cred.response?['expires_in'],
          equals(3600),
          reason: 'expires_in must be present in the credential response map',
        );
      },
    );

    test('createCredential without expiresIn has no expires_in', () {
      final client = _stubClient();

      final cred = client.createCredential(
        accessToken: 'some.access.token',
        tokenType: 'Bearer',
      );

      expect(
        cred.response?['expires_in'],
        isNull,
        reason: 'Without expiresIn the field should be absent',
      );
    });

    testWidgets(
      'renewed credential response includes expires_in from token endpoint',
      (tester) async {
        const newExpiresIn = 7200;
        final newExpEpoch =
            DateTime.now()
                .toUtc()
                .add(const Duration(seconds: newExpiresIn))
                .millisecondsSinceEpoch ~/
            1000;

        final mockHttp = MockClient(
          (_) async => http.Response(
            jsonEncode({
              'access_token': _makeJwt(expEpochSeconds: newExpEpoch),
              'token_type': 'Bearer',
              'refresh_token': 'new-refresh',
              'expires_in': newExpiresIn,
            }),
            200,
            headers: {'content-type': 'application/json'},
          ),
        );

        final client = _stubClient();
        final cred = _credWithExpiry(
          client,
          _renewalLeadTime + const Duration(seconds: 10),
        );

        late BuildContext capturedCtx;

        await tester.pumpWidget(
          _wrap(
            AuthService(
              authInfo: const AuthInfo(clientId: 'test-client'),
              oidClient: client,
              httpClient: mockHttp,
              child: Builder(
                builder: (ctx) {
                  capturedCtx = ctx;
                  return const SizedBox.shrink();
                },
              ),
            ),
          ),
        );

        // ignore: invalid_use_of_protected_member
        final state =
            tester.state<State<StatefulWidget>>(find.byType(AuthService))
                as dynamic;
        state.setState(() => state.setCredentialForTest(cred));
        await tester.pump();

        // Trigger renewal.
        await tester.pump(const Duration(seconds: 11));
        await tester.pumpAndSettle();

        // After renewal the widget should have a new credential.
        final renewedCred = AuthService.getCreds(capturedCtx);
        expect(renewedCred, isNotNull);
        expect(
          renewedCred!.response?['expires_in'],
          equals(newExpiresIn),
          reason:
              'Renewed credential must carry expires_in from the token response',
        );
      },
    );
  }); // end P2 group
} // end main

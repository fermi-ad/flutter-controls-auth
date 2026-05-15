import 'dart:developer' as dev;
import 'dart:io';

import 'package:openid_client/openid_client.dart';
import 'package:url_launcher/url_launcher.dart';

import 'openid_common.dart';

/// The HTML page returned to the user's browser after a successful
/// authentication redirect. It displays a brief confirmation message and
/// attempts to close the browser tab automatically.
const _successHtml = '''
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authentication Complete</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                   Helvetica, Arial, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
      background: #f5f5f5;
      color: #333;
    }
    .card {
      text-align: center;
      padding: 2rem 3rem;
      background: white;
      border-radius: 12px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    h1 { font-size: 1.4rem; margin-bottom: 0.5rem; }
    p  { color: #666; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authentication Successful</h1>
    <p>You can close this window and return to the app.</p>
  </div>
  <script>window.close();</script>
</body>
</html>
''';

/// Starts a temporary loopback HTTP server, opens the authorization URL in the
/// system browser, and waits for the authorization code callback.
///
/// This implements the Authorization Code + PKCE (S256) flow for non-web
/// platforms (iOS, Android, desktop). A loopback redirect URI is used so the
/// authorization server delivers the code back to the app via the local server.
///
/// The [port] parameter controls which port the loopback server binds to.
/// Use `0` to let the OS assign an available ephemeral port (recommended).
Future<Credential> authenticate(
  Client client, {
  List<String> scopes = const [],
  int port = 0,
}) async {
  // Bind a one-shot HTTP server on the loopback interface. Using loopback
  // (127.0.0.1) rather than anyIPv4 prevents other devices on the network
  // from reaching the callback endpoint.

  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, port);

  try {
    final boundPort = server.port;
    final redirectUri = Uri.parse('http://localhost:$boundPort/');

    // Build the PKCE flow with our own code verifier, matching the pattern
    // used in the browser implementation.

    final codeVerifier = generateCodeVerifier();
    final flow = Flow.authorizationCodeWithPKCE(
      client,
      scopes: mergeScopes(scopes),
      codeVerifier: codeVerifier,
    )..redirectUri = redirectUri;

    // Launch the authorization URL in the platform browser / in-app browser.

    final authUri = flow.authenticationUri;

    dev.log('opening auth URI: $authUri', name: 'auth');

    if (!await launchUrl(authUri, mode: LaunchMode.externalApplication)) {
      throw Exception('Could not launch authorization URL');
    }

    // Wait for the authorization server to redirect back to our loopback
    // server with the authorization code.

    final params = await _waitForCallback(server, flow.state);

    // Exchange the authorization code for tokens.

    return await flow.callback(params);
  } finally {
    await server.close();
  }
}

/// Listens on [server] for the OAuth callback request carrying the expected
/// [state] value. Returns the query parameters from the redirect. The server
/// responds with a friendly HTML page and is left open for the caller to close.
Future<Map<String, String>> _waitForCallback(
  HttpServer server,
  String state,
) async {
  await for (final request in server) {
    // Only process GET requests to the root path.

    if (request.method != 'GET' || request.uri.path != '/') {
      request.response
        ..statusCode = HttpStatus.notFound
        ..write('Not found');
      await request.response.close();
      continue;
    }

    final params = request.requestedUri.queryParameters;

    // Ignore requests that don't carry our state parameter (e.g. favicon
    // requests from the browser).

    if (!params.containsKey('state')) {
      request.response
        ..statusCode = HttpStatus.badRequest
        ..write('Missing state parameter');
      await request.response.close();
      continue;
    }

    // Verify the state matches to prevent CSRF.

    if (params['state'] != state) {
      request.response
        ..statusCode = HttpStatus.forbidden
        ..write('State mismatch');
      await request.response.close();
      continue;
    }

    // Respond with a user-friendly page and return the parameters.

    request.response
      ..statusCode = HttpStatus.ok
      ..headers.contentType = ContentType.html
      ..write(_successHtml);
    await request.response.close();

    return params.cast<String, String>();
  }

  // The server was closed before we received a valid callback.
  throw Exception('Authentication callback server closed unexpectedly');
}

/// On non-web platforms there is no redirect-based result to recover; the
/// loopback server handles the callback synchronously during [authenticate].
Future<Credential?> getRedirectResult(
  Client client, {
  List<String> scopes = const [],
}) async => null;

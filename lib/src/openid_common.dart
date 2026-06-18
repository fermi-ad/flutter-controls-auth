import 'dart:math';

/// Generates a cryptographically random string suitable for use as a PKCE
/// code verifier (RFC 7636 §4.1). Uses [Random.secure] and the unreserved
/// character set [A-Z / a-z / 0-9 / "-" / "." / "_" / "~"].
String generateCodeVerifier([int length = 128]) {
  const charset =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  final rng = Random.secure();

  return List.generate(
    length,
    (_) => charset[rng.nextInt(charset.length)],
  ).join();
}

/// Merges the caller's scopes with the OpenID Connect scopes required to
/// receive an ID token containing user-info claims.
List<String> mergeScopes(List<String> scopes) =>
    {...scopes, 'openid', 'profile', 'email'}.toList();

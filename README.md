# flutter-controls-auth

Provides support for authentication via KeyCloak.

## Features

- Provides a widget that manages authorization details
  - Connects to KeyCloak to authenticate the user
  - Renews the JWT, in the background, before it expires
- Provides functions for applications to test if a user is authorized in
required roles.

## Getting started

The latest branch is `0.x`. To track the latest features, add this to your
`pubspec.yaml` file:

```yaml
dependencies:
  git:
    url: https://github.com/fermi-ad/flutter-controls-auth.git
    ref: 0.x
```

## Usage

Applications authors won't, typically, use this package because it is used
by our core framework. However, if one was developing a standalone, Dart
program, this package may come in handy.
/// Functions for displaying common toast notification message boxes.

library;

import 'package:flutter/material.dart';
import 'package:toastification/toastification.dart';

void _showBox(
  BuildContext context,
  ToastificationType type,
  String title,
  String content,
  Duration? duration,
) {
  final theme = Theme.of(context);
  final textTheme = theme.textTheme;

  toastification.show(
    context: context,
    type: type,
    style: .minimal,
    title: Text(
      title,
      style: textTheme.titleSmall!.copyWith(
        color: theme.colorScheme.onInverseSurface,
      ),
    ),
    description: Text(
      content,
      style: textTheme.bodyMedium!.copyWith(
        color: theme.colorScheme.onInverseSurface,
      ),
    ),
    autoCloseDuration: duration,
  );
}

/// Displays an error notification.
///
/// - [context] is the [BuildContext] used to display the notification.
/// - [title] is the bold heading of the notification.
/// - [content] is the descriptive body text of the notification.
/// - [duration] controls how long the notification is visible.
void errorBox(
  BuildContext context,
  String title,
  String content, {
  Duration? duration,
}) => _showBox(context, .error, title, content, duration);

/// Displays a warning notification.
///
/// - [context] is the [BuildContext] used to display the notification.
/// - [title] is the bold heading of the notification.
/// - [content] is the descriptive body text of the notification.
/// - [duration] controls how long the notification is visible.
void warningBox(
  BuildContext context,
  String title,
  String content, {
  Duration? duration,
}) => _showBox(context, .warning, title, content, duration);

/// Displays an informational notification.
///
/// - [context] is the [BuildContext] used to display the notification.
/// - [title] is the bold heading of the notification.
/// - [content] is the descriptive body text of the notification.
/// - [duration] controls how long the notification is visible.
void infoBox(
  BuildContext context,
  String title,
  String content, {
  Duration? duration,
}) => _showBox(context, .info, title, content, duration);

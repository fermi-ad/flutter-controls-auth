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
  final colors = Theme.of(context).colorScheme;

  toastification.show(
    context: context,
    type: type,
    style: .minimal,
    backgroundColor: colors.surface,
    foregroundColor: colors.onSurface,
    title: Text(title),
    description: Text(content),
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

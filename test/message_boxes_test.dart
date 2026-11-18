import 'package:flutter/material.dart';
import 'package:flutter_controls_auth/flutter_controls_auth.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  for (final brightness in Brightness.values) {
    testWidgets('infoBox uses the surface colors in ${brightness.name} mode', (
      tester,
    ) async {
      final colors = ColorScheme.fromSeed(
        seedColor: Colors.teal,
        brightness: brightness,
      );
      late BuildContext context;
      await tester.pumpWidget(
        MaterialApp(
          theme: ThemeData(colorScheme: colors),
          home: Builder(
            builder: (routeContext) {
              context = routeContext;
              return const SizedBox.shrink();
            },
          ),
        ),
      );

      infoBox(context, 'Notice', 'You are logged in.');
      await tester.pumpAndSettle();

      final title = find.text('Notice');
      final message = find.text('You are logged in.');
      final background = find.ancestor(
        of: title,
        matching: find.byWidgetPredicate(
          (widget) =>
              widget is DecoratedBox &&
              widget.decoration is BoxDecoration &&
              (widget.decoration as BoxDecoration).color?.toARGB32() ==
                  colors.surface.toARGB32(),
        ),
      );
      expect(background, findsOneWidget);

      for (final (text, expectedColor) in [
        (title, colors.onSurface),
        (message, colors.onSurface.withValues(alpha: .8)),
      ]) {
        final richText = find.descendant(
          of: text,
          matching: find.byType(RichText),
        );
        expect(
          tester.widget<RichText>(richText).text.style?.color,
          expectedColor,
        );
      }

      await tester.tap(find.byIcon(Icons.close));
      await tester.pumpAndSettle();
      expect(title, findsNothing);
    });
  }
}

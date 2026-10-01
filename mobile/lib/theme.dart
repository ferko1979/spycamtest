import 'package:flutter/material.dart';

/// Brand palette shared with the desktop agent (cyan → indigo → violet).
class Brand {
  static const bg0 = Color(0xFF0A0F1C);
  static const surface = Color(0xFF121B2E);
  static const surface2 = Color(0xFF0F1728);
  static const border = Color(0xFF223049);
  static const fg = Color(0xFFEEF2FB);
  static const muted = Color(0xFF9AA7C2);
  static const c1 = Color(0xFF22D3EE);
  static const c2 = Color(0xFF4F7BF7);
  static const c3 = Color(0xFF7C3AED);
  static const ok = Color(0xFF4ADE80);
  static const warn = Color(0xFFFBBF24);
  static const danger = Color(0xFFFB7185);

  static const gradient = LinearGradient(
    colors: [c1, c2, c3],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );
}

ThemeData buildTheme() {
  final base = ThemeData.dark(useMaterial3: true);
  return base.copyWith(
    scaffoldBackgroundColor: Brand.bg0,
    colorScheme: base.colorScheme.copyWith(
      primary: Brand.c2,
      secondary: Brand.c1,
      surface: Brand.surface,
    ),
    cardTheme: CardTheme(
      color: Brand.surface,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: Brand.border),
      ),
    ),
    textTheme: base.textTheme.apply(bodyColor: Brand.fg, displayColor: Brand.fg),
  );
}

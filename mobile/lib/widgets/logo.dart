import 'dart:math' as math;
import 'package:flutter/material.dart';
import '../theme.dart';

/// SpyCamLogo paints the brand mark (radar sweep + camera lens) with
/// CustomPainter, so the app needs no SVG renderer dependency.
class SpyCamLogo extends StatelessWidget {
  final double size;
  const SpyCamLogo({super.key, this.size = 40});

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: size,
      height: size,
      child: CustomPaint(painter: _LogoPainter()),
    );
  }
}

class _LogoPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final r = RRect.fromRectAndRadius(
      Offset.zero & size,
      Radius.circular(size.width * 0.23),
    );
    final badge = Paint()
      ..shader = Brand.gradient.createShader(Offset.zero & size);
    canvas.drawRRect(r, badge);

    final c = Offset(size.width / 2, size.height / 2);
    final white = Paint()
      ..color = Colors.white
      ..style = PaintingStyle.stroke
      ..strokeWidth = size.width * 0.016
      ..strokeCap = StrokeCap.round;

    // Radar rings.
    canvas.drawCircle(c, size.width * 0.30, white..color = Colors.white24);
    canvas.drawCircle(c, size.width * 0.21, white..color = Colors.white38);

    // Sweep wedge.
    final sweep = Paint()..color = Colors.white.withOpacity(0.5);
    final path = Path()
      ..moveTo(c.dx, c.dy)
      ..lineTo(c.dx, size.height * 0.16)
      ..arcTo(
        Rect.fromCircle(center: c, radius: size.width * 0.34),
        -math.pi / 2,
        math.pi / 3,
        false,
      )
      ..close();
    canvas.drawPath(path, sweep);

    // Lens.
    canvas.drawCircle(c, size.width * 0.135, Paint()..color = Colors.white);
    canvas.drawCircle(c, size.width * 0.05, Paint()..color = Brand.bg0);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

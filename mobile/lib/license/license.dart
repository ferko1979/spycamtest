import 'dart:async';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;
import 'package:uuid/uuid.dart';

/// Feature identifiers — must match the Go server (internal/license).
class Features {
  static const scan = 'scan';
  static const activeScan = 'active_scan';
  static const cameras = 'cameras';
  static const activity = 'activity';
  static const alerts = 'alerts';
  static const signing = 'signing';
}

/// Claims is the server's signed verdict for one code.
class Claims {
  final String code;
  final bool valid;
  final String plan;
  final List<String> features;
  final DateTime issuedAt;
  final DateTime? expires;
  final String nonce;
  final String reason;

  Claims({
    required this.code,
    required this.valid,
    required this.plan,
    required this.features,
    required this.issuedAt,
    required this.expires,
    required this.nonce,
    required this.reason,
  });

  factory Claims.fromJson(Map<String, dynamic> j) {
    DateTime? exp;
    final e = j['expires'] as String?;
    if (e != null && !e.startsWith('0001-01-01')) {
      exp = DateTime.tryParse(e);
    }
    return Claims(
      code: j['code'] as String? ?? '',
      valid: j['valid'] as bool? ?? false,
      plan: j['plan'] as String? ?? '',
      features: (j['features'] as List?)?.cast<String>() ?? const [],
      issuedAt: DateTime.tryParse(j['issued_at'] as String? ?? '') ?? DateTime(1970),
      expires: exp,
      nonce: j['nonce'] as String? ?? '',
      reason: j['reason'] as String? ?? '',
    );
  }
}

/// LicenseClient verifies one code against the server, checking the Ed25519
/// signature, the echoed nonce, response freshness, and (if set) a pinned key.
class LicenseClient {
  final String serverUrl;
  final String deviceId;
  final String? pinnedPublicKey; // base64
  final Duration maxSkew;

  LicenseClient({
    required this.serverUrl,
    required this.deviceId,
    this.pinnedPublicKey,
    this.maxSkew = const Duration(minutes: 10),
  });

  Future<Claims> verify(String code) async {
    final nonce = Uuid().v4();
    final body = jsonEncode({
      'code': code,
      'device_id': deviceId,
      'app_version': '1.0.0',
      'nonce': nonce,
    });
    final resp = await http
        .post(
          Uri.parse('${_trim(serverUrl)}/api/verify'),
          headers: {'Content-Type': 'application/json'},
          body: body,
        )
        .timeout(const Duration(seconds: 10));
    if (resp.statusCode != 200) {
      throw Exception('license server HTTP ${resp.statusCode}');
    }

    // Extract the exact signed claims bytes (balanced-brace slice) so
    // verification never depends on re-serialization.
    final rawClaims = _extractClaimsRaw(resp.body);
    final outer = jsonDecode(resp.body) as Map<String, dynamic>;
    final pub = outer['public_key'] as String? ?? '';
    final sig = outer['signature'] as String? ?? '';

    if (pinnedPublicKey != null && pinnedPublicKey!.isNotEmpty && pub != pinnedPublicKey) {
      throw Exception('license server public key mismatch');
    }
    if (!await _verifySig(pub, rawClaims, sig)) {
      throw Exception('invalid license signature');
    }

    final claims = Claims.fromJson(jsonDecode(rawClaims) as Map<String, dynamic>);
    if (claims.nonce != nonce) {
      throw Exception('nonce mismatch (possible replay)');
    }
    final age = DateTime.now().toUtc().difference(claims.issuedAt.toUtc()).abs();
    if (age > maxSkew) {
      throw Exception('stale license response');
    }
    return claims;
  }

  static Future<bool> _verifySig(String pubB64, String payload, String sigB64) async {
    try {
      final algo = Ed25519();
      final pub = SimplePublicKey(base64.decode(pubB64), type: KeyPairType.ed25519);
      final sig = Signature(base64.decode(sigB64), publicKey: pub);
      return algo.verify(utf8.encode(payload), signature: sig);
    } catch (_) {
      return false;
    }
  }

  /// Returns the raw JSON substring for the "claims" object, matching braces.
  static String _extractClaimsRaw(String body) {
    final key = '"claims":';
    final i = body.indexOf(key);
    if (i < 0) throw Exception('no claims in response');
    var j = i + key.length;
    while (j < body.length && body[j] != '{') {
      j++;
    }
    if (j >= body.length) throw Exception('malformed claims');
    var depth = 0;
    var inStr = false;
    var esc = false;
    for (var k = j; k < body.length; k++) {
      final ch = body[k];
      if (inStr) {
        if (esc) {
          esc = false;
        } else if (ch == '\\') {
          esc = true;
        } else if (ch == '"') {
          inStr = false;
        }
        continue;
      }
      if (ch == '"') {
        inStr = true;
      } else if (ch == '{') {
        depth++;
      } else if (ch == '}') {
        depth--;
        if (depth == 0) return body.substring(j, k + 1);
      }
    }
    throw Exception('unbalanced claims');
  }

  static String _trim(String s) => s.endsWith('/') ? s.substring(0, s.length - 1) : s;
}

/// Entitlement is the aggregate across all configured codes.
class Entitlement {
  final Set<String> features;
  final List<Claims> valid;
  final DateTime? soonestExpiry;
  final bool inGrace;
  final bool degraded;
  final String? lastError;

  const Entitlement({
    required this.features,
    required this.valid,
    required this.soonestExpiry,
    required this.inGrace,
    required this.degraded,
    required this.lastError,
  });

  bool has(String f) => features.contains(f);

  List<String> get plans => valid.map((c) => c.plan).where((p) => p.isNotEmpty).toList();
}

/// LicenseManager unions features across codes, re-verifies every 30 minutes,
/// and keeps the last-known entitlement for a grace window when offline.
class LicenseManager extends ChangeNotifierLite {
  LicenseClient Function() clientFactory;
  List<String> codes;
  final Set<String> base;
  final Duration grace;

  Entitlement _ent;
  DateTime? _lastGood;
  Timer? _timer;

  LicenseManager({
    required this.clientFactory,
    required this.codes,
    this.base = const {Features.scan},
    this.grace = const Duration(hours: 24),
  }) : _ent = Entitlement(
          features: {Features.scan},
          valid: const [],
          soonestExpiry: null,
          inGrace: false,
          degraded: true,
          lastError: null,
        );

  Entitlement get entitlement => _ent;
  bool has(String f) => _ent.has(f);

  void start() {
    refresh();
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(minutes: 30), (_) => refresh());
  }

  void dispose() {
    _timer?.cancel();
  }

  Future<void> refresh() async {
    final union = <String>{...base};
    final valid = <Claims>[];
    DateTime? soonest;
    var anyValid = false;
    String? err;
    final client = clientFactory();

    for (final code in codes.where((c) => c.trim().isNotEmpty)) {
      try {
        final claims = await client.verify(code);
        if (claims.valid) {
          anyValid = true;
          valid.add(claims);
          union.addAll(claims.features);
          if (claims.expires != null &&
              (soonest == null || claims.expires!.isBefore(soonest!))) {
            soonest = claims.expires;
          }
        }
      } catch (e) {
        err = e.toString();
      }
    }

    final hadCodes = codes.any((c) => c.trim().isNotEmpty);
    if (anyValid || !hadCodes) {
      _lastGood = DateTime.now();
      _ent = Entitlement(
        features: union,
        valid: valid,
        soonestExpiry: soonest,
        inGrace: false,
        degraded: !anyValid,
        lastError: err,
      );
    } else {
      final withinGrace =
          _lastGood != null && DateTime.now().difference(_lastGood!) <= grace;
      if (withinGrace) {
        _ent = Entitlement(
          features: _ent.features,
          valid: _ent.valid,
          soonestExpiry: _ent.soonestExpiry,
          inGrace: true,
          degraded: false,
          lastError: err,
        );
      } else {
        _ent = Entitlement(
          features: {...base},
          valid: const [],
          soonestExpiry: null,
          inGrace: false,
          degraded: true,
          lastError: err,
        );
      }
    }
    notify();
  }
}

/// Minimal change notifier (avoids importing flutter in this logic file).
class ChangeNotifierLite {
  final List<void Function()> _listeners = [];
  void addListener(void Function() fn) => _listeners.add(fn);
  void removeListener(void Function() fn) => _listeners.remove(fn);
  void notify() {
    for (final l in List.of(_listeners)) {
      l();
    }
  }
}

/// Overrides for the provider-routing schedule and clock margins — for TEST
/// HARNESSES only (the live browser self-test runs 2 s rounds instead of 15 s).
/// The network-wide defaults live in `protocol-core` (`delegation.RoundSchedule`,
/// `engine.Delegation`, `delegation.DeviceClock`); a normal build passes no
/// tuning and uses them, so they are never duplicated here. Every device and
/// the provider must use the same schedule, or devices never hand a live set in.
class RoutingTuning {
  const RoutingTuning({
    required this.intervalMillis,
    required this.cutoffMillis,
    required this.refreshEveryRounds,
    required this.horizonRounds,
    required this.openGraceMillis,
    required this.closeGraceMillis,
    required this.submitMarginMillis,
    this.epochMillis = 0,
  });

  final int epochMillis;
  final int intervalMillis;
  final int cutoffMillis;
  final int refreshEveryRounds;
  final int horizonRounds;
  final int openGraceMillis;
  final int closeGraceMillis;
  final int submitMarginMillis;
}

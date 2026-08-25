package sidecar

/** Transport-free microbenchmark of the oblivious scan — the loop the load tests showed dominates
  * everything else at realistic capacities.
  *
  * ==Why hand-rolled rather than criterion / JMH==
  *
  * The point is a THREE-WAY comparison (Rust, JVM, Scala Native), and criterion and JMH do not
  * exist on all three. Running a different harness per language would fold each harness's own
  * overhead and timing methodology into the numbers being compared. So all three implementations
  * use the identical shape — a fixed token pool built outside the timed region, a warmup phase, a
  * timed phase over a fixed op count, and a checksum consumed at the end — and the per-op cost is
  * large enough (hundreds of ns to hundreds of µs) that loop overhead is irrelevant.
  *
  * The checksum is not decoration: without consuming the result, the JIT is entitled to delete the
  * whole scan, and a benchmark reporting 0 ns/op would look like a spectacular win.
  *
  * One "round" is a `write` followed by a `readSealed` of the same token — matching the load test,
  * and keeping occupancy at one live entry so the scan never degenerates into a full-store walk.
  */
object ScanBench:

  import ObliviousStore.{FrameLen, TokenLen}

  /** Distinct tokens, cycled through, all built BEFORE timing starts: token derivation is not part
    * of what is being measured and would otherwise differ between languages. */
  private val PoolSize = 64

  private def tokenPool(): Array[Array[Byte]] =
    Array.tabulate(PoolSize) { i =>
      val t = new Array[Byte](TokenLen)
      var x = (i + 1).toLong * 0x9e3779b97f4a7c15L
      var j = 0
      while j < TokenLen do
        x ^= x >>> 30
        x *= 0xbf58476d1ce4e5b9L
        x ^= x >>> 27
        t(j) = (x >>> 24).toByte
        j += 1
      t
    }

  private def frame(): Array[Byte] = Array.tabulate(FrameLen)(i => (i & 0xff).toByte)

  /** The two scans of one round, so a variant can be swapped in without touching anything else
    * about the measurement — the safe and unsafe runs share this timing code exactly. */
  trait RoundOps:
    def write(store: ObliviousStore, token: Array[Byte], frame: Array[Byte]): Boolean
    def read(store: ObliviousStore, token: Array[Byte], out: Array[Byte]): Boolean

  object SafeOps extends RoundOps:
    def write(s: ObliviousStore, t: Array[Byte], f: Array[Byte]): Boolean = s.write(t, f)
    def read(s: ObliviousStore, t: Array[Byte], o: Array[Byte]): Boolean = s.readSealed(t, o)

  /** Returns (nanosPerRound, checksum). */
  private def measure(capacity: Int, ops: Int, warmup: Int, ops0: RoundOps): (Double, Long) =
    val store = new ObliviousStore(capacity)
    val pool = tokenPool()
    val f = frame()
    val out = new Array[Byte](FrameLen)
    var checksum = 0L

    def rounds(n: Int): Unit =
      var i = 0
      while i < n do
        val t = pool(i % PoolSize)
        ops0.write(store, t, f)
        if ops0.read(store, t, out) then checksum += 1
        checksum += out(i % FrameLen) & 0xffL
        i += 1

    rounds(warmup)
    val t0 = System.nanoTime()
    rounds(ops)
    val elapsed = System.nanoTime() - t0
    (elapsed.toDouble / ops, checksum)

  private def report(label: String, capacity: Int, nsPerRound: Double, checksum: Long): Unit =
    // Fixed-field output so the three languages' results can be diffed directly.
    println(
      f"$label%-24s capacity=$capacity%-6d ${nsPerRound / 1000.0}%10.2f us/round  checksum=$checksum"
    )

  def main(capacities: Seq[Int], ops: Int, warmup: Int): Unit =
    println(s"# oblivious scan microbenchmark — ops=$ops warmup=$warmup pool=$PoolSize")
    for c <- capacities do
      val (ns, ck) = measure(c, ops, warmup, SafeOps)
      report("scala-safe", c, ns, ck)
    // The bounds-check experiment: identical algorithm over the identical arrays of the identical
    // store, differing ONLY in that the accesses go through raw pointers. Available on Scala
    // Native; there is no equivalent on the JVM, where the JIT is what removes the checks.
    if UnsafeScan.available then
      for c <- capacities do
        val (ns, ck) = measure(c, ops, warmup, UnsafeScan.Ops)
        report("scala-unsafe-ptr", c, ns, ck)
    else
      println("scala-unsafe-ptr           n/a on this platform (JVM: the JIT elides checks itself)")

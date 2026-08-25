package sidecar

/** JVM side of the bounds-check experiment: there is nothing to do here.
  *
  * On the JVM, bounds-check elimination is the JIT's job and is not something source code can opt
  * out of — which is itself the comparison. The Scala Native counterpart of this file scans the
  * same arrays through raw pointers to measure what those checks cost when nothing removes them. */
object UnsafeScan:
  val available: Boolean = false

  def Ops: ScanBench.RoundOps =
    throw new UnsupportedOperationException("raw-pointer scan is Scala Native only")

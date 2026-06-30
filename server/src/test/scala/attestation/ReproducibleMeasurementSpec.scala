package attestation

import org.scalatest.funsuite.AnyFunSuite

/** T057 end-to-end: the `MRENCLAVE` produced by the reproducible Docker + Gramine build
  * (`deploy/enclave/Dockerfile` — a static-musl `obsd`, signed twice with an identical measurement)
  * flows through the transparency [[ReferenceLog]] and is trusted ONLY via an inclusion proof to a
  * pinned root. The value below is a **manually-pinned snapshot** of the reproducible build's output
  * (re-pinned by running `deploy/enclave/reproduce.sh` and updating `measurement.txt` + this constant —
  * the CI build is not run here); a guard test asserts the two copies stay in lockstep. The point is to
  * exercise the publish → prove → pinned-root trust chain with the REAL produced value, not a synthetic
  * one.
  *
  * `MRENCLAVE` is the SHA-256 measurement of the enclave code/data pages; it is independent of the
  * signing key and is verified reproducible by the build itself (two independent signings must agree).
  * `MRSIGNER` identifies WHO signed — in production the PCK-endorsed platform signer (hardware-gated);
  * here it is a fixed, documented dev stand-in (the dev build signs with a throwaway key, so its signer
  * value is not itself reproduced). The log → trust mechanism carries the whole pair regardless. */
class ReproducibleMeasurementSpec extends AnyFunSuite:

  private def hex(s: String): Vector[Byte] =
    s.grouped(2).map(h => Integer.parseInt(h, 16).toByte).toVector
  private def fill(b: Int): Vector[Byte] = Vector.fill(32)(b.toByte)

  // The reproducible enclave measurement from `deploy/enclave/Dockerfile` (musl obsd → Gramine sign).
  private val mrEnclave = hex("45296a439f2db45b48eec1f4611699f740be707ef5b979f52be7b1a177c6e64f")
  // Documented DEV signer stand-in (production pins the PCK-endorsed signer's MRSIGNER).
  private val mrSigner = hex("00" * 31 + "01")
  private val measurement = Measurement(mrEnclave, mrSigner)

  test("the reproducible MRENCLAVE is a 32-byte SHA-256 measurement"):
    assert(mrEnclave.size == 32, "MRENCLAVE must be a 32-byte measurement")

  test("the pinned MRENCLAVE matches deploy/enclave/measurement.txt (no silent divergence)"):
    // Single source of truth: the `mrEnclave` constant above and the published measurement file must
    // agree, so a re-pin after a rebuild updates both. Locate the file by walking up from the test dir.
    val pinned = mrEnclave.map(b => f"${b & 0xff}%02x").mkString // rendered from the one constant
    var dir = java.nio.file.Paths.get("").toAbsolutePath
    var found = Option.empty[java.nio.file.Path]
    while found.isEmpty && dir != null do
      val cand = dir.resolve("deploy/enclave/measurement.txt")
      if java.nio.file.Files.exists(cand) then found = Some(cand)
      dir = dir.getParent
    val path =
      found.getOrElse(fail("deploy/enclave/measurement.txt not found from the test working dir"))
    val txt = new String(java.nio.file.Files.readAllBytes(path), "UTF-8")
    val line =
      txt.linesIterator.find(_.trim.startsWith("MRENCLAVE")).getOrElse(fail("no MRENCLAVE line"))
    val recorded = line.split("=", 2)(1).trim
    assert(
      recorded == pinned,
      s"measurement.txt MRENCLAVE ($recorded) must match the pinned constant ($pinned)"
    )

  test(
    "published to the ReferenceLog, the measurement is trusted via inclusion proof to the pinned root"
  ):
    val log = new ReferenceLog
    log.append(Measurement(fill(0x10), fill(0x20))) // an unrelated prior entry
    log.append(measurement)
    log.append(Measurement(fill(0x30), fill(0x40))) // and a later one
    val pinnedRoot = log.root // clients pin this published checkpoint root out of band
    val ref =
      log.reference(measurement).getOrElse(fail("the logged measurement must have a reference"))
    assert(
      ReferenceLogTrust.trusts(ref, log.size, pinnedRoot),
      "logged ⇒ inclusion-proven ⇒ trusted"
    )
    // The appraisal reference set the verifier consults includes exactly this measurement.
    assert(log.referenceValues.allowed.contains(measurement))

  test("an enclave whose MRENCLAVE was never logged is NOT trusted (only logged code may run)"):
    val log = new ReferenceLog
    log.append(measurement)
    val rogue = Measurement(fill(0xde), mrSigner) // a different, unlogged build
    assert(log.reference(rogue).isEmpty, "unlogged measurement ⇒ no reference ⇒ untrusted")

  test("the logged measurement under a DIFFERENT pinned root is rejected (no forged trust)"):
    val log = new ReferenceLog
    log.append(measurement)
    val ref = log.reference(measurement).get
    val wrongRoot = { val c = log.root.clone(); c(0) = (c(0) ^ 0x01).toByte; c }
    assert(!ReferenceLogTrust.trusts(ref, log.size, wrongRoot), "wrong pinned root ⇒ untrusted")

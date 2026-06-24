package attestation

/** The append-only **reference-measurement log** that backs attestation appraisal (Constitution IX/X,
  * T057). A measurement is in the trusted set ONLY because it was published to this transparency log;
  * a relying party accepts it ONLY with a valid [[TransparencyLog]] inclusion proof to a **pinned**
  * root. So "what code may run the enclave" is publicly auditable and the operator cannot quietly add
  * trust to un-logged code.
  *
  * This is the publish-and-prove half of T057, fully software-testable. The other half — producing a
  * measurement from a **reproducible enclave build** so the logged value is exactly what runs — is
  * toolchain/hardware-gated (`deploy/enclave/README.md`). */
object ReferenceLog:

  /** Canonical, deterministic log-entry bytes for a measurement: length-prefixed `mrEnclave ‖ mrSigner`
    * (so distinct measurements never collide on the same entry and the prover/verifier agree). */
  def encode(m: Measurement): Array[Byte] =
    def lp(b: Vector[Byte]): Array[Byte] =
      Array(((b.size >> 8) & 0xff).toByte, (b.size & 0xff).toByte) ++ b.toArray
    lp(m.mrEnclave) ++ lp(m.mrSigner)

  /** A reference value plus the proof that it is logged — what an auditor checks. */
  final case class LoggedReference(measurement: Measurement, index: Int, proof: Vector[Array[Byte]])

/** A mutable append-only log of reference measurements. Single source of truth for the trusted set. */
final class ReferenceLog:
  import ReferenceLog.*

  private var entries: Vector[Array[Byte]] = Vector.empty

  /** Append a measurement; returns the new log root (what gets pinned/published). */
  def append(m: Measurement): Array[Byte] =
    entries = entries :+ encode(m)
    root

  def size: Int = entries.size
  def root: Array[Byte] = TransparencyLog.root(entries)

  /** An inclusion-proof record for a logged measurement, or `None` if it was never logged. */
  def reference(m: Measurement): Option[LoggedReference] =
    val target = encode(m)
    entries.indexWhere(e => java.util.Arrays.equals(e, target)) match
      case -1 => None
      case i => Some(LoggedReference(m, i, TransparencyLog.inclusionProof(entries, i)))

  /** The trusted reference set the [[AttestationVerifier]] appraises against — derived ONLY from the
    * logged measurements, so the appraisal set is exactly the transparency-logged set. */
  def referenceValues: ReferenceValues =
    val ms = (0 until entries.size).map(i => decode(entries(i)))
    ReferenceValues(ms.map(_.mrEnclave).toSet, ms.map(_.mrSigner).toSet)

  private def decode(e: Array[Byte]): Measurement =
    val l1 = ((e(0) & 0xff) << 8) | (e(1) & 0xff)
    val mrEnclave = e.slice(2, 2 + l1).toVector
    val rest = e.drop(2 + l1)
    val l2 = ((rest(0) & 0xff) << 8) | (rest(1) & 0xff)
    Measurement(mrEnclave, rest.slice(2, 2 + l2).toVector)

object ReferenceLogTrust:
  /** A relying party trusts a measurement ONLY when its inclusion proof verifies against the root it
    * has pinned (out of band, e.g. from the published log checkpoint). No proof / wrong root ⇒ no trust
    * — exactly the gate that stops an operator adding un-logged code to the trusted set. */
  def trusts(ref: ReferenceLog.LoggedReference, treeSize: Int, pinnedRoot: Array[Byte]): Boolean =
    TransparencyLog.verifyInclusion(
      TransparencyLog.leafHash(ReferenceLog.encode(ref.measurement)),
      ref.index,
      treeSize,
      ref.proof,
      pinnedRoot
    )

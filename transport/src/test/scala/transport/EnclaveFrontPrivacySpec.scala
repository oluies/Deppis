package transport

import org.scalatest.funsuite.AnyFunSuite
import privacy.Privacy

/** The production label path (T058): the attestation-gated `attested` flag on the enclave fronts must
  * flow to `GrpcRoundTransport.privacyStatus` and yield the right label. These assert only the status
  * derivation — no RPC is made, so a null stub is fine (the stub is consulted only by write/read). */
class EnclaveFrontPrivacySpec extends AnyFunSuite:

  test("EnclaveObliviousStore.privacyStatus reflects its attested flag"):
    val attested = new EnclaveObliviousStore(null, attested = true)
    assert(attested.privacyStatus.metadataPrivate && attested.label == Privacy.PrivateLabel)
    val unattested = new EnclaveObliviousStore(null, attested = false)
    assert(!unattested.privacyStatus.metadataPrivate && unattested.label == Privacy.DevLabel)

  test("GrpcRoundTransport.privacyStatus forwards the store's attestation-gated status"):
    val privateT = new GrpcRoundTransport(
      new EnclaveObliviousStore(null, attested = true),
      new EnclaveNotificationClient(null, attested = true)
    )
    assert(privateT.privacyStatus.backend == Privacy.Backend.EnclaveTarget)
    assert(
      privateT.privacyStatus.metadataPrivate && privateT.privacyStatus.label == Privacy.PrivateLabel
    )

    val devT = new GrpcRoundTransport(
      new EnclaveObliviousStore(null, attested = false),
      new EnclaveNotificationClient(null, attested = false)
    )
    assert(!devT.privacyStatus.metadataPrivate && devT.privacyStatus.label == Privacy.DevLabel)

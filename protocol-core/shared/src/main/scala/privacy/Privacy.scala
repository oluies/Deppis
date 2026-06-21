package privacy

/** Build privacy status (T017, FR-016, Constitution IV — the labeling rule). A build provides
  * real metadata privacy ONLY when it runs a real backend whose attestation passed; every
  * other build (dev store, Groove single-shuffler stub, or an unattested real backend) is NOT
  * private and MUST surface the dev label in code, logs, and UI. */
object Privacy:
  val DevLabel: String = "DEV, NO METADATA PRIVACY"
  val PrivateLabel: String = "METADATA PRIVATE"

  enum Backend:
    case Dev, EnclaveTarget, GrooveStub, GrooveTarget

  final case class BuildPrivacyStatus(backend: Backend, attestationPassed: Boolean):
    def metadataPrivate: Boolean = backend match
      case Backend.EnclaveTarget => attestationPassed
      case Backend.GrooveTarget => attestationPassed
      case Backend.Dev | Backend.GrooveStub => false

    def label: String = if metadataPrivate then PrivateLabel else DevLabel

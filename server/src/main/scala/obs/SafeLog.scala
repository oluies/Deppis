package obs

/** Logging and error discipline for secret-dependent code (T018, Constitution II).
  *
  * Secret values MUST NOT appear in logs or error messages, and messages MUST NOT vary on secret
  * content — a message whose text, length, or branch depends on a secret is itself a side channel.
  * These helpers make the safe path the easy path: secrets collapse to a single constant marker,
  * and failures are described by a fixed, public reason rather than ad-hoc strings built from the
  * offending value.
  *
  * Usage: build user/operator-facing failures from [[FailureReason]], and pass any secret through
  * [[SafeLog.redact]] before it could reach a log line or exception message. */
object SafeLog:
  /** Constant redaction marker. Deliberately independent of the secret's value AND its length:
    * even revealing the length of a key, token, or plaintext can leak information. */
  val Redacted: String = "<redacted>"

  def redact(secret: Array[Byte]): String = Redacted
  def redact(secret: String): String      = Redacted

/** The closed set of public failure reasons secret-handling code may surface. Each maps to a
  * fixed message that carries no secret-dependent content. */
enum FailureReason:
  case AuthenticationFailed
  case MalformedInput
  case NotFound
  case LimitReached
  case Unauthorized
  case Unavailable

  def message: String = this match
    case FailureReason.AuthenticationFailed => "authentication failed"
    case FailureReason.MalformedInput       => "malformed input"
    case FailureReason.NotFound             => "not found"
    case FailureReason.LimitReached         => "limit reached"
    case FailureReason.Unauthorized         => "unauthorized"
    case FailureReason.Unavailable          => "temporarily unavailable"

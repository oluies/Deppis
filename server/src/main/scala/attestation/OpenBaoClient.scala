package attestation

import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.util.Base64
import scala.util.control.NonFatal

/** Minimal client to **OpenBao** (the Vault-compatible secret store) for the **attested key
  * release** (Constitution IX, research D11; see `design/attestation-key-provisioning.md`).
  *
  * After a passing, hardware-backed attestation, the enclave reads its sealed PONG/notify key from
  * OpenBao. This client + its response parsing are CI-tested against an in-process mock HTTP server.
  * The pieces that need a RUNNING OpenBao are OPS-gated and NOT in CI:
  *   - **Shamir unseal** (M-of-N operator shares, or HSM auto-unseal) to open the storage barrier;
  *   - the **attestation-gated auth method** that only issues a token to a verified enclave (so the
  *     `token` here is itself a product of attestation, not a static secret);
  *   - **Transit wrap** so the key is released wrapped to the enclave's attested public key and never
  *     exists in plaintext outside the enclave.
  *
  * Errors are fixed, non-secret strings (Constitution II); the client never logs the key. */
final class OpenBaoClient(
    baseUrl: String,
    token: String,
    http: HttpClient = HttpClient.newHttpClient()
):

  /** Read a KV-v2 secret and return `data.data.<field>`, base64-decoded. The OpenBao KV-v2 read
    * response is `{ "data": { "data": { <field>: "<base64>" }, "metadata": {...} } }`. */
  def readKey(path: String, field: String = "key"): Either[String, Array[Byte]] =
    request(s"$baseUrl/v1/$path").flatMap { body =>
      try
        val json = ujson.read(body)
        json.obj.get("data").flatMap(_.obj.get("data")).flatMap(_.obj.get(field)).map(_.str) match
          case Some(b64) =>
            try Right(Base64.getDecoder.decode(b64))
            catch case NonFatal(_) => Left("openbao: key field not valid base64")
          case None => Left("openbao: key field absent")
      catch case NonFatal(_) => Left("openbao: malformed response")
    }

  private def request(url: String): Either[String, String] =
    try
      val req = HttpRequest
        .newBuilder(URI.create(url))
        .header("X-Vault-Token", token)
        .GET()
        .build()
      val resp = http.send(req, HttpResponse.BodyHandlers.ofString())
      resp.statusCode() match
        case 200 => Right(resp.body())
        case 403 => Left("openbao: permission denied")     // fixed, non-secret (Constitution II)
        case 404 => Left("openbao: secret not found")
        case _   => Left("openbao: request failed")
    catch case NonFatal(_) => Left("openbao: request failed")

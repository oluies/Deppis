package transport.round

import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.{Extension, GeneralName, GeneralNames}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.security.{KeyPairGenerator, KeyStore, PrivateKey, SecureRandom}
import javax.net.ssl.KeyManagerFactory
import java.util.Date

/** A **dev-only** self-signed TLS certificate generator (T020).
  *
  * `TlsRoundServer` needs a cert to bind TLS 1.3. For development we mint a throwaway self-signed
  * Ed25519 cert (CN=localhost) here with Bouncy Castle — netty's built-in `SelfSignedCertificate`
  * relies on `sun.security.x509` internals that newer JDKs no longer expose. A self-signed cert has
  * NO CA trust, so a server bound with it is a development endpoint, not an attested/operator-trusted
  * one (Constitution IV); a real deployment loads operator/SPIRE-issued certs (T060) instead. */
object DevCert:
  /** A fresh (private key, self-signed cert) pair — CN=localhost, **Ed25519**, valid for one day.
    *
    * Ed25519 rather than ECDSA P-256, and that choice is load-bearing for [[PqTls]]: Bouncy Castle's
    * TLS server will only select an ECDSA credential when the certificate's own curve appears in the
    * negotiated `supported_groups`. Under RFC 10024 hybrid-ONLY that list is `X25519MLKEM768` and
    * nothing else, so a P-256 cert leaves the server with no usable credential and it aborts the
    * handshake with `handshake_failure(40)` — reported, misleadingly, as "found no selectable cipher
    * suite". An Ed25519 credential is selected via `signature_algorithms` instead, which is
    * independent of the key-agreement groups, so it works under a hybrid-only policy. */
  def selfSigned(): (PrivateKey, X509Certificate) =
    val kpg = KeyPairGenerator.getInstance("Ed25519", PqTls.bcProvider)
    kpg.initialize(255, new SecureRandom())
    val kp = kpg.generateKeyPair()

    val name = new X500Name("CN=localhost")
    val now = System.currentTimeMillis()
    val notBefore = new Date(now - 60_000L)
    val notAfter = new Date(now + 86_400_000L) // 24h is plenty for a dev/test bind
    val serial = BigInteger.valueOf(now)

    val builder =
      new JcaX509v3CertificateBuilder(name, serial, notBefore, notAfter, name, kp.getPublic)
    // A dNSName=localhost SAN so TLS hostname verification doesn't depend on the deprecated CN
    // fallback (RFC 6125; some JDK/provider versions reject CN-only certs).
    builder.addExtension(
      Extension.subjectAlternativeName,
      false,
      new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost"))
    )
    val signer =
      new JcaContentSignerBuilder("Ed25519").setProvider(PqTls.bcProvider).build(kp.getPrivate)
    val cert =
      new JcaX509CertificateConverter()
        .setProvider(PqTls.bcProvider)
        .getCertificate(builder.build(signer))
    (kp.getPrivate, cert)

  /** A fresh dev credential as a **Bouncy-Castle-built** `KeyManagerFactory`, plus the certificate
    * (which callers need separately, to build a client that trusts this server).
    *
    * netty's `SslContextBuilder.forServer(key, cert)` stores the credential in a KeyStore created
    * from the *default* provider, so the KeyManager hands BC's TLS stack a
    * `sun.security.ec.ed.EdDSAPrivateKeyImpl`. BC's signer accepts only its own key types and aborts
    * the handshake with `internal_error(80)` — "'privateKey' type not supported". Building both the
    * keystore and the KeyManagerFactory through BC keeps the key a BC key end to end. */
  def selfSignedManaged(): (KeyManagerFactory, X509Certificate) =
    val (key, cert) = selfSigned()
    val pw = Array.emptyCharArray
    val ks = KeyStore.getInstance("PKCS12", PqTls.bcProvider)
    ks.load(null, null)
    ks.setKeyEntry("dev", key, pw, Array(cert))
    val kmf = KeyManagerFactory.getInstance("PKIX", PqTls.provider)
    kmf.init(ks, pw)
    (kmf, cert)

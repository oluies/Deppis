package transport.round

import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.{Extension, GeneralName, GeneralNames}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.security.{KeyPairGenerator, PrivateKey, SecureRandom}
import java.util.Date

/** A **dev-only** self-signed TLS certificate generator (T020).
  *
  * `TlsRoundServer` needs a cert to bind TLS 1.3. For development we mint a throwaway self-signed
  * P-256 cert (CN=localhost) here with Bouncy Castle — netty's built-in `SelfSignedCertificate`
  * relies on `sun.security.x509` internals that newer JDKs no longer expose. A self-signed cert has
  * NO CA trust, so a server bound with it is a development endpoint, not an attested/operator-trusted
  * one (Constitution IV); a real deployment loads operator/SPIRE-issued certs (T060) instead. */
object DevCert:
  /** A fresh (private key, self-signed cert) pair — CN=localhost, P-256/ECDSA, valid for one day. */
  def selfSigned(): (PrivateKey, X509Certificate) =
    val kpg = KeyPairGenerator.getInstance("EC")
    kpg.initialize(256, new SecureRandom())
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
    val signer = new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate)
    val cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer))
    (kp.getPrivate, cert)

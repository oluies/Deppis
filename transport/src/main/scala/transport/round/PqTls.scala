package transport.round

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider
import java.security.{Provider, Security}

/** Post-quantum TLS 1.3 key agreement per **RFC 10024** ("Post-Quantum Traditional (PQ/T) Hybrid Key
  * Agreement Mechanisms for TLS 1.3", Standards Track, August 2026).
  *
  * ## Why a provider swap is required
  *
  * The JDK's own JSSE implements **no** RFC 10024 group. Measured on JDK 26 via
  * `SSLContext.getDefault.getSupportedSSLParameters.getNamedGroups`:
  * {{{
  * [x25519, secp256r1, secp384r1, secp521r1, x448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192]
  * }}}
  * No `X25519MLKEM768`, no `SecP256r1MLKEM768`, no `SecP384r1MLKEM1024`. So `SslProvider.JDK` — what
  * `TlsRoundServer` used before — cannot negotiate post-quantum key agreement at all, on the newest
  * JDK available. Bouncy Castle's `bctls` does, at the RFC's exact codepoints (4587/4588/4589), and
  * it is already a vetted dependency here (Constitution I: no hand-rolled crypto).
  *
  * ## Hybrid-ONLY, by deliberate choice
  *
  * RFC 10024's deployment guidance is to offer the hybrid share **first** and to deploy **without**
  * retry/fallback, because fallback logic reintroduces exactly the downgrade attacks the hybrid
  * construction exists to prevent. We go further and offer hybrid *only*: [[NamedGroups]] lists
  * `X25519MLKEM768` and nothing else, so there is no classical group to negotiate down to.
  *
  * The cost is real and intended: **a peer that cannot do ML-KEM-768 cannot connect.** That includes
  * any client on the JDK's stock JSSE. This is a security posture, not an oversight.
  *
  * Measured effect on the ClientHello (parsed off the wire, not inferred):
  * {{{
  * supported_groups = 0x11EC                 // X25519MLKEM768, and nothing else
  * key_share        = 0x11EC (1216 bytes)    // real ML-KEM-768 hybrid share in the FIRST flight
  * ClientHello      = 1368 bytes
  * }}}
  * Sending the hybrid share in the first flight is what avoids a HelloRetryRequest round trip: BC's
  * default (hybrid listed last, classical key_share only) negotiates PQ solely via HRR, at the cost
  * of an extra RTT. 1368 bytes also stays under the ~1500-byte ClientHello that legacy middleboxes
  * assume, which is the dominant real-world failure mode for PQ TLS — it manifests as a silent hang
  * rather than a clean error, so staying below it matters.
  *
  * ## Why a system property
  *
  * Named groups are not configurable per-`SSLContext` through the netty that grpc-netty-shaded
  * bundles: its `SslContextBuilder` exposes `sslProvider`, `sslContextProvider`, `ciphers` and
  * `protocols`, but no `namedGroups`. The only lever is the JVM-wide `jdk.tls.namedGroups`, which
  * Bouncy Castle honours (its own `org.bouncycastle.jsse.*.namedGroups` properties do **not** take
  * effect — verified by capturing the ClientHello both ways). BC reads the property when the context
  * is built, so [[enforce]] setting it before any context is created is equivalent to a JVM flag.
  *
  * Because the property is process-wide, [[enforce]] fails closed rather than silently overriding a
  * value someone else set — a surprising downgrade is precisely the failure this class exists to
  * prevent. */
object PqTls:

  /** The RFC 10024 group we require, and the only one we offer. Codepoint 4588. */
  val Group: String = "X25519MLKEM768"

  /** The `jdk.tls.namedGroups` value: hybrid and nothing else, so no downgrade target exists. */
  val NamedGroups: String = Group

  private val NamedGroupsProperty = "jdk.tls.namedGroups"

  /** The Bouncy Castle *crypto* provider (bcprov), registered once. `DevCert` mints its Ed25519 key
    * and signature through this rather than the JDK's provider so the credential BC's TLS stack is
    * handed comes from the same implementation that has to consume it. */
  lazy val bcProvider: Provider =
    synchronized {
      Option(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)).getOrElse {
        val p = new BouncyCastleProvider(); Security.addProvider(p); p
      }
    }

  /** The Bouncy Castle JSSE provider, registered once. Not installed at position 1: it is passed
    * explicitly via netty's `sslContextProvider`, so nothing else in the process silently changes
    * TLS provider as a side effect of this class loading. */
  lazy val provider: Provider =
    synchronized {
      Option(Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME)).getOrElse {
        // bctls needs bcprov for the underlying primitives (ML-KEM-768, X25519, ECDSA).
        val p = new BouncyCastleJsseProvider(bcProvider)
        Security.addProvider(p)
        p
      }
    }

  /** Pin `jdk.tls.namedGroups` to the hybrid-only list, and fail if that is not possible.
    *
    * Idempotent. Throws if the property is already set to anything else: silently honouring a
    * foreign value could downgrade every connection in the process to classical key agreement while
    * still appearing to work, which is the one outcome this module must never produce. */
  def enforce(): Unit =
    synchronized {
      // Order matters. Netty's JdkSslContext static initialiser builds a probe SSLEngine from the
      // *JDK's* provider to derive default cipher suites, and the JDK's SSLConfiguration rejects a
      // jdk.tls.namedGroups value containing nothing it knows — which, for a hybrid-only list, is
      // every entry ("contains no supported named groups"). Forcing that class to initialise while
      // the property is still unset lets it compute its defaults from the JDK, after which our
      // contexts are built against Bouncy Castle and never consult the JDK's group table again.
      Class.forName("io.grpc.netty.shaded.io.netty.handler.ssl.JdkSslContext")
      Option(System.getProperty(NamedGroupsProperty)) match
        case None => System.setProperty(NamedGroupsProperty, NamedGroups)
        case Some(v) if v == NamedGroups => ()
        case Some(other) =>
          throw new IllegalStateException(
            s"$NamedGroupsProperty is already '$other', but RFC 10024 hybrid-only TLS requires " +
              s"'$NamedGroups'. Refusing to continue rather than negotiate a downgrade."
          )
    }

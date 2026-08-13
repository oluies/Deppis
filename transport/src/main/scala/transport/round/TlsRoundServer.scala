package transport.round

import io.grpc.netty.shaded.io.grpc.netty.{NettyChannelBuilder, NettyServerBuilder}
import io.grpc.netty.shaded.io.netty.handler.ssl.ApplicationProtocolConfig.{
  Protocol,
  SelectedListenerFailureBehavior,
  SelectorFailureBehavior
}
import io.grpc.netty.shaded.io.netty.handler.ssl.{
  ApplicationProtocolConfig,
  ApplicationProtocolNames,
  SslContext,
  SslContextBuilder,
  SslProvider
}
import io.grpc.{ManagedChannel, Server}
import metadatamessenger.messaging.v1.messaging.RoundServiceGrpc
import store.ObliviousStore
import transport.RoundServiceImpl
import java.security.cert.X509Certificate
import scala.concurrent.ExecutionContext

/** A **networked** gRPC host for the round service, secured with **TLS 1.3** (T020, contract
  * `messaging.proto`). This is the real-port, real-handshake bind — distinct from the in-process
  * service tests (`RoundServiceSpec` et al.) which use `InProcessServerBuilder` and no transport
  * security at all.
  *
  * DEV posture (Constitution IV): the certificate is a freshly-generated **self-signed** cert
  * (`DevCert`, CN=localhost) with no CA trust — this is a development bind, NOT an attested or
  * operator-trusted deployment. A real deployment supplies operator/SPIRE-issued certs (T060) and a
  * privacy-positive backend; the round server does not by itself confer metadata privacy, and the
  * backend it binds keeps surfacing its own `DEV, NO METADATA PRIVACY` label. */
final class TlsRoundServer private (server: Server, cert: X509Certificate):
  /** The bound port (resolved when `port = 0` was requested). */
  def port: Int = server.getPort

  /** A client channel that trusts THIS server's dev self-signed cert over TLS 1.3. */
  def trustingChannel(): ManagedChannel = TlsRoundServer.clientChannel(port, cert)

  /** Shut the server down. */
  def stop(): Unit = server.shutdownNow()

object TlsRoundServer:
  /** TLS 1.3 server context from a key + cert, configured for gRPC/HTTP-2 (ALPN).
    *
    * `SslProvider.JDK` selects netty's JSSE path (not the bundled BoringSSL, which rejects the
    * BC-generated EC cert with an internal error), and `sslContextProvider` points that path at
    * **Bouncy Castle's** JSSE rather than the JDK's. That swap is what enables RFC 10024 hybrid key
    * agreement: the JDK's own JSSE implements no hybrid group even on JDK 26. See [[PqTls]]. */
  /** ALPN advertising exactly `h2`, which is what gRPC requires over TLS. This is the same config
    * `GrpcSslContexts.configure` installs; we build it here because that helper additionally gates
    * on a hard-coded provider whitelist and rejects Bouncy Castle ("BCJSSE selected, but Java 9+
    * ALPN unavailable") even though the Java 9 ALPN API is present — `JettyTlsUtil
    * .isJava9AlpnAvailable()` returns true on this JDK. Supplying the identical ALPN config directly
    * keeps gRPC's wire requirements intact while letting us choose the JSSE provider. */
  private val alpnH2 = new ApplicationProtocolConfig(
    Protocol.ALPN,
    // gRPC requires a definite h2 outcome; NO_ADVERTISE/ACCEPT is what GrpcSslContexts uses.
    SelectorFailureBehavior.NO_ADVERTISE,
    SelectedListenerFailureBehavior.ACCEPT,
    ApplicationProtocolNames.HTTP_2
  )

  /** Finish an SslContextBuilder as **TLS 1.3 with RFC 10024 hybrid-only key agreement**: netty's
    * JSSE path, pointed at Bouncy Castle's provider, with the named groups pinned by [[PqTls]]. */
  private def pq(builder: SslContextBuilder): SslContext =
    PqTls.enforce()
    builder
      .sslProvider(SslProvider.JDK)
      .sslContextProvider(PqTls.provider)
      .protocols("TLSv1.3")
      .applicationProtocolConfig(alpnH2)
      .build()

  private def serverSsl(kmf: javax.net.ssl.KeyManagerFactory): SslContext =
    pq(SslContextBuilder.forServer(kmf))

  /** Bind the `RoundService` (over `store`) on `port` (0 ⇒ ephemeral) with TLS 1.3 and a fresh dev
    * self-signed cert, then start it. */
  def bind(store: ObliviousStore, port: Int = 0)(using ec: ExecutionContext): TlsRoundServer =
    val (kmf, cert) = DevCert.selfSignedManaged()
    val server = NettyServerBuilder
      .forPort(port)
      .sslContext(serverSsl(kmf))
      .addService(RoundServiceGrpc.bindService(new RoundServiceImpl(store), ec))
      .build()
      .start()
    new TlsRoundServer(server, cert)

  /** A client channel that trusts `cert` (the server's dev self-signed cert) over TLS 1.3. The
    * authority is `localhost` to match the cert CN. */
  def clientChannel(port: Int, cert: X509Certificate): ManagedChannel =
    PqTls.enforce()
    val ssl = pq(SslContextBuilder.forClient.trustManager(cert))
    NettyChannelBuilder
      .forAddress("localhost", port)
      .sslContext(ssl)
      .build()

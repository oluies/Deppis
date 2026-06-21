package transport.round

import io.grpc.netty.shaded.io.grpc.netty.{GrpcSslContexts, NettyChannelBuilder, NettyServerBuilder}
import io.grpc.netty.shaded.io.netty.handler.ssl.{SslContext, SslContextBuilder, SslProvider}
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
  /** TLS 1.3 server context from a key + cert, configured for gRPC/HTTP-2 (ALPN). Uses the JDK SSL
    * provider (JSSE) — native TLS 1.3 on JDK 22+ — rather than the shaded netty's bundled BoringSSL,
    * which rejects the BC-generated EC cert with an internal error. */
  private def serverSsl(key: java.security.PrivateKey, cert: X509Certificate): SslContext =
    GrpcSslContexts
      .configure(SslContextBuilder.forServer(key, cert), SslProvider.JDK)
      .protocols("TLSv1.3")
      .build()

  /** Bind the `RoundService` (over `store`) on `port` (0 ⇒ ephemeral) with TLS 1.3 and a fresh dev
    * self-signed cert, then start it. */
  def bind(store: ObliviousStore, port: Int = 0)(using ec: ExecutionContext): TlsRoundServer =
    val (key, cert) = DevCert.selfSigned()
    val server = NettyServerBuilder
      .forPort(port)
      .sslContext(serverSsl(key, cert))
      .addService(RoundServiceGrpc.bindService(new RoundServiceImpl(store), ec))
      .build()
      .start()
    new TlsRoundServer(server, cert)

  /** A client channel that trusts `cert` (the server's dev self-signed cert) over TLS 1.3. The
    * authority is `localhost` to match the cert CN. */
  def clientChannel(port: Int, cert: X509Certificate): ManagedChannel =
    val ssl = GrpcSslContexts
      .configure(SslContextBuilder.forClient.trustManager(cert), SslProvider.JDK)
      .protocols("TLSv1.3")
      .build()
    NettyChannelBuilder
      .forAddress("localhost", port)
      .sslContext(ssl)
      .build()

package transport.round

import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder
import metadatamessenger.provider.v1.provider.ProviderServiceGrpc
import metadatamessenger.store.v1.{store as spb}
import ping.DevNotificationServer
import store.dev.DevObliviousStore
import transport.{ProviderServiceImpl, StoreServiceImpl}
import java.security.SecureRandom
import scala.concurrent.ExecutionContext

/** Plaintext **h2c** gRPC host for the `ObliviousStore` service and the service provider's
  * `ProviderService` — the Envoy gRPC-web upstream (T032c, `deploy/grpc-web/`). Envoy routes every
  * path here, so a browser's `ProviderSession` (`engine.ProviderSessionJs`) reaches the provider
  * through the same proxy; the provider runs its rounds on the wall clock against the same dev store
  * (`design/offline-delegation.md` §3).
  *
  * A browser cannot speak HTTP/2 gRPC directly, so the `ProtocolEngine`'s gRPC-web host transport
  * talks gRPC-web (HTTP/1.1) to Envoy, which translates it to gRPC (HTTP/2) and forwards here. This
  * binds the store over **plain h2c** on purpose: in that topology TLS terminates at/above Envoy (the
  * browser trusts Envoy's cert; Envoy→backend is an internal hop), so adding TLS here would be
  * redundant. A networked TLS bind for the non-proxied path already exists in [[TlsRoundServer]].
  *
  * DEV posture (Constitution IV): the dev in-memory `ObliviousStore` provides NO access-pattern
  * privacy and surfaces that label — this server does not by itself confer metadata privacy. */
object GrpcWebBackendServer:
  def main(args: Array[String]): Unit =
    given ec: ExecutionContext = ExecutionContext.global
    val port = sys.env.getOrElse("PORT", "9090").toInt
    val running = start(port)
    sys.addShutdownHook(running.close())
    running.server.awaitTermination()

  /** A running backend: the gRPC server and the provider's round clock, stopped together. */
  final class Running(val server: io.grpc.Server, clock: AutoCloseable) extends AutoCloseable:
    def port: Int = server.getPort
    def close(): Unit =
      clock.close()
      server.shutdownNow(): Unit

  /** Bind the store and the provider on `port` (0 ⇒ ephemeral) and start the provider's round clock. */
  def start(port: Int)(using ec: ExecutionContext): Running =
    val store = new DevObliviousStore()
    // The provider's backend: the same dev store, and a dev notify server with a fresh random key
    // (the provider seals notify tokens itself until Phase 4 moves sealing onto the device).
    val notifyKey = new Array[Byte](crypto.Crypto.KeyBytes)
    new SecureRandom().nextBytes(notifyKey)
    val provider = _root_.provider.Provider(
      _root_.provider.DevProviderBackend(store, DevNotificationServer(notifyKey))
    )
    val clock = _root_.provider.ProviderRoundDriver(provider).start()
    val server = NettyServerBuilder
      .forPort(port)
      .addService(spb.ObliviousStoreGrpc.bindService(new StoreServiceImpl(store), ec))
      .addService(ProviderServiceGrpc.bindService(new ProviderServiceImpl(provider), ec))
      .build()
      .start()
    System.err.println(
      s"[grpc-web-backend] h2c gRPC ObliviousStore + ProviderService on :${server.getPort} — " +
        s"${store.label} (metadataPrivate=${store.metadataPrivate}); provider rounds on the wall clock"
    )
    Running(server, clock)

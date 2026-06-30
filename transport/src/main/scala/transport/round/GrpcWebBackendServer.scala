package transport.round

import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder
import metadatamessenger.store.v1.{store as spb}
import store.dev.DevObliviousStore
import transport.StoreServiceImpl
import scala.concurrent.ExecutionContext

/** Plaintext **h2c** gRPC host for the `ObliviousStore` service — the Envoy gRPC-web upstream (T032c,
  * `deploy/grpc-web/`).
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
    val store = new DevObliviousStore()
    val server = NettyServerBuilder
      .forPort(port)
      .addService(spb.ObliviousStoreGrpc.bindService(new StoreServiceImpl(store), ec))
      .build()
      .start()
    System.err.println(
      s"[grpc-web-backend] h2c gRPC ObliviousStore on :$port — ${store.label} " +
        s"(metadataPrivate=${store.metadataPrivate})"
    )
    sys.addShutdownHook(server.shutdown())
    server.awaitTermination()

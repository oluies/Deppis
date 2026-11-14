package transport.round

import io.grpc.ManagedChannelBuilder
import metadatamessenger.provider.v1.provider.ProviderServiceGrpc
import org.scalatest.funsuite.AnyFunSuite
import transport.GrpcProviderClient

import scala.concurrent.ExecutionContext

/** The Envoy gRPC-web upstream now serves the provider too (`design/offline-delegation.md` §3): bind
  * it on a free port and reach `ProviderService` over plaintext h2c — the hop Envoy makes — with the
  * same client calls a browser host maps to gRPC-web. */
class GrpcWebBackendServerSpec extends AnyFunSuite:
  test("the gRPC-web backend serves ProviderService over h2c"):
    given ExecutionContext = ExecutionContext.global
    val running = GrpcWebBackendServer.start(0)
    val channel = ManagedChannelBuilder.forAddress("127.0.0.1", running.port).usePlaintext().build()
    try
      val client = GrpcProviderClient(ProviderServiceGrpc.blockingStub(channel))
      assert(client.register("browser-user", "label".getBytes).isRight, "a device can register")
      assert(client.register("browser-user", "label".getBytes).isLeft, "and only once")
      assert(client.collectAll("browser-user").isEmpty)
    finally
      channel.shutdownNow()
      running.close()

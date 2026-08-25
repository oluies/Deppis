package sidecar

import cats.effect.{ExitCode, IO, IOApp}
import cats.effect.std.Mutex
import com.comcast.ip4s.{Host, Ipv4Address, Port}
import metadatamessenger.store.v1.store as pb
import org.http4s.ember.server.EmberServerBuilder
import org.typelevel.log4cats.LoggerFactory
import org.typelevel.log4cats.noop.NoOpFactory

/** Benchmark server: the SAME code linked for the JVM and for Scala Native, so the only difference
  * the numbers can reflect is the runtime underneath.
  *
  * BENCHMARK BUILD — NO METADATA PRIVACY, and unlike `obsd` this one makes no privacy claim even
  * in principle: see [[ObliviousStore]] for why its constant-time discipline is not enforceable
  * here. Do not deploy it.
  *
  * Configuration mirrors `obsd` so the two are driven identically:
  *   SIDECAR_ADDR      host:port (default 127.0.0.1:50061)
  *   SIDECAR_CAPACITY  slot count (default 4096, matching OBSD_CAPACITY's default)
  *
  * Both are parsed FAIL-CLOSED. A benchmark that silently fell back to a default capacity would
  * report a number for a configuration nobody asked for, which is worse than not starting: the
  * whole point of the run is that capacity is the independent variable.
  */
object Main extends IOApp:

  private val DefaultAddr = "127.0.0.1:50061"
  private val DefaultCapacity = 4096

  private def die(msg: String): IO[Nothing] =
    IO.consoleForIO.errorln(s"sidecar-scala: $msg") *> IO.raiseError(new RuntimeException(msg))

  private def parseAddr(s: String): IO[(Host, Port)] =
    s.split(':') match
      case Array(h, p) =>
        (Ipv4Address.fromString(h), Port.fromString(p)) match
          case (Some(host), Some(port)) => IO.pure((host, port))
          case _ => die(s"SIDECAR_ADDR is not a valid host:port: `$s`")
      case _ => die(s"SIDECAR_ADDR must be host:port, got `$s`")

  private def parseCapacity(s: String): IO[Int] =
    s.toIntOption.filter(_ > 0) match
      case Some(n) => IO.pure(n)
      case None => die(s"SIDECAR_CAPACITY must be a positive integer, got `$s`")

  def run(args: List[String]): IO[ExitCode] =
    given LoggerFactory[IO] = NoOpFactory[IO]
    for
      // bound as one value, not destructured in the pattern: a tuple pattern in a for-comprehension
      // desugars to `withFilter`, which IO does not have.
      addr <- IO(sys.env.getOrElse("SIDECAR_ADDR", DefaultAddr)).flatMap(parseAddr)
      (host, port) = addr
      capacity <- sys.env.get("SIDECAR_CAPACITY").fold(IO.pure(DefaultCapacity))(parseCapacity)
      mutex <- Mutex[IO]
      store = new ObliviousStore(capacity)
      routes = pb.ObliviousStore.toRoutes(new StoreService[IO](mutex, store))
      _ <- IO.consoleForIO.errorln(
        s"sidecar-scala: serving ObliviousStore (capacity $capacity) on $host:$port" +
          " — BENCHMARK BUILD, DEV, NO METADATA PRIVACY"
      )
      exit <- EmberServerBuilder
        .default[IO]
        .withHost(host)
        .withPort(port)
        .withHttpApp(routes.orNotFound)
        .build
        .useForever
        .as(ExitCode.Success)
    yield exit

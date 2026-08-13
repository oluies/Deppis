package transport.round

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import java.net.ServerSocket
import javax.net.ssl.{SSLContext, SSLSocket, TrustManager, X509ExtendedTrustManager}

/** Proves the RFC 10024 posture **on the wire** rather than trusting that a handshake succeeded.
  *
  * A green TLS test says nothing about *which* key agreement ran: the whole failure mode this module
  * guards against is a connection that works perfectly while having silently negotiated classical
  * X25519. So this spec points a `PqTls`-configured client at a plain socket, captures the raw
  * ClientHello, and parses `supported_groups` and `key_share` out of it. */
final class PqTlsSpec extends AnyFlatSpec with Matchers:

  private val X25519MLKEM768 = 0x11ec // RFC 10024 codepoint 4588
  private val X25519 = 0x001d

  /** (supported_groups, key_share entries as (group, shareLength)) from a real ClientHello. */
  private def clientHelloExtensions(): (Seq[Int], Seq[(Int, Int)]) =
    PqTls.enforce()
    val server = new ServerSocket(0)
    @volatile var captured = Array.emptyByteArray
    val t = new Thread(() =>
      try
        val s = server.accept()
        val buf = new Array[Byte](8192)
        val n = s.getInputStream.read(buf)
        captured = buf.take(math.max(n, 0))
        s.close()
      catch case _: Throwable => ()
    )
    t.start()

    val ctx = SSLContext.getInstance("TLS", PqTls.provider)
    ctx.init(null, Array[TrustManager](TrustAll), null)
    try
      val c =
        ctx.getSocketFactory.createSocket("localhost", server.getLocalPort).asInstanceOf[SSLSocket]
      c.setEnabledProtocols(Array("TLSv1.3"))
      c.startHandshake() // fails (the peer is a plain socket) — we only need the ClientHello
    catch case _: Throwable => ()
    t.join(5000)
    server.close()
    parse(captured)

  private def parse(h: Array[Byte]): (Seq[Int], Seq[(Int, Int)]) =
    def u16(i: Int) = ((h(i) & 0xff) << 8) | (h(i + 1) & 0xff)
    // record(5) | handshake type+len(4) | client_version(2) | random(32) | session_id | suites | comp
    var i = 5 + 4 + 2 + 32
    i += 1 + (h(i) & 0xff)
    i += 2 + u16(i)
    i += 1 + (h(i) & 0xff)
    i += 2 // extensions total length
    var groups = Seq.empty[Int]
    var shares = Seq.empty[(Int, Int)]
    while i + 4 <= h.length do
      val (etype, elen, body) = (u16(i), u16(i + 2), i + 4)
      if etype == 10 then
        val listEnd = body + 2 + u16(body)
        groups = (body + 2).until(listEnd, 2).map(u16)
      if etype == 51 then
        val listEnd = body + 2 + u16(body)
        var k = body + 2
        while k + 4 <= listEnd do
          val (g, kl) = (u16(k), u16(k + 2))
          shares = shares :+ (g -> kl)
          k += 4 + kl
      i = body + elen
    (groups, shares)

  private object TrustAll extends X509ExtendedTrustManager:
    import java.security.cert.X509Certificate as Cert
    def checkClientTrusted(c: Array[Cert], s: String): Unit = ()
    def checkServerTrusted(c: Array[Cert], s: String): Unit = ()
    def checkClientTrusted(c: Array[Cert], s: String, k: java.net.Socket): Unit = ()
    def checkServerTrusted(c: Array[Cert], s: String, k: java.net.Socket): Unit = ()
    def checkClientTrusted(c: Array[Cert], s: String, e: javax.net.ssl.SSLEngine): Unit = ()
    def checkServerTrusted(c: Array[Cert], s: String, e: javax.net.ssl.SSLEngine): Unit = ()
    def getAcceptedIssuers: Array[Cert] = Array.empty

  "PqTls" should "offer X25519MLKEM768 and NOTHING else (no classical downgrade target)" in {
    val (groups, _) = clientHelloExtensions()
    groups shouldBe Seq(X25519MLKEM768)
    groups should not contain X25519
  }

  it should "carry the ML-KEM-768 hybrid key share in the FIRST flight (no HelloRetryRequest)" in {
    val (_, shares) = clientHelloExtensions()
    // One share, for the hybrid group. 1216 B = X25519 (32) + ML-KEM-768 encapsulation key (1184).
    shares.map(_._1) shouldBe Seq(X25519MLKEM768)
    shares.head._2 shouldBe 1216
  }

  it should "reject a conflicting named-groups policy rather than silently downgrade" in {
    val prop = "jdk.tls.namedGroups"
    val saved = System.getProperty(prop)
    try
      System.setProperty(prop, "x25519")
      val e = intercept[IllegalStateException](PqTls.enforce())
      e.getMessage should include("Refusing to continue")
    finally if saved == null then System.clearProperty(prop) else System.setProperty(prop, saved)
  }

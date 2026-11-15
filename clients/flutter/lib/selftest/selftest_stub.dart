/// The routing self-test needs a browser (gRPC-web + the Scala.js bundle).
Future<void> runRoutingSelfTest() async =>
    throw UnsupportedError('the routing self-test runs only in a browser');

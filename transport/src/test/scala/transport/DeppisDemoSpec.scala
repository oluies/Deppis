package transport

import org.scalatest.funsuite.AnyFunSuite

/** Smoke test for the headless demo: drives `DeppisDemo.run` against the REAL Rust `obsd` (via the
  * shared [[ObsdHarness]]) and asserts Alice's message actually reaches Bob. Keeps the runnable
  * prototype honest — if the demo wiring rots, CI's `integration` job (which builds obsd) catches
  * it. Opt-in: cancels when obsd is absent. */
class DeppisDemoSpec extends AnyFunSuite with ObsdHarness:

  test("DeppisDemo.run delivers Alice's message to Bob through obsd"):
    val notifyKey = DeppisDemo.devNotifyKey // single source — obsd + demo must agree
    withObsd(notifyKey) { channel =>
      assert(DeppisDemo.run(channel, notifyKey), "the demo should deliver the message end-to-end")
    }

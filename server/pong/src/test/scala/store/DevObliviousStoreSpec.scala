package store

import store.dev.DevObliviousStore
import frame.Frame
import privacy.Privacy
import org.scalatest.funsuite.AnyFunSuite

class DevObliviousStoreSpec extends AnyFunSuite:

  private def frame(b: Byte): Array[Byte] = Frame.pad(Array(b)).toOption.get

  test("dev store is labeled and never metadata-private (Constitution IV)"):
    val s = DevObliviousStore()
    assert(!s.metadataPrivate)
    assert(s.label == Privacy.DevLabel)

  test("write then read returns the frame; second read is empty (non-recurrence, FR-014)"):
    val s = DevObliviousStore()
    val tok = "tok-1".getBytes
    assert(s.write(tok, frame(7)).isRight)
    assert(s.read(tok).toOption.get.exists(_.sameElements(frame(7))))
    assert(s.read(tok).toOption.get.isEmpty) // single-use
  test("writing the same token twice is rejected (no two messages under one token)"):
    val s = DevObliviousStore()
    val tok = "tok-2".getBytes
    assert(s.write(tok, frame(1)).isRight)
    assert(s.write(tok, frame(2)).isLeft)

  test("non-256-byte frames are rejected"):
    assert(DevObliviousStore().write("t".getBytes, Array[Byte](1, 2, 3)).isLeft)

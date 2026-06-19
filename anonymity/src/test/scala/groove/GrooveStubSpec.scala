package groove

import privacy.Privacy
import org.scalatest.funsuite.AnyFunSuite

class GrooveStubSpec extends AnyFunSuite:

  private def hex(b: Array[Byte]): String = b.map(x => f"${x & 0xff}%02x").mkString
  private def frames(n: Int): Vector[Array[Byte]] =
    (0 until n).toVector.map(i => Array.fill[Byte](256)(i.toByte))

  test("stub is labeled and never metadata-private (Constitution IV)"):
    val g = GrooveStub()
    assert(!g.metadataPrivate)
    assert(g.label == Privacy.DevLabel)

  test("fetch returns exactly the round's frames as a multiset (shuffle preserves content)"):
    val g  = GrooveStub()
    val fs = frames(8)
    fs.foreach(f => assert(g.submit(1L, f).isRight))
    val out = g.fetch(1L, 8).toOption.get
    assert(out.map(hex).sorted == fs.map(hex).sorted)

  test("fetch returns at most `count` frames"):
    val g = GrooveStub()
    frames(10).foreach(f => g.submit(2L, f))
    assert(g.fetch(2L, 3).toOption.get.size == 3)

  test("rounds are isolated; an empty/unknown round yields nothing"):
    val g = GrooveStub()
    g.submit(1L, frames(1).head)
    assert(g.fetch(99L, 5).toOption.get.isEmpty)

  test("negative count is rejected"):
    assert(GrooveStub().fetch(1L, -1).isLeft)

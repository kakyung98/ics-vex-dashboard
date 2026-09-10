importCpg("C:/Users/user/Desktop/jvm/zlib.cpg.bin")
val defined = cpg.method.isExternal(false).size
val ext = cpg.method.isExternal(true).size
println(s"RESULT METHODS=${cpg.method.size} DEFINED=$defined EXTERNAL=$ext CALLS=${cpg.call.size}")
println("RESULT HAS_inflate=" + cpg.method.nameExact("inflate").size)
println("RESULT HAS_inflate_table=" + cpg.method.nameExact("inflate_table").size)
println("RESULT CALLERS_inflate_table=" + cpg.method.nameExact("inflate_table").caller.name.dedup.l.mkString("|"))
println("RESULT RESOLUTION=" + (defined.toDouble / (defined + ext).toDouble))

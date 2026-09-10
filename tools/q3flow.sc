// Q3 as a data-flow question, not a reachability one.
// Reachability asks "can control get here". CISA asks "can the adversary
// control the vulnerable code" - that is a taint flow from an attacker-supplied
// source into the vulnerable function's parameters.
importCpg("C:/Users/user/Desktop/jvm/zlib.cpg.bin")
val TARGET = "inflate_table"

val ioNames = "recv|recvfrom|read|fread|fgets|getline|accept|SSL_read|getenv|scanf|fscanf"

// 1. call-graph reachability (what the current pipeline computes)
val callers = cpg.method.nameExact(TARGET).caller.name.dedup.l
println("RESULT CALLERS=" + callers.mkString("|"))

// 2. the sink: the vulnerable function's parameters
val sink = cpg.method.nameExact(TARGET).parameter
println("RESULT SINK_PARAMS=" + sink.name.l.mkString("|"))

// 3a. taint from an I/O primitive anywhere in the tree
val ioSrc = cpg.call.name(ioNames).argument
val flowsIo = sink.reachableByFlows(ioSrc).size
println("RESULT FLOWS_FROM_IO=" + flowsIo)

// 3b. taint from the library's own public entry points - for a library the
//     attacker's bytes arrive through the API, not through a syscall it makes
val apiSrc = cpg.method.name("inflate|inflateBack|inflateInit_|inflateInit2_").parameter
val flowsApi = sink.reachableByFlows(apiSrc).size
println("RESULT FLOWS_FROM_API=" + flowsApi)

if (flowsApi > 0) {
  val f = sink.reachableByFlows(apiSrc).head
  println("RESULT SAMPLE_FLOW=" + f.elements.map(_.code.take(40)).mkString(" -> "))
}

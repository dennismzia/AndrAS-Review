import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.amandroid.alir.componentSummary.ComponentSummaryTable.CHANNELS
import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis, ICC_Summary, IntentCaller}
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.{AndroidReachingFactsAnalysis, AndroidReachingFactsAnalysisConfig, IntentHelper}
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, DataLeakageAndroidSourceAndSinkManager}
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.util.AndroidUrlCollector
import org.argus.amandroid.summary.wu.IntentWu
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core.{ClassLoadManager, Global, JawaMethod}
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.io.DefaultReporter
import org.argus.jawa.core.util.{FileUtil, IList, ISet, MSet, msetEmpty}
import org.argus.jawa.flow.pta.{PTAConcreteStringInstance, PTAResult, PTAScopeManager, PTASlot, VarSlot}
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.summary.wu.{PTStore, PTSummary, PTSummaryRule, WorkUnit}
import org.argus.jawa.flow.summary.{BottomUpSummaryGenerator, SummaryManager}
import org.argus.jawa.flow.cg.CallGraph
import org.argus.jawa.core.util.MyTimeout
import org.argus.jawa.core.util._
import org.argus.jawa.flow.cfg.{ICFGCallNode, ICFGInvokeNode, ICFGLocNode, ICFGNode, InterProceduralControlFlowGraph}
import org.argus.jawa.flow.dda.InterProceduralDataDependenceAnalysis
import org.argus.jawa.flow.interprocedural.CallHandler
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.jawa.core.Global
import org.argus.jawa.core.util.URLInString
import org.argus.jawa.core.util._

import scala.language.postfixOps
import scala.concurrent.duration._
import java.io.{File, PrintWriter}
import java.util.concurrent.{TimeUnit, TimeoutException}
import java.util.regex.Pattern


object Main {

  val sources: Array[String] = Array(
    "Ljava/net/URL;.<init>:(Ljava/lang/String;)V",
    ""
  )

  val sinks: Array[String] = Array(
    "Ljava/net/URLConnection;.getOutputStream:()Ljava/io/OutputStream;",
    "Ljava/net/URLConnection;.getInputStream:()Ljava/io/InputStream;",
    "Lorg/apache/http/HttpResponse;.getEntity:()Lorg/apache/http/HttpEntity;",
    "Lorg/apache/http/util/EntityUtils;.toString:(Lorg/apache/http/HttpEntity;)Ljava/lang/String;",
    "Lorg/apache/http/util/EntityUtils;.toString:(Lorg/apache/http/HttpEntity;Ljava/lang/String;)Ljava/lang/String;",
    "Lorg/apache/http/util/EntityUtils;.toByteArray:(Lorg/apache/http/HttpEntity;)[B",
    "Lorg/apache/http/util/EntityUtils;.getContentCharSet:(Lorg/apache/http/HttpEntity;)Ljava/lang/String;",
  )

  def regex1(code: String): Boolean = {
    val reg1 = "^.*(URLConnection|org\\/apache\\/http).*$"
    val reg2 = "^.*(openConnection|connect|HttpRequest).*$"

    val a = Pattern.compile(reg1).matcher(code).matches()
    val b = Pattern.compile(reg2).matcher(code).matches()
    a && b
  }

  def regex2(code: String): Boolean = {
    val reg1 = "^.*(javax\\/net\\/ssl\\/HttpsURLConnection).*$"
    val reg2 = "^.*(HttpsURLConnection|connect).*$"

    Pattern.compile(reg1).matcher(code).matches() && Pattern.compile(reg2).matcher(code).matches()
  }

  def regex3(code: String): Boolean = {
    val reg1 = "^.*(org\\/apache\\/http\\/impl\\/client\\/DefaultHttpClient).*$"
    val reg2 = "^.*(HttpClient|HttpGet|DefaultHttpClient|HttpEntity|HttpResponse|HttpPost).*$"

    Pattern.compile(reg1).matcher(code).matches() && Pattern.compile(reg2).matcher(code).matches()
  }

  def regex4(code: String): Boolean = {
    val reg1 = "^.*(android\\/net\\/http\\/AndroidHttpClient).*$"
    val reg2 = "^.*(AndroidHttpClient|AndroidHttpClient\\/newInstance|HttpResponse|HttpGet|HttpPost).*$"

    Pattern.compile(reg1).matcher(code).matches() && Pattern.compile(reg2).matcher(code).matches()
  }

  def regex5(code: String): Boolean = {
    val reg1 = "^.*(okhttp3\\/OkHttpClient|com\\/squareup\\/okhttp\\/OkHttpClient).*$"
    val reg2 = "^.*(OkHttpClient|Request\\/Builder|newCall).*$"

    Pattern.compile(reg1).matcher(code).matches() && Pattern.compile(reg2).matcher(code).matches()
  }

  def regex6(code: String): Boolean = {
    val reg1 = "^.*(retrofit2\\/Retrofit|retrofit.RestAdapter).*$"
    val reg2 = "^.*(Retrofit|Retrofit\\/Builder|RestAdapter\\/Builder|setEndpoint|baseUrl).*$"

    Pattern.compile(reg1).matcher(code).matches() && Pattern.compile(reg2).matcher(code).matches()
  }

  def regex7(code: String): Boolean = {
    val reg1 = "^.*(com\\/android\\/volley\\/toolbox\\/Volley|com\\/android\\/volley\\/toolbox\\/StringRequest|com\\/android\\/volley\\/RequestQueue|com\\/android\\/volley\\/Response).*$"
    val reg2 = "^.*(Volley\\/newRequestQueue|StringRequest|Response\\/Listener|ReResponse\\/ErrorListenersponse).*$"

    Pattern.compile(reg1).matcher(code).matches() && Pattern.compile(reg2).matcher(code).matches()
  }

  def main(args: Array[String]): Unit = {
    if (args.length != 3) {
      println("usage: [full|partial] apk_path output_path")
      return
    }
    val fileUri = FileUtil.toUri(args(1))
    val outputUri = FileUtil.toUri(args(2))
    val reporter = new DefaultReporter
    // Yard is the apks manager
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout) // , sourceLevel = DecompileLevel.TYPED
    val settings = DecompilerSettings(debugMode = false, forceDelete = false, strategy, reporter)
    // apk is the apk meta data manager, class loader and class manager
    if (args(0).equals("full")) {
      val apk = yard.loadApk(fileUri, settings, collectInfo = false, resolveCallBack = false)
      val urls = collectUrlsFromSource(apk, fileUri)
      println("BEGIN")
      urls.foreach(p => println(p))
      println("END")
      return
    }

    if (!args(0).equals("partial")) {
      println("usage: [full|partial] apk_path output_path")
      return
    }

    val apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)
    val urls = collectUrlsFromSource(apk, fileUri)

    var setString: scala.collection.mutable.Set[String] = scala.collection.mutable.Set()
    apk.model.getComponents foreach {
      component =>
        apk.model.getEnvMap.get(component) match {
          case Some((esig, _)) => {
            val ep = apk.getMethod(esig).get
            val initialfacts = AndroidReachingFactsAnalysisConfig.getInitialFactsForMainEnvironment(ep)
            val icfg = new InterProceduralControlFlowGraph[ICFGNode]

            val ptaresult = new PTAResult
            val sp = new AndroidSummaryProvider(apk)
            val analysis = new AndroidReachingFactsAnalysis(
              apk, icfg, ptaresult, new AndroidModelCallHandler, sp.getSummaryManager, new ClassLoadManager,
              AndroidReachingFactsAnalysisConfig.resolve_static_init,
              timeout = None)
            val idfg = analysis.build(ep, initialfacts, new Context(apk.nameUri))

            var codeMap: Map[Signature, String] = Map()
            idfg.icfg.nodes foreach {
              case cn: ICFGLocNode =>
                val source = cn.toString
                codeMap += (cn.getContext.getMethodSig -> (codeMap.getOrElse(cn.getContext.getMethodSig, "") + source))
              case _ =>
            }
            codeMap.foreach(kv => {
              if (regex1(kv._2) ||
                regex2(kv._2)||
                regex3(kv._2) ||
                regex4(kv._2) ||
                regex5(kv._2) ||
                regex6(kv._2) ||
                regex7(kv._2)) {
                urls.filter(p => kv._2.contains(p)).foreach(p => setString += p)
              }
            })
          }
          case _ =>
        }
    }


    println("BEGIN")
    setString.foreach(url => println(url))
    println("END")
    println("Accuracy: " + (setString.size.toFloat / urls.size.toFloat) * 100.0f + "%")

    //
//    val component = apk.model.getComponents.head // get any component you want to perform analysis
//    apk.model.getEnvMap.get(component) match {
//      case Some((esig, _)) =>
//        val ep = apk.getMethod(esig).get
//        val initialfacts = AndroidReachingFactsAnalysisConfig.getInitialFactsForMainEnvironment(ep)
//        val icfg = new InterProceduralControlFlowGraph[ICFGNode]
//        val ptaresult = new PTAResult
//        val sp = new AndroidSummaryProvider(apk)
//        val analysis = new AndroidReachingFactsAnalysis(
//          apk, icfg, ptaresult, new AndroidModelCallHandler, sp.getSummaryManager, new ClassLoadManager,
//          AndroidReachingFactsAnalysisConfig.resolve_static_init,
//          timeout = None)
//        val idfg = analysis.build(ep, initialfacts, new Context(apk.nameUri))
//        val iddResult = InterProceduralDataDependenceAnalysis(apk, idfg)
//        val ssm = new DataLeakageAndroidSourceAndSinkManager("/home/m3k4/thesis/CustomSourceSink.txt")
//        val taint_analysis_result = AndroidDataDependentTaintAnalysis(yard, iddResult, idfg.ptaresult, ssm)
//
//        /** ***************** Resolve all URL value ******************** */
//
//        val urlMap: MMap[Context, MSet[String]] = mmapEmpty
//        idfg.icfg.nodes foreach {
//          case cn: ICFGCallNode if cn.getCalleeSig == new Signature("Ljava/net/URL;.<init>:(Ljava/lang/String;)V") =>
//            val urlSlot = VarSlot(cn.recvNameOpt.get)
//
//            val urls = idfg.ptaresult.pointsToSet(cn.getContext, urlSlot)
//            val strSlot = VarSlot(cn.argNames(0))
//            val urlvalues = idfg.ptaresult.pointsToSet(cn.getContext, strSlot) map {
//              case pcsi: PTAConcreteStringInstance => pcsi.string
//              case _ => "ANY"
//            }
//            for (url <- urls;
//                 urlvalue <- urlvalues) {
//              urlMap.getOrElseUpdate(url.defSite, msetEmpty) += urlvalue
//            }
//          case _ =>
//        }
//
//        println(urlMap)
//
//        val gisNodes = taint_analysis_result.getSourceNodes.filter { node =>
//          node.node.node match {
//            case cn: ICFGInvokeNode if cn.getCalleeSig == new Signature("Ljava/net/URLConnection;.getInputStream:()Ljava/io/InputStream;") =>
//              true
//            case _ => false
//          }
//        }
//        gisNodes.foreach {
//          node =>
//            val invNode = node.node.node.asInstanceOf[ICFGInvokeNode]
//            val connSlot = VarSlot(invNode.recvNameOpt.get)
//            val connValues = idfg.ptaresult.pointsToSet(invNode.getContext, connSlot)
//            connValues foreach {
//              connValue =>
//                val urlInvNode = idfg.icfg.getICFGCallNode(connValue.defSite).asInstanceOf[ICFGCallNode]
//                val urlSlot = VarSlot(urlInvNode.recvNameOpt.get)
//                val urlValues = idfg.ptaresult.pointsToSet(connValue.defSite, urlSlot)
//                urlValues foreach { urlValue =>
//                  println("URL value at " + node.descriptor + "@" + node.node.node.getContext.getLocUri + "\nis:\n" + urlMap.getOrElse(urlValue.defSite, msetEmpty).mkString("\n"))
//                }
//            }
//        }
//
//      case None =>
//        yard.reporter.error("TaintAnalysis", "Component " + component + " did not have environment! Some package or name mismatch maybe in the Manifest file.")
//    }
  }

  def collectUrlsFromSource(global: Global, file: FileResourceUri): ISet[String] = {
    val afp = AppInfoCollector.analyzeARSC(global.reporter, file)
    val strs = msetEmpty[String]
    strs ++= afp.getGlobalStringPool.values
    val sources = global.getApplicationClassCodes
    val code_urls: Set[String] = {
      if (sources.nonEmpty) {
        sources.map {
          case (_, source) =>
            URLInString.extract(source.code)
        }.reduce(iunion[String])
      } else isetEmpty[String]
    }
    code_urls
  }
}
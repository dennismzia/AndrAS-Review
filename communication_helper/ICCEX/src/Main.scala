import hu.ssh.progressbar.ConsoleProgressBar
import org.argus.amandroid.alir.componentSummary.ComponentSummaryTable.CHANNELS
import org.argus.amandroid.alir.componentSummary.{ApkYard, ComponentBasedAnalysis, ICC_Summary, IntentCaller}
import org.argus.amandroid.alir.pta.model.AndroidModelCallHandler
import org.argus.amandroid.alir.pta.reachingFactsAnalysis.IntentHelper
import org.argus.amandroid.alir.pta.summaryBasedAnalysis.AndroidSummaryProvider
import org.argus.amandroid.core.ApkGlobal
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileLevel, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.summary.wu.IntentWu
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core.{Global, JawaMethod}
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.io.DefaultReporter
import org.argus.jawa.core.util.{FileUtil, IList, ISet, MSet, msetEmpty}
import org.argus.jawa.flow.pta.{PTAScopeManager, PTASlot}
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.summary.wu.{PTStore, PTSummary, PTSummaryRule, WorkUnit}
import org.argus.jawa.flow.summary.{BottomUpSummaryGenerator, SummaryManager}
import org.argus.jawa.flow.cg.CallGraph
import org.argus.jawa.core.util.MyTimeout
import org.argus.jawa.core.util._
import org.argus.jawa.flow.interprocedural.CallHandler

import scala.language.postfixOps
import scala.concurrent.duration._
import java.io.{File, PrintWriter}
import java.util.concurrent.{TimeUnit, TimeoutException}

object Main {
  def v1(apk: ApkGlobal, yard: ApkYard): Unit = {
    ComponentBasedAnalysis.prepare(Set(apk))(FiniteDuration(5, TimeUnit.MINUTES))
    val cba = new ComponentBasedAnalysis(yard)
    cba.phase1(Set(apk))
    val iddResult = cba.phase2(Set(apk))

    println("BEGIN")
    apk.getSummaryTables.foreach { st =>
      val table: ICC_Summary = st._2.get(CHANNELS.ICC)
      table.asCaller.foreach { x =>
        val method = x._1.getOwner.getClassName
        val intent: IntentCaller = x._2.asInstanceOf[IntentCaller]
        if (intent.intent.componentNames.nonEmpty) {
          println(s"$method - ${intent.intent.componentNames.head}")
        } else {
          // println(s"NO component link. Its likely an action ${intent.intent}")
        }
      }
    }
    println("END")
  }

  def v2(apk: ApkGlobal): Unit = {
    val handler: AndroidModelCallHandler = new AndroidModelCallHandler
    val sm: SummaryManager = new AndroidSummaryProvider(apk).getSummaryManager
    val analysis = new BottomUpSummaryGenerator[Global, PTSummaryRule](apk, sm, handler,
      (sig, rule) => PTSummary(sig, rule),
      ConsoleProgressBar.on(System.out).withFormat("[:bar] :percent% :elapsed Left: :remain"))
    val store: PTStore = new PTStore

    val sigs: ISet[Signature] = apk.model.getComponentInfos.flatMap(apk.getEntryPoints)
    val cg = SignatureBasedCallGraph(apk, sigs, None)
    val orderedWUs: IList[IntentWu] = cg.topologicalSort(true).map { sig =>
      val method = apk.getMethodOrResolve(sig).getOrElse(throw new RuntimeException("Method does not exist: " + sig))
      new IntentWu(apk, method, sm, handler, store, "intent")
    }
    analysis.build(orderedWUs.asInstanceOf[IList[WorkUnit[Global, PTSummaryRule]]])
    val candidate = store.getPropertyOrElse[MSet[(Context, PTASlot)]]("intent", msetEmpty)

    println("BEGIN")
    candidate.foreach { case (ctx, s) =>
      val intentInss = store.resolved.pointsToSet(ctx, s)
      val intent = IntentHelper.getIntentContents(store.resolved, intentInss, ctx)
      if (intent.nonEmpty && intent.head.componentNames.nonEmpty) {
        println(ctx.getMethodSig.getClassName + " - " + intent.head.componentNames.head)
      }
    }
    println("END")
  }

  def main(args: Array[String]): Unit = {
    // println(args.length)
    if (args.length < 3) {
      println("usage: [v1/v2] apk_path output_path (nolib)")
      return
    }
    val fileUri = FileUtil.toUri(args(1))
    val outputUri = FileUtil.toUri(args(2))
    val reporter = new DefaultReporter
    // Yard is the apks manager
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    var strategy: DecompileStrategy = null
    if (args.length == 4 && args(3).equals("nolib")) {
      strategy = DecompileStrategy(layout, thirdPartyLibLevel = DecompileLevel.NO) // , sourceLevel = DecompileLevel.TYPED
    } else {
      strategy = DecompileStrategy(layout) // , sourceLevel = DecompileLevel.TYPED
    }
    val settings = DecompilerSettings(debugMode = false, forceDelete = false, strategy, reporter)
    // apk is the apk meta data manager, class loader and class manager
    val apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)

    if (args(0).equals("v1")) {
      v1(apk, yard);
    } else if (args(0).equals("v2")) {
      v2(apk);
    } else {
      println("usage: [v1/v2] apk_path output_path (nolib)")
    }
  }
}

object SignatureBasedCallGraph {
  final val TITLE = "SignatureBasedCallGraph"

  def apply(
             global: Global,
             entryPoints: ISet[Signature],
             timer: Option[MyTimeout] = Some(new MyTimeout(1 minutes))): CallGraph = build(global, entryPoints, timer)

  def build(
             global: Global,
             entryPoints: ISet[Signature],
             timer: Option[MyTimeout]): CallGraph = {
    global.reporter.println(s"Building SignatureBasedCallGraph with ${entryPoints.size} entry points...")
    val cg = new CallGraph
    val processed: MSet[String] = msetEmpty
    entryPoints.foreach{ ep =>
      if(timer.isDefined) timer.get.refresh()
      try {
        val epmopt = global.getMethodOrResolve(ep)
        epmopt match {
          case Some(epm) =>
            if (!PTAScopeManager.shouldBypass(epm.getDeclaringClass) && epm.isConcrete) {
              sbcg(global, epm, cg, processed, timer)
            }
          case None =>
        }
      } catch {
        case te: TimeoutException =>
          global.reporter.error(TITLE, ep + ": " + te.getMessage)
      }
    }
    global.reporter.println(s"SignatureBasedCallGraph done with call size ${cg.getCallMap.size}.")
    cg
  }

  private def sbcg(global: Global, ep: JawaMethod, cg: CallGraph, processed: MSet[String], timer: Option[MyTimeout]) = {
    val worklist: MList[JawaMethod] = mlistEmpty // Make sure that all the method in the worklist are concrete.
    worklist += ep
    while(worklist.nonEmpty) {
      if(timer.isDefined) timer.get.timeoutThrow()
      val m = worklist.remove(0)
      processed += m.getSignature.signature
      try {
        m.getBody.resolvedBody.locations foreach { l =>
          l.statement match {
            case cs: CallStatement =>
              CallHandler.resolveSignatureBasedCall(global, cs.signature, cs.kind) foreach { callee =>
                cg.addCall(m.getSignature, callee.getSignature)
                if (!processed.contains(callee.getSignature.signature) && !PTAScopeManager.shouldBypass(callee.getDeclaringClass) && callee.isConcrete) {
                  worklist += callee
                }
              }
            case _ =>
          }
        }
      } catch {
        case e: Throwable => global.reporter.warning(TITLE, e.getMessage)
      }
    }
  }
}
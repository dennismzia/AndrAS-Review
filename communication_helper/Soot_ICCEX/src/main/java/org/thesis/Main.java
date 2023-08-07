package org.thesis;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Value;
import soot.jimple.ClassConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.infoflow.android.SetupApplication;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class Main {
//    private final static String android_path = "/home/m3k4/Android/Sdk/platforms/android-32/android.jar";
//    private final static String apk_path = "/home/m3k4/thesis/InsecureBankv2.apk";

    private static String android_path;
    private static String apk_path;

    // args have list of activity classes
    public static void main(String[] args) {

        if (args.length != 2) {
            System.out.println("USAGE: apk_path android_jar_path");
            return;
        }

        apk_path = args[0];
        android_path = args[1];

        SetupApplication app = new SetupApplication(android_path, apk_path);
        app.constructCallgraph();

        Set<String> entrypoints = app.getEntrypointClasses().stream()
                .map(SootClass::getName)
                .collect(Collectors.toSet());
        // PointsToAnalysis pointsToAnalysis = Scene.v().getPointsToAnalysis();

        // Entrypoints don't have callback class (E.g: com.example.A, but non com.example.A$1, ...)
        // Workaround is get all class, filter by name (contain) -> proceed
        // entrypoints' size usually small, so they may make no impact on performance

        System.out.println("BEGIN");
        Scene.v().getClasses().stream()
                .filter(className -> entrypoints.stream().anyMatch(e -> className.getName().contains(e)))
                .forEach(classSoot -> classSoot
                        .getMethods()
                        .forEach(method -> {
                                try {
                                method.retrieveActiveBody().getUnits()
                                        .forEach(unit ->
                                                unit.getUseBoxes().forEach(box -> {
                                                    Value v = box.getValue();
                                                    if (v instanceof InvokeExpr) {
                                                        InvokeExpr t = (InvokeExpr) v;
                                                        if (t.getMethod().getDeclaringClass().toString().equals("android.content.Intent") &&
                                                                t.getMethod().getName().equals("<init>") &&
                                                                t.getArgCount() > 1 &&
                                                                t.getArg(1) instanceof ClassConstant) {
                                                            ClassConstant c = (ClassConstant) t.getArg(1);
                                                            System.out.println(classSoot.getName() + " - " + c.toInternalString().replace('/', '.'));
                                                        }
                                                    }
                                                })

                                        );
                                } catch (Exception ignored) {}
                        }
                        ));
        System.out.println("END");
//        DotGraph dot = new DotGraph("cg");
//        Scene.v().getClasses().stream()
//                .filter(className -> Arrays.stream(args).anyMatch(e -> className.toString().contains(e)))
//                .forEach(classSoot -> classSoot
//                        .getMethods().stream()
//                        .map(method -> getTargetInMethod(method, args))
//                        .flatMap(Collection::stream)
//                        .collect(Collectors.toSet())
//                        .forEach(target -> dot.drawEdge(classSoot.getName().split("\\$")[0], target)));
//        dot.getNode(args[0]).setStyle("dashed");
//        dot.plot("/home/m3k4/thesis/graph.dot");
//
//        Scene.v().getSootClass("com.android.insecurebankv2.LoginActivity")
//                .getMethodByName("onCreate")
//                .retrieveActiveBody()
//                .getUnits()
//                .forEach(unit -> {
//                    unit.getUseBoxes().forEach(box -> {
//                        Value v = box.getValue();
//                        System.out.println(v);
//                        if (v instanceof InvokeExpr) {
//                            System.out.println("Calling");
//                            System.out.println(((InvokeExpr) v).getMethod().getName());
//                            System.out.println("with");
//                            System.out.println(((InvokeExpr) v).getArgs());
//                            System.out.println("end.");
//                        }
//                    });
//                    System.out.println("----");
//                });

    }

    private static String classToJimpleText(String className) {
        return "class \"L" + String.join("/", className.split("\\.")) + ";\"";
    }

    private static List<String> getTargetInMethod(SootMethod method, String[] args) {
        return method.retrieveActiveBody().getUnits().stream()
                .filter(unit -> unit.toString().contains("android.content.Intent"))
                .map(unit ->
                        Arrays.stream(args)
                                .filter(targetClass -> unit.toString().contains(classToJimpleText(targetClass)))
                                .findFirst()
                                .orElse(null))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }
}
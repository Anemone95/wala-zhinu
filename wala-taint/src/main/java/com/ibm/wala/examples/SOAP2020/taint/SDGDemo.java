package com.ibm.wala.examples.SOAP2020.taint;

import com.ibm.wala.cast.ipa.callgraph.CAstCallGraphUtil;
import com.ibm.wala.cast.python.client.PythonAnalysisEngine;
import com.ibm.wala.cast.python.loader.PythonLoaderFactory;
import com.ibm.wala.cast.python.modref.PythonModRef;
import com.ibm.wala.cast.python.types.PythonTypes;
import com.ibm.wala.cast.python.util.PythonInterpreter;
import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.Module;
import com.ibm.wala.classLoader.SourceURLModule;
import com.ibm.wala.examples.drivers.PDFTypeHierarchy;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.*;
import com.ibm.wala.ipa.slicer.*;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.types.Descriptor;
import com.ibm.wala.types.MethodReference;
import com.ibm.wala.types.Selector;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.WalaException;
import com.ibm.wala.util.collections.HashSetFactory;
import com.ibm.wala.util.collections.NonNullSingletonIterator;
import com.ibm.wala.util.graph.Graph;
import com.ibm.wala.util.graph.traverse.BFSPathFinder;
import com.ibm.wala.util.intset.OrdinalSet;
import com.ibm.wala.util.strings.Atom;
import com.ibm.wala.viz.DotUtil;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

public class SDGDemo {
    public static void main(String[] args) throws ClassNotFoundException, IllegalAccessException, InstantiationException, CancelException, IOException, WalaException {
        Class<?> j3 = Class.forName("com.ibm.wala.cast.python3.loader.Python3LoaderFactory");
        PythonAnalysisEngine.setLoaderFactory((Class<? extends PythonLoaderFactory>) j3);
        Class<?> i3 = Class.forName("com.ibm.wala.cast.python3.util.Python3Interpreter");
        PythonInterpreter.setInterpreter((PythonInterpreter)i3.newInstance());

        String filename="demo.py";
        Collection<Module> src = Collections.singleton(new SourceURLModule(
                SDGDemo.class.getClassLoader().getResource(filename)));
        PythonAnalysisEngine<Void> analysisEngine = new PythonAnalysisEngine<Void>() {
            @Override
            public Void performAnalysis(PropagationCallGraphBuilder builder) throws CancelException {
                assert false;
                return null;
            }
        };
        analysisEngine.setModuleFiles(src);
        SSAPropagationCallGraphBuilder builder = (SSAPropagationCallGraphBuilder) analysisEngine.defaultCallGraphBuilder();
        CallGraph callGraph = builder.makeCallGraph(builder.getOptions());
        CAstCallGraphUtil.AVOID_DUMP = false;
        CAstCallGraphUtil.dumpCG((SSAContextInterpreter)builder.getContextInterpreter(), builder.getPointerAnalysis(), callGraph);
        SDG<InstanceKey> sdg = new SDG<>(callGraph, builder.getPointerAnalysis(), new PythonModRef(), Slicer.DataDependenceOptions.NO_BASE_NO_HEAP_NO_EXCEPTIONS, Slicer.ControlDependenceOptions.NONE);
        DotUtil.dotify(sdg, null, PDFTypeHierarchy.DOT_FILE, "temp.pdf", "dot");
        System.out.println(getPaths(sdg, sourceFinder(sdg), sinkFinder(sdg)));
    }


    public static <T> Set<List<T>> getPaths(Graph<T> G, EndpointFinder<T> sources, EndpointFinder<T> sinks) {
        Set<List<T>> result = HashSetFactory.make();
        for(T src : G) {
            if (sources.endpoint(src)) {
                BFSPathFinder<T> paths =
                        new BFSPathFinder<T>(G, new NonNullSingletonIterator<T>(src), (Predicate<T>) dst -> sinks.endpoint(dst));
                List<T> path;
                while ((path = paths.find()) != null) {
                    result.add(path);
                }
            }
        }
        return result;
    }

    public static EndpointFinder<Statement> sourceFinder(SDG<InstanceKey> sdg) {

        PointerAnalysis<? super InstanceKey> ptrs = sdg.getPointerAnalysis();
        MethodReference flask =
                MethodReference.findOrCreate(
                        TypeReference.findOrCreate(PythonTypes.pythonLoader, "Lflask"),
                        new Selector(
                                Atom.findOrCreateUnicodeAtom("import"),
                                Descriptor.findOrCreateUTF8("()Lflask;")));
        return (s) -> {
            if (s.getKind() == Statement.Kind.NORMAL) {
                NormalStatement ns = (NormalStatement) s;
                SSAInstruction inst = ns.getInstruction();
                if (inst instanceof SSAGetInstruction) {
                    if(inst.getUse(0)<0){
                        return false;
                    }
                    LocalPointerKey objKey = new LocalPointerKey(ns.getNode(), inst.getUse(0)); // FIXME: getUse=-1
                    OrdinalSet<? super InstanceKey> objs = ptrs.getPointsToSet(objKey);
                    for (Object x : objs) {
                        if (x instanceof AllocationSiteInNode) {
                            AllocationSiteInNode xx = (AllocationSiteInNode) x;
                            if (xx.getNode().getMethod().getReference().equals(flask) &&
                                    xx.getSite().getProgramCounter() == 5) {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        };
    }

    public static EndpointFinder<Statement> sinkFinder(SDG<InstanceKey> sdg) {
        CallGraph CG = sdg.getCallGraph();

        return new EndpointFinder<Statement>() {
            @Override
            public boolean endpoint(Statement s) {
                if (s.getKind()==Statement.Kind.PARAM_CALLER) {
                    CallSiteReference cs = ((ParamCaller)s).getInstruction().getCallSite();
                    for(CGNode callee : CG.getPossibleTargets(s.getNode(), cs)) {
                        if (callee.getMethod().getReference().toString().contains("os/function/system")) {
                            System.out.println(s.toString());
                            return true;
                        }
                    }
                }
                return false;
            }
        };
    }
}

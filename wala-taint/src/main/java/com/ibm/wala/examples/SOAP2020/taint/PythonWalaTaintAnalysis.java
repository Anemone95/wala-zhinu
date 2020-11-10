package com.ibm.wala.examples.SOAP2020.taint;

import com.ibm.wala.cast.python.types.PythonTypes;
import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.AllocationSiteInNode;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.LocalPointerKey;
import com.ibm.wala.ipa.callgraph.propagation.PointerAnalysis;
import com.ibm.wala.ipa.slicer.*;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.types.Descriptor;
import com.ibm.wala.types.MethodReference;
import com.ibm.wala.types.Selector;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.util.intset.OrdinalSet;
import com.ibm.wala.util.strings.Atom;

public class PythonWalaTaintAnalysis extends AbstractPythonWalaTaintAnalysis{

    @Override
    protected EndpointFinder<Statement> sourceFinder(SDG<InstanceKey> sdg) {
        PointerAnalysis<? super InstanceKey> ptrs = builder.getPointerAnalysis();

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

    @Override
    protected EndpointFinder<Statement> sinkFinder(SDG<InstanceKey> sdg) {
        CallGraph CG = builder.getCallGraph();

        return new EndpointFinder<Statement>() {
            @Override
            public boolean endpoint(Statement s) {
                if (s.getKind()==Statement.Kind.PARAM_CALLER) {
                    CallSiteReference cs = ((ParamCaller)s).getInstruction().getCallSite();
                    for(CGNode callee : CG.getPossibleTargets(s.getNode(), cs)) {
                        if (callee.getMethod().getReference().toString().contains("subprocess/function/call")) {
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

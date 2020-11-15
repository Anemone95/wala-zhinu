package top.anemone.wala.taintanalysis;

import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.fixpoint.UnaryOperator;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.Context;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ssa.SSAAbstractInvokeInstruction;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.util.intset.BitVector;
import com.ibm.wala.util.intset.BitVectorIntSet;
import com.ibm.wala.util.intset.OrdinalSetMapping;

public class MyNodeTransfer extends UnaryOperator<BitVectorVariable> {

    private final BasicBlockInContext<IExplodedBasicBlock> node;
    private final OrdinalSetMapping<TaintVar> taintVars;
    private final CallGraph callGraph;

    public MyNodeTransfer(BasicBlockInContext<IExplodedBasicBlock> node, OrdinalSetMapping<TaintVar> vars, CallGraph callGraph){
        this.node=node;
        this.taintVars=vars;
        this.callGraph=callGraph;
    }

    @Override
    public byte evaluate(BitVectorVariable lhs, BitVectorVariable rhs) {
        if (rhs == null) {
            throw new IllegalArgumentException("rhs == null");
        }
        if (lhs == null) {
            throw new IllegalArgumentException("lhs == null");
        }
        IExplodedBasicBlock ebb = node.getDelegate();
        SSAInstruction instruction = ebb.getInstruction();
        CGNode cgNode = node.getNode();
        Context context=cgNode.getContext();
        IMethod method = cgNode.getMethod();

        BitVectorIntSet gen = new BitVectorIntSet();
        BitVectorIntSet kill = new BitVectorIntSet();

        if (instruction != null) {
            boolean isHandled=false;
            if (instruction instanceof SSAGetInstruction){
                // source
                if (instruction.toString().contains("suggestion")){
                    int idx=this.taintVars.add(new TaintVar(instruction.getDef(), context));
                    gen.add(idx);
                    isHandled=true;
                }
            }
            if (instruction instanceof SSAAbstractInvokeInstruction){
                // sink
                String sinkFunc="os/function/system";
                int sinkParam=1;
                if (instruction.getNumberOfUses()-1>=sinkParam){
                    CallSiteReference cs = ((SSAAbstractInvokeInstruction) instruction).getCallSite();
                    for(CGNode callee : this.callGraph.getPossibleTargets(cgNode, cs)) {
                        // sink pattern(os/function/system)
                        TaintVar tVar=new TaintVar(instruction.getUse(sinkParam), context);
                        int idx=this.taintVars.getMappedIndex(tVar);
                        if (callee.getMethod().getReference().toString().contains(sinkFunc)) {
                            System.out.println("Vulnerable");
                        }
                    }
                }
            }
            if (!isHandled){
                for (int i=0;i<instruction.getNumberOfUses();i++){
                    // propogate
                    TaintVar tVar=new TaintVar(instruction.getUse(i), context);
                    if (this.taintVars.hasMappedIndex(tVar)){
                        int idx=this.taintVars.getMappedIndex(tVar);
                        if (rhs.get(idx)){
                            TaintVar nextTaintVar=new TaintVar(instruction.getDef(), context);
                            int newIdx=this.taintVars.add(nextTaintVar);
                            gen.add(newIdx);
                        }
                    }
                }
            }
//            System.out.println(instruction.toString());
        }
        BitVectorVariable U = new BitVectorVariable();
        BitVectorIntSet bv = new BitVectorIntSet();
        if (rhs.getValue() != null) {
            bv.addAll(rhs.getValue());
        }
        bv.removeAll(kill);
        bv.addAll(gen);
        U.addAll(bv.getBitVector());
        if (!lhs.sameValue(U)) {
            lhs.copyState(U);
            return CHANGED;
        } else {
            return NOT_CHANGED;
        }
    }

    @Override
    public int hashCode() {
        return 0;
    }

    @Override
    public boolean equals(Object o) {
        return false;
    }

    @Override
    public String toString() {
        return null;
    }
}

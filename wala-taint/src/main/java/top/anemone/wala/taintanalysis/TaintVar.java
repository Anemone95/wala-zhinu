package top.anemone.wala.taintanalysis;

import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.Context;
import com.ibm.wala.ipa.callgraph.impl.ContextInsensitiveSelector;
import com.ibm.wala.ssa.SSAInstruction;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class TaintVar {
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TaintVar taintVar = (TaintVar) o;
        return varNo == taintVar.varNo &&
                Objects.equals(context, taintVar.context) &&
                Objects.equals(propagateInstructions, taintVar.propagateInstructions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(context, propagateInstructions, varNo);
    }

    final Context context;
    Set<SSAInstruction> propagateInstructions;
    int varNo;

    public TaintVar(int varNo, Context context) {
        this.varNo=varNo;
        this.context=context;
        this.propagateInstructions = new HashSet<>();
    }

}

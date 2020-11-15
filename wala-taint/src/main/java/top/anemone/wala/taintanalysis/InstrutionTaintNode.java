package top.anemone.wala.taintanalysis;

import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.util.collections.Pair;

/**
 * Created by liyc on 9/28/15.
 * js instruction as TaintNode
 */
public class InstrutionTaintNode implements TaintNode {
    public Pair<CGNode, Integer> value;

    public InstrutionTaintNode(Pair<CGNode, Integer> value) {
        this.value = value;
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof InstrutionTaintNode)) return false;
        if (value == null) return ((InstrutionTaintNode) o).value == null;
        return value.equals(((InstrutionTaintNode) o).value);
    }

    public String toString() {
        return String.format("{{instruction:%d|%s|%s}}", value.snd,
                value.fst.getIR().getInstructions()[value.snd],
                value.fst.getMethod().getSignature());
    }

    public SSAInstruction getInstruction() {
        return value.fst.getIR().getInstructions()[value.snd];
    }
}

package top.anemone.wala.taintanalysis;

import com.ibm.wala.types.MethodReference;
import com.ibm.wala.util.collections.Pair;

/**
 * Created by liyc on 9/27/15.
 * local variable in js code as TaintNode
 */
public class LocalTaintNode implements TaintNode {
    public Pair<MethodReference, Integer> value;

    public LocalTaintNode(Pair<MethodReference, Integer> value) {
        this.value = value;
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof LocalTaintNode)) return false;
        if (value == null) return ((LocalTaintNode) o).value == null;
        return value.equals(((LocalTaintNode) o).value);
    }

    public String toString() {
        return String.format("{{local:%d|%s}}", value.snd, value.fst.getSignature());
    }
}

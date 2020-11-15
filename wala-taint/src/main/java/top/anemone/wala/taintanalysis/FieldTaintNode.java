package top.anemone.wala.taintanalysis;

import com.ibm.wala.types.FieldReference;

/**
 * Created by liyc on 9/27/15.
 * HTML/js field as TaintNode
 */
public class FieldTaintNode implements TaintNode {
    public FieldReference value;

    public FieldTaintNode(FieldReference field) {
        value = field;
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof FieldTaintNode)) return false;
        if (value == null) return ((FieldTaintNode) o).value == null;
        return value.equals(((FieldTaintNode) o).value);
    }

    public String toString() {
        return String.format("{{field|%s}}", value.getSignature());
    }
}

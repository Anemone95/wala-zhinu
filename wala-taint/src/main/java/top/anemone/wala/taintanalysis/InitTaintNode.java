package top.anemone.wala.taintanalysis;

/**
 * Created by liyc on 9/28/15.
 * mockSource node and mockSink node
 */
public class InitTaintNode implements TaintNode {
    public String value;
    public InitTaintNode(String value) {
        this.value = value;
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof InitTaintNode)) return false;
        if (value == null) return ((InitTaintNode) o).value == null;
        return value.equals(((InitTaintNode) o).value);
    }

    public String toString() {
        return value;
    }
}

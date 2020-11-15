package top.anemone.wala.taintanalysis;

import java.util.Arrays;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by liyc on 9/27/15.
 * this class represents a source/sink definition in HTML taint analysis
 */
public class SourceSink implements TaintNode {
    public final boolean isSource;
    public final String typeTag;
    private final String[] tags;

    private static final String patternStr = "^[a-zA-Z]* <\\((.*)\\) (.*)> -> _(SOURCE|SINK)_$";
    private static final Pattern pattern = Pattern.compile(patternStr);

    public SourceSink(String typeTag, String[] tags, boolean isSource){
        this.typeTag=typeTag;
        this.tags=tags;
        this.isSource=isSource;
    }

    public SourceSink(String signature) {
        signature = signature.trim();

        Matcher m = pattern.matcher(signature);
        if (m.find()) {
            this.typeTag = m.group(1);
            this.tags = m.group(2).split(",");
            this.isSource = m.group(3).equals("SOURCE");
        }
        else {
            System.err.println("invalid source/sink definition: " + signature);
            this.typeTag = null;
            this.tags = new String[]{};
            this.isSource = true;
        }
    }

    public boolean matches(HashSet<String> matchTags) {
        if (this.tags.length == 0 || matchTags == null)
            return false;
        for (String tag : tags) {
            boolean matched = false;
            for (String matchTag : matchTags) {
                if (matchTag.contains(tag)) {
                    matched = true;
                    break;
                }
            }
            if (!matched) return false;
        }
        return true;
    }

    public boolean isArgs() {
        return "ARGS".equals(this.typeTag);
    }

    public boolean isRet() {
        return "RET".equals(this.typeTag);
    }

    public static void main(String[] args) {
        String line = "HTML <(ARGS) window,console> -> _SINK_";
        Matcher m = pattern.matcher(line);
        if (m.find()) {
            System.out.println(m.group(0));
            System.out.println(m.group(1));
            System.out.println(m.group(2));
            System.out.println(m.group(3));
        }
    }

    @Override
    public String toString() {
        return "SourceSink{" +
                "isSource=" + isSource +
                ", typeTag='" + typeTag + '\'' +
                ", tags=" + Arrays.toString(tags) +
                '}';
    }
}

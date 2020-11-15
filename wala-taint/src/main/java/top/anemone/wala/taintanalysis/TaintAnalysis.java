package top.anemone.wala.taintanalysis;

import com.ibm.wala.cast.ipa.callgraph.CAstCallGraphUtil;
import com.ibm.wala.cast.ir.ssa.AstLexicalAccess;
import com.ibm.wala.cast.ir.ssa.AstLexicalRead;
import com.ibm.wala.cast.js.ssa.JavaScriptInvoke;
import com.ibm.wala.cast.python.client.PythonAnalysisEngine;
import com.ibm.wala.cast.python.loader.PythonLoaderFactory;
import com.ibm.wala.cast.python.ssa.PythonInvokeInstruction;
import com.ibm.wala.cast.python.util.PythonInterpreter;
import com.ibm.wala.classLoader.*;
import com.ibm.wala.dalvik.dex.instructions.GetField;
import com.ibm.wala.dataflow.graph.*;
import com.ibm.wala.examples.drivers.PDFTypeHierarchy;
import com.ibm.wala.fixpoint.BitVectorVariable;
import com.ibm.wala.fixpoint.UnaryOperator;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.impl.Everywhere;
import com.ibm.wala.ipa.callgraph.impl.ExplicitCallGraph;
import com.ibm.wala.ipa.callgraph.propagation.*;
import com.ibm.wala.ipa.cfg.BasicBlockInContext;
import com.ibm.wala.ipa.cfg.ExplodedInterproceduralCFG;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.ssa.*;
import com.ibm.wala.ssa.analysis.IExplodedBasicBlock;
import com.ibm.wala.types.FieldReference;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.WalaException;
import com.ibm.wala.util.collections.HashMapFactory;
import com.ibm.wala.util.collections.ObjectArrayMapping;
import com.ibm.wala.util.collections.Pair;
import com.ibm.wala.util.intset.BitVector;
import com.ibm.wala.util.intset.OrdinalSet;
import com.ibm.wala.util.intset.OrdinalSetMapping;
import com.ibm.wala.viz.DotUtil;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.PrintStream;
import java.util.*;

public class TaintAnalysis {

    /**
     * the exploded interprocedural control-flow graph on which to compute the analysis
     */
    private final ExplodedInterproceduralCFG icfg;

    private final ExplicitCallGraph cg;

    /**
     * for resolving field references in putstatic instructions
     */
    private final IClassHierarchy cha;

    private static final boolean VERBOSE = true;

    private final Map<Pair<CGNode, Integer>, HashSet<String>> invokeInstTags;

    private final OrdinalSetMapping<TaintNode> taintNodeNumbering;

    private final Map<Integer, BitVector> taintNodeChain = HashMapFactory.make();

    private final Collection<SourceSink> sourceSinks;

    private final TaintNode mockSource = new InitTaintNode("mockSource");

    private final TaintNode mockSink = new InitTaintNode("mockSink");
    private final PointerAnalysis<? super InstanceKey> pointerAnalysis;

    public TaintAnalysis(CallGraph cg, Collection<SourceSink> sourceSinks, PointerAnalysis<? super InstanceKey> pointerAnalysis) {
        this.cg = (ExplicitCallGraph) cg;
        this.cha = cg.getClassHierarchy();
        this.enhanceCG();
        this.icfg = ExplodedInterproceduralCFG.make(cg);
        this.sourceSinks = sourceSinks;
        this.invokeInstTags = tagInvokeInsts();
        this.taintNodeNumbering = numberTaintNodes();
        this.pointerAnalysis = pointerAnalysis;
        this.taintInit();
    }
    private static SourceSink sink = new SourceSink("ARGS", new String[]{"os","system"}, false);
    private static SourceSink source = new SourceSink("RET", new String[]{"request","form"}, true);

    public static void main(String[] args) throws ClassNotFoundException, IllegalAccessException, InstantiationException, CancelException, IOException, WalaException {
        Class<?> j3 = Class.forName("com.ibm.wala.cast.python3.loader.Python3LoaderFactory");
        PythonAnalysisEngine.setLoaderFactory((Class<? extends PythonLoaderFactory>) j3);
        Class<?> i3 = Class.forName("com.ibm.wala.cast.python3.util.Python3Interpreter");
        PythonInterpreter.setInterpreter((PythonInterpreter)i3.newInstance());

        String filename="demo.py";
        Collection<Module> src = Collections.singleton(new SourceURLModule(
                TaintAnalysis.class.getClassLoader().getResource(filename)));
        PythonAnalysisEngine<Void> analysisEngine = new PythonAnalysisEngine<Void>() {
            @Override
            public Void performAnalysis(PropagationCallGraphBuilder builder) throws CancelException {
                assert false;
                return null;
            }
        };
        List<SourceSink> sourceSinks=new LinkedList<>();
        sourceSinks.add(source);
        sourceSinks.add(sink);
        analysisEngine.setModuleFiles(src);
        SSAPropagationCallGraphBuilder builder = (SSAPropagationCallGraphBuilder) analysisEngine.defaultCallGraphBuilder();
        CallGraph callGraph = builder.makeCallGraph(builder.getOptions());

        analysisEngine.getPointerAnalysis();
        CAstCallGraphUtil.AVOID_DUMP = false;
        CAstCallGraphUtil.dumpCG((SSAContextInterpreter)builder.getContextInterpreter(), builder.getPointerAnalysis(), callGraph);
        DotUtil.dotify(callGraph, null, PDFTypeHierarchy.DOT_FILE, "callgraph.pdf", "dot");
        TaintAnalysis analysis=new TaintAnalysis(callGraph, sourceSinks,builder.getPointerAnalysis());
        analysis.analyze();
        analysis.dumpResult(System.out);
    }

    private void enhanceCG() {
        // connect taint js to normal js
        Map<Pair<CGNode, CallSiteReference>, IClass> callTargets = new HashMap<>();

        for (CGNode node : this.cg) {
            if (node.getMethod().getSignature().contains("taintjs")) {
                for (SSAInstruction inst : node.getIR().getInstructions()) {
                    if (inst instanceof JavaScriptInvoke) {
                        CallSiteReference callSite = ((JavaScriptInvoke) inst).getCallSite();
                        int numberOftarget = this.cg.getNumberOfTargets(node, callSite);

                        if (numberOftarget == 0) {
                            // missing edge from taint js to normal js
                            // manually add edges
                            int func = ((JavaScriptInvoke) inst).getFunction();
                            HashSet<String> tags = this.getReachingTags(node, func);
                            String tagStr = "";
                            for (String tag : tags) {
                                tagStr += "||";
                                tagStr += tag;
                            }

                            Iterator<IClass> allCls = this.cha.getLoaders()[0].iterateAllClasses();
                            while (allCls.hasNext()) {
                                IClass cls = allCls.next();
                                String clsName = cls.getName().toString();
                                String[] clsNameSegs = clsName.split("/");
                                String clsNameLastSeg = clsNameSegs[clsNameSegs.length - 1];

                                if (clsNameLastSeg.startsWith("LRoot") || clsNameLastSeg.startsWith("Lpreamble") || clsNameLastSeg.startsWith("Lprologue"))
                                    continue;

                                if (tagStr.contains(clsNameLastSeg)) {
                                    callTargets.put(Pair.make(node, callSite), cls);
                                }
                            }
                        }
                    }
                }
            }
        }

        for (Pair site : callTargets.keySet()) {
            ExplicitCallGraph.ExplicitNode enode = (ExplicitCallGraph.ExplicitNode) site.fst;
            CallSiteReference callSite = (CallSiteReference) site.snd;
            IClass tgtCls = callTargets.get(site);

            for (IMethod m : tgtCls.getAllMethods()) {
                try {
                    CGNode tgtNode = this.cg.findOrCreateNode(m, Everywhere.EVERYWHERE);
                    enode.addTarget(callSite, tgtNode);
                } catch (CancelException e) {
                    e.printStackTrace();
                }

            }
        }
    }

    private void taintInit() {
        // sources and sinks
        for (SourceSink sourceSink : this.sourceSinks) {
            if (sourceSink.isSource)
                markNode(sourceSink, mockSource);
            else
                markNode(mockSink, sourceSink);
        }

        // fields
        for (CGNode cgNode : icfg.getCallGraph()) {
            for (SSAInstruction instruction : cgNode.getIR().getInstructions()) {
                if (instruction instanceof SSAFieldAccessInstruction) {
                    FieldReference fr = ((SSAFieldAccessInstruction) instruction).getDeclaredField();
                    HashSet<String> fieldTags = new HashSet<>();
                    fieldTags.add(fr.getSignature());
                    fieldTags.add(fr.getFieldType().toString());

                    TaintNode node = new FieldTaintNode(fr);

                    for (SourceSink sourceSink : this.getMatchedSourceAndSink(fieldTags)) {
                        if (sourceSink.isSource) markNode(node, sourceSink);
                        else markNode(mockSink, sourceSink);
                    }
                }
            }
        }

        for (CGNode cgNode : icfg.getCallGraph()) {
            IMethod method = cgNode.getMethod();
            HashSet<String> methodTags = new HashSet<>();
            methodTags.add(method.getSignature());
//            methodTags.add(method.getDeclaringClass().getReference().toString());

            HashSet<TaintNode> argNodes = new HashSet<>();
            HashSet<TaintNode> retNodes = new HashSet<>();

            icfg.getCallGraph().getEntrypointNodes().add(cgNode);
            int[] paraIds = cgNode.getIR().getSymbolTable().getParameterValueNumbers();
            for (int i : paraIds) {
                TaintNode taintNode = new LocalTaintNode(Pair.make(method.getReference(), i));
                argNodes.add(taintNode);
            }
            // instructions
            IR ir = cgNode.getIR();
            if (ir != null) {
                SSAInstruction[] instructions = ir.getInstructions();
                for (int i = 0; i < instructions.length; i++) {
                    SSAInstruction instruction = instructions[i];
                    // get field
                    if (instruction instanceof SSAGetInstruction){
                        SSAGetInstruction inst=((SSAGetInstruction) instruction);

                        if (inst.toString().contains("suggest")){
                            Pair<CGNode, Integer> instPair = Pair.make(cgNode, i);
                            TaintNode taintNode = new InstrutionTaintNode(instPair);
                            // FIXME 这里flask定义指针分析有问题，getReference只能找到Lflask
                            this.markNode(taintNode, source);
                        }
                        // 正常操作应该通过指针分析的到类
//                        LocalPointerKey objKey = new LocalPointerKey(cgNode, inst.getRef()); // FIXME: getUse=-1
//                        OrdinalSet<? super InstanceKey> objs = this.pointerAnalysis.getPointsToSet(objKey);
//                        for (Object x : objs) {
//                            if (x instanceof AllocationSiteInNode) {
//                                AllocationSiteInNode xx = (AllocationSiteInNode) x;
//                                if (xx.getNode().getMethod().getReference().toString().contains("flask")) {
//                                }
//                            }
//                        }


                        FieldReference f=((SSAGetInstruction) instruction).getDeclaredField();
                        f.getDeclaringClass();
                    }

                    // invokeFunction
                    if (instruction instanceof PythonInvokeInstruction){
                        PythonInvokeInstruction inst = (PythonInvokeInstruction) instruction;

                        LocalPointerKey objKey = new LocalPointerKey(cgNode, inst.getUse(0)); // FIXME: getUse=-1
                        OrdinalSet<? super InstanceKey> objs = this.pointerAnalysis.getPointsToSet(objKey);
                        for (Object x : objs) {
                            if (x instanceof AllocationSiteInNode) {
                                AllocationSiteInNode xx = (AllocationSiteInNode) x;
                                if (xx.getNode().getMethod().getReference().toString().contains("flask")) {
                                }
                            }
                        }
                    }

                    if (instruction instanceof JavaScriptInvoke) {
                        Pair<CGNode, Integer> instPair = Pair.make(cgNode, i);
                        TaintNode taintNode = new InstrutionTaintNode(instPair);
                        HashSet<String> invokeMethodTags = this.invokeInstTags.get(instPair);

                        for (SourceSink sourceSink : this.getMatchedSourceAndSink(invokeMethodTags)) {
                            if (sourceSink.isSource && sourceSink.isRet()) {
                                this.markNode(taintNode, sourceSink);
                            } else if (!sourceSink.isSource && sourceSink.isArgs()) {
                                this.markNode(sourceSink, taintNode);
                            }
                        }
                    } else if (instruction instanceof SSAReturnInstruction) {
                        TaintNode taintNode = new InstrutionTaintNode(Pair.make(cgNode, i));
                        retNodes.add(taintNode);
                    }
                }
            }

            HashSet<SourceSink> methodSourceSinks = this.getMatchedSourceAndSink(methodTags);

            for (SourceSink sourceSink : methodSourceSinks) {
                if (sourceSink.isArgs() && sourceSink.isSource) {
                    for (TaintNode argNode : argNodes) {
                        this.markNode(argNode, sourceSink);
                    }
                }
                else if (sourceSink.isRet() && !sourceSink.isSource) {
                    for (TaintNode retNode : retNodes) {
                        this.markNode(sourceSink, retNode);
                    }
                }
            }

        }

    }

    public void markNode(TaintNode site, TaintNode mark) {
        int siteId = this.taintNodeNumbering.getMappedIndex(site);
        int markId = this.taintNodeNumbering.getMappedIndex(mark);
        markNodeId(siteId, markId);
    }

    public void markNodeId(int siteId, int markId) {
        BitVector bv = this.taintNodeChain.get(siteId);
        if (bv == null) {
            bv = new BitVector();
            this.taintNodeChain.put(siteId, bv);
        }
        bv.set(markId);
    }

    private HashSet<SourceSink> getMatchedSourceAndSink(HashSet<String> tags) {
        HashSet<SourceSink> matchedSourceSinks = new HashSet<>();
        for (SourceSink sourceSink : sourceSinks) {
            if (sourceSink.matches(tags)) matchedSourceSinks.add(sourceSink);
        }
        return matchedSourceSinks;
    }

    // generating a numbering of fields in program
    private OrdinalSetMapping<TaintNode> numberTaintNodes() {
        ArrayList<TaintNode> taintNodes = new ArrayList<>();

        // init
        taintNodes.add(mockSource);
        taintNodes.add(mockSink);

        // sources and sinks
        for (SourceSink sourceSink : this.sourceSinks) {
            taintNodes.add(sourceSink);
        }

        // fields
        for (CGNode cgNode : icfg.getCallGraph()) {
            for (SSAInstruction instruction : cgNode.getIR().getInstructions()) {
                if (instruction instanceof SSAFieldAccessInstruction) {
                    FieldReference fr = ((SSAFieldAccessInstruction) instruction).getDeclaredField();
                    TaintNode node = new FieldTaintNode(fr);
                    taintNodes.add(node);
                }
            }
        }

        // instructions
        for (CGNode node : icfg.getCallGraph()) {
            IR ir = node.getIR();
            if (ir == null) {
                continue;
            }
            SSAInstruction[] instructions = ir.getInstructions();

            for (int i = 0; i < instructions.length; i++) {
                taintNodes.add(new InstrutionTaintNode(Pair.make(node, i)));
            }
        }

        // locals
        for (CGNode node : icfg.getCallGraph()) {
            IMethod m = node.getMethod();
            int maxValueNumber = node.getIR().getSymbolTable().getMaxValueNumber();

            for (int i = 0; i <= maxValueNumber; i++) {
                taintNodes.add(new LocalTaintNode(Pair.make(m.getReference(), i)));
            }
        }

        return new ObjectArrayMapping<>(taintNodes.toArray(new TaintNode[taintNodes.size()]));
    }

    private Map<Pair<CGNode, Integer>, HashSet<String>> tagInvokeInsts() {
        Map<Pair<CGNode, Integer>, HashSet<String>> invokeInstTags = new HashMap<>();

        for (CGNode node : icfg.getCallGraph()) {
            String m = node.getMethod().getDeclaringClass().getName().toString();
            if (m.startsWith("Lprologue.js") || m.startsWith("Lpreamble.js"))
                continue;

            IR ir = node.getIR();
            if (ir == null) continue;

            SSAInstruction[] instructions = ir.getInstructions();
            for (int i = 0; i < instructions.length; i++) {
                SSAInstruction instruction = instructions[i];
                if (instruction instanceof JavaScriptInvoke) {
                    JavaScriptInvoke invokeInst = (JavaScriptInvoke) instruction;
                    Pair<CGNode, Integer> invokeInstItem = Pair.make(node, i);
                    HashSet<String> tags = this.getReachingTags(node, invokeInst);
                    invokeInstTags.put(invokeInstItem, tags);
                }
            }
        }

        return invokeInstTags;
    }

    private HashSet<String> getReachingTags(CGNode node, SSAInstruction inst) {
        HashSet<String> tags = new HashSet<>();
        if (node == null || inst == null) return tags;
//        DefUse du = node.getDU();

        if (inst instanceof JavaScriptInvoke) {
            JavaScriptInvoke invoke_inst = (JavaScriptInvoke) inst;
            tags.addAll(getReachingTags(node, invoke_inst.getFunction()));
        }
        else if (inst instanceof SSANewInstruction) {
            SSANewInstruction new_inst = (SSANewInstruction) inst;
            tags.add(new_inst.getNewSite().toString());
        }
        else if (inst instanceof SSAGetInstruction) {
            SSAGetInstruction get_inst = (SSAGetInstruction) inst;
            FieldReference field = get_inst.getDeclaredField();
            tags.add(field.getSignature());
        }
        else if (inst instanceof AstLexicalRead) {
            for (AstLexicalAccess.Access access : ((AstLexicalRead) inst).getAccesses()) {
                tags.add(access.variableName);
            }
        }
        for (int j = 0; j < inst.getNumberOfUses(); j++) {
            tags.addAll(getReachingTags(node, inst.getUse(j)));
        }

        return tags;
    }

    private HashSet<String> getReachingTags(CGNode node, int reg) {
        SSAInstruction def = node.getDU().getDef(reg);
        if (def != null)
            return getReachingTags(node, def);
        else {
            HashSet<String> tags = new HashSet<>();
            SymbolTable st = node.getIR().getSymbolTable();
            String valueString = st.getValueString(reg);
            tags.add(valueString);
            return tags;
        }
    }

    private class TransferFunctions implements ITransferFunctionProvider<BasicBlockInContext<IExplodedBasicBlock>, BitVectorVariable> {

        /**
         * our meet operator is set union
         */
        @Override
        public AbstractMeetOperator<BitVectorVariable> getMeetOperator() {
            return BitVectorUnion.instance();
        }

        @Override
        public UnaryOperator<BitVectorVariable> getNodeTransferFunction(BasicBlockInContext<IExplodedBasicBlock> node) {
            IExplodedBasicBlock ebb = node.getDelegate();
            SSAInstruction instruction = ebb.getInstruction();
            CGNode cgNode = node.getNode();
            IMethod method = cgNode.getMethod();

            BitVector gen = new BitVector();
            BitVector kill = new BitVector();

            if (instruction != null) {
                int instructionIndex = ebb.getFirstInstructionIndex();

                TaintNode mediatorTaintNode = new InstrutionTaintNode(Pair.make(cgNode, instructionIndex));
                int mediatorTaintNodeId = taintNodeNumbering.getMappedIndex(mediatorTaintNode);

                HashSet<TaintNode> defTaintNodes = new HashSet<>();
                HashSet<TaintNode> useTaintNodes = new HashSet<>();

                for (int i = 0; i < instruction.getNumberOfDefs(); i++)
                    defTaintNodes.add(new LocalTaintNode(Pair.make(method.getReference(), instruction.getDef(i))));
                if (instruction instanceof SSAPutInstruction)
                    defTaintNodes.add(new FieldTaintNode(((SSAPutInstruction) instruction).getDeclaredField()));

                for (int i = 0; i < instruction.getNumberOfUses(); i++)
                    useTaintNodes.add(new LocalTaintNode(Pair.make(method.getReference(), instruction.getUse(i))));
                if (instruction instanceof SSAGetInstruction)
                    useTaintNodes.add(new FieldTaintNode(((SSAGetInstruction) instruction).getDeclaredField()));

                HashSet<Integer> defTaintNodeIds = new HashSet<>();
                HashSet<Integer> useTaintNodeIds = new HashSet<>();
                for (TaintNode taintNode : defTaintNodes) {
                    defTaintNodeIds.add(taintNodeNumbering.getMappedIndex(taintNode));
                }
                for (TaintNode useNode : useTaintNodes) {
                    useTaintNodeIds.add(taintNodeNumbering.getMappedIndex(useNode));
                }

                // Propagation
                for (int useNodeId : useTaintNodeIds) {
                    BitVector useNodeValue = taintNodeChain.get(useNodeId);
                    if (useNodeValue != null)
                        markNodeId(mediatorTaintNodeId, useNodeId);
                }
                BitVector mediatorValue = taintNodeChain.get(mediatorTaintNodeId);
                if (mediatorValue != null) {
                    for (int defNodeId : defTaintNodeIds) {
                        markNodeId(defNodeId, mediatorTaintNodeId);
                        gen.set(defNodeId);
                    }
                }
            }

            Iterator<SSAPhiInstruction> phiInsts = node.iteratePhis();
            while (phiInsts.hasNext()) {
                SSAPhiInstruction phiInst = phiInsts.next();

                TaintNode defTaintNode = new LocalTaintNode(Pair.make(method.getReference(), phiInst.getDef()));
                int defTaintNodeId = taintNodeNumbering.getMappedIndex(defTaintNode);
                HashSet<Integer> useTaintNodeIds = new HashSet<>();

                for (int i = 0; i < phiInst.getNumberOfUses(); i++) {
                    TaintNode useNode = new LocalTaintNode(Pair.make(method.getReference(), phiInst.getUse(i)));
                    useTaintNodeIds.add(taintNodeNumbering.getMappedIndex(useNode));
                }

                // Propagation
                for (int useNodeId : useTaintNodeIds) {
                    BitVector useNodeValue = taintNodeChain.get(useNodeId);
                    if (useNodeValue != null)
                        markNodeId(defTaintNodeId, useNodeId);
                }
                BitVector defTaintValue = taintNodeChain.get(defTaintNodeId);
                if (defTaintValue != null) gen.set(defTaintNodeId);
            }

            return new BitVectorKillGen(kill, gen);
        }

        /**
         * here we need an edge transfer function for call-to-return edges (see
         * {@link #getEdgeTransferFunction(BasicBlockInContext, BasicBlockInContext)})
         */
        @Override
        public boolean hasEdgeTransferFunctions() {
            return true;
        }

        @Override
        public boolean hasNodeTransferFunctions() {
            return true;
        }

        /**
         * for direct call-to-return edges at a call site, the edge transfer function will kill all facts, since we only want to
         * consider facts that arise from going through the callee
         */
        @Override
        public UnaryOperator<BitVectorVariable> getEdgeTransferFunction(BasicBlockInContext<IExplodedBasicBlock> src,
                                                                        BasicBlockInContext<IExplodedBasicBlock> dst) {
            SSAInstruction srcInst = src.getDelegate().getInstruction();
//            SSAInstruction dstInst = dst.getDelegate().getInstruction();

            if (!(srcInst instanceof JavaScriptInvoke) && (src.getNode().equals(dst.getNode()))) {
                // normal edge
                return BitVectorIdentity.instance();
            }

            if (src.getNode().equals(dst.getNode())) {
                // call to return
                return BitVectorIdentity.instance();
            }
            else  {
                if (srcInst instanceof JavaScriptInvoke && dst.isEntryBlock()) {
                    // call to entry
                    int numPara = ((JavaScriptInvoke) srcInst).getNumberOfPositionalParameters();
                    int numMethodPara = dst.getNode().getIR().getNumberOfParameters();
                    if (numPara != numMethodPara && numPara != numMethodPara + 1) {
                        System.err.println("parameter number mismatch!");
                        return BitVectorIdentity.instance();
                    }

                    BitVector gen = new BitVector();
                    for (int i = 0; i < numMethodPara; i++) {
                        int paraSrcId = srcInst.getUse(i);
                        TaintNode paraSrcNode = new LocalTaintNode(Pair.make(src.getMethod().getReference(), paraSrcId));
                        int paraSrcNodeId = taintNodeNumbering.getMappedIndex(paraSrcNode);

                        int paraDstId = dst.getNode().getIR().getSymbolTable().getParameter(i);
                        TaintNode paraDstNode = new LocalTaintNode(Pair.make(dst.getMethod().getReference(), paraDstId));
                        int paraDstNodeId = taintNodeNumbering.getMappedIndex(paraDstNode);

                        BitVector paraSrcNodeValue = taintNodeChain.get(paraSrcNodeId);
                        if (paraSrcNodeValue != null) {
                            markNodeId(paraDstNodeId, paraSrcNodeId);
                            gen.set(paraDstNodeId);
                        }
                    }
                    return new BitVectorKillGen(new BitVector(), gen);
                }
                else if (src.isExitBlock() && !dst.isExitBlock()) {
                    // exit to return
                    BitVector gen = new BitVector();

                    Iterator<BasicBlockInContext<IExplodedBasicBlock>> predNodes = icfg.getPredNodes(dst);

                    while (predNodes.hasNext()) {
                        BasicBlockInContext<IExplodedBasicBlock> predNode = predNodes.next();
//                        if (!icfg.getCallTargets(predNode).contains(src.getNode())) {
//                            continue;
//                        }
                        if (!icfg.hasEdge(predNode, icfg.getEntry(src.getNode()))) {
                            continue;
                        }
                        SSAInstruction invokeInst = predNode.getDelegate().getInstruction();
                        if (invokeInst instanceof JavaScriptInvoke) {
                            int retDstId = invokeInst.getDef();
                            TaintNode retDstNode = new LocalTaintNode(Pair.make(dst.getMethod().getReference(), retDstId));
                            int retDstNodeId = taintNodeNumbering.getMappedIndex(retDstNode);

                            for (SSAInstruction inst : src.getNode().getIR().getInstructions()) {
                                if (inst instanceof SSAReturnInstruction) {
                                    for (int i = 0; i < inst.getNumberOfUses(); i++) {
                                        int retSrcId = inst.getUse(i);
                                        TaintNode retSrcNode = new LocalTaintNode(Pair.make(src.getMethod().getReference(), retSrcId));
                                        int retSrcNodeId = taintNodeNumbering.getMappedIndex(retSrcNode);

                                        BitVector paraSrcNodeValue = taintNodeChain.get(retSrcNodeId);
                                        if (paraSrcNodeValue != null) {
                                            markNodeId(retDstNodeId, retSrcNodeId);
                                            gen.set(retDstNodeId);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    return new BitVectorKillGen(new BitVector(), gen);
                }
            }
            return BitVectorIdentity.instance();
        }
    }

    /**
     * run the analysis
     *
     * @return the solver used for the analysis, which contains the analysis result
     */
    public BitVectorSolver<BasicBlockInContext<IExplodedBasicBlock>> analyze() {
        // the framework describes the dataflow problem, in particular the underlying graph and the transfer functions
        BitVectorFramework<BasicBlockInContext<IExplodedBasicBlock>, TaintNode> framework = new BitVectorFramework<>(
                icfg, new TransferFunctions(), this.taintNodeNumbering);
        BitVectorSolver<BasicBlockInContext<IExplodedBasicBlock>> solver = new BitVectorSolver<>(framework);
        try {
            solver.solve(null);
        } catch (CancelException e) {
            // this shouldn't happen
            assert false;
        }

        if (VERBOSE) {
            this.dumpResult(System.out);
        }
        return solver;
    }

    public HashSet<Integer> getTaintMarks(int site) {
        BitVector bv = taintNodeChain.get(site);
        HashSet<Integer> marks = new HashSet<>();

        if (bv == null) {
            return marks;
        }

        for (int i = 0; i < bv.length(); i++) {
            if (bv.get(i)) {
                marks.add(i);
            }
        }
        return marks;
    }

    public HashSet<Integer> getMarkedSites(int mark) {
        HashSet<Integer> sites = new HashSet<>();

        for (int site : taintNodeChain.keySet()) {
            BitVector marks = taintNodeChain.get(site);
            if (marks != null && marks.get(mark)) sites.add(site);
        }

        return sites;
    }

    public Set<List<Integer>> getTaintPathsFrom(Integer sourceId) {
        HashSet<List<Integer>> paths = new HashSet<>();

        HashSet<Integer> markedSites = this.getMarkedSites(sourceId);

        if (markedSites.isEmpty()) {
            List<Integer> path = new ArrayList<>();
            path.add(sourceId);
            paths.add(path);
        }
        else {
            for (int site : markedSites) {
                Set<List<Integer>> succPaths = getTaintPathsFrom(site);
                for (List<Integer> path : succPaths) {
                    path.add(0, sourceId);
                }
                paths.addAll(succPaths);
            }
        }

        return paths;
    }

    public Set<List<Integer>> getTaintPathsTo(Integer sinkId) {
        HashSet<List<Integer>> paths = new HashSet<>();

        HashSet<Integer> taintMarks = this.getTaintMarks(sinkId);

        if (taintMarks.isEmpty()) {
            List<Integer> path = new ArrayList<>();
            path.add(sinkId);
            paths.add(path);
        }
        else {
            for (int mark : taintMarks) {
                Set<List<Integer>> prevPaths = getTaintPathsTo(mark);
                for (List<Integer> path : prevPaths) {
                    path.add(sinkId);
                }
                paths.addAll(prevPaths);
            }
        }

        return paths;
    }

    private Set<List<Integer>> result = null;
    public Set<List<Integer>> getSource2SinkTaintPaths() {
        if (result != null) return result;
        result = new HashSet<>();

        int sourceNodeId = taintNodeNumbering.getMappedIndex(mockSource);
        int sinkNodeId = taintNodeNumbering.getMappedIndex(mockSink);

        Set<List<Integer>> paths = this.getTaintPathsTo(sinkNodeId);
        for (List<Integer> path : paths) {
            if (path.size() <= 5) continue;
            Integer head = path.get(0);
            Integer tail = path.get(path.size() - 1);
            if (head == sourceNodeId && tail == sinkNodeId) {
                result.add(path);
            }
        }
        return result;
    }

    public final int PATH_FORMAT_NUMBERED = 0;
    public final int PATH_FORMAT_WALA_SSA = 1;
    public final int PATH_FORMAT_TAGGED = 2;
    public String path2String(List<Integer> path, int format) {
        if (format == PATH_FORMAT_NUMBERED) return StringUtils.join(path, " --> ");

        List<TaintNode> nodes = new ArrayList<>();
        for (int nodeId : path) {
            nodes.add(taintNodeNumbering.getMappedObject(nodeId));
        }
        if (format == PATH_FORMAT_WALA_SSA) return StringUtils.join(nodes, " --> ");

        List<String> taggedNodes = new ArrayList<>();
        for (TaintNode taintNode : nodes) {
            String taggedNode = null;

            if (taintNode instanceof SourceSink) {
                taggedNode = taintNode.toString();
            }
            else if (taintNode instanceof InstrutionTaintNode) {
                SSAInstruction inst = ((InstrutionTaintNode) taintNode).getInstruction();
                if (inst instanceof JavaScriptInvoke) {
                    taggedNode = getTagsStr(this.getReachingTags(((InstrutionTaintNode) taintNode).value.fst, inst));
                }
            }
            else if (taintNode instanceof FieldTaintNode) {
                FieldReference field = ((FieldTaintNode) taintNode).value;
                HashSet<String> tags = new HashSet<>();
                tags.add(field.getSignature());
                taggedNode = getTagsStr(tags);
            }

            if (taggedNode != null && taggedNode.length() != 0)
                taggedNodes.add(taggedNode);
        }
        if (format == PATH_FORMAT_TAGGED) return StringUtils.join(taggedNodes, " --> ");

        // by default, return tagged path str
        return StringUtils.join(taggedNodes, " --> ");
    }

    public static String getTagsStr(HashSet<String> tags) {
        HashSet<String> filteredTags = new HashSet<>();
        for (String tag : tags) {
            for (String tagSeg : tag.split(" |\\.|#|:|,")) {
                if (tagSeg.startsWith("LRoot") || tagSeg.startsWith("Lprologue") || tagSeg.length() == 0
                        || tagSeg.startsWith("Lpreamble") || tagSeg.startsWith("__WALA__"))
                    continue;
                filteredTags.add(tagSeg);
            }
        }
        ArrayList<String> filteredTagsList = new ArrayList<>(filteredTags);
        Collections.sort(filteredTagsList);
        return StringUtils.join(filteredTagsList, ',');
    }

    public void dumpResult(PrintStream ps) {
        for (List<Integer> path : this.getSource2SinkTaintPaths()) {
            ps.println("\nsource to sink path:");
            ps.println("numbered path: " + this.path2String(path, PATH_FORMAT_NUMBERED));
            ps.println("wala SSA path: " + this.path2String(path, PATH_FORMAT_WALA_SSA));
            ps.println("tagged path: " + this.path2String(path, PATH_FORMAT_TAGGED));
        }
    }
}

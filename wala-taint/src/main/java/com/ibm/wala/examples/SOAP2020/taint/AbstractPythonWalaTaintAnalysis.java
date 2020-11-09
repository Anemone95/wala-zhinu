package com.ibm.wala.examples.SOAP2020.taint;

import java.io.IOException;
import java.util.Collection;

import com.ibm.wala.cast.ipa.callgraph.AstSSAPropagationCallGraphBuilder;
import com.ibm.wala.cast.python.client.PythonAnalysisEngine;
import com.ibm.wala.cast.python.modref.PythonModRef;
import com.ibm.wala.cast.python.types.PythonTypes;
import com.ibm.wala.classLoader.CallSiteReference;
import com.ibm.wala.classLoader.Module;
import com.ibm.wala.ipa.callgraph.CGNode;
import com.ibm.wala.ipa.callgraph.CallGraph;
import com.ibm.wala.ipa.callgraph.propagation.AllocationSiteInNode;
import com.ibm.wala.ipa.callgraph.propagation.InstanceKey;
import com.ibm.wala.ipa.callgraph.propagation.LocalPointerKey;
import com.ibm.wala.ipa.callgraph.propagation.PointerAnalysis;
import com.ibm.wala.ipa.callgraph.propagation.PropagationCallGraphBuilder;
import com.ibm.wala.ipa.modref.ModRef;
import com.ibm.wala.ipa.slicer.NormalStatement;
import com.ibm.wala.ipa.slicer.ParamCaller;
import com.ibm.wala.ipa.slicer.Statement;
import com.ibm.wala.ssa.SSAGetInstruction;
import com.ibm.wala.ssa.SSAInstruction;
import com.ibm.wala.types.Descriptor;
import com.ibm.wala.types.MethodReference;
import com.ibm.wala.types.Selector;
import com.ibm.wala.types.TypeReference;
import com.ibm.wala.util.CancelException;
import com.ibm.wala.util.WalaException;
import com.ibm.wala.util.intset.OrdinalSet;
import com.ibm.wala.util.strings.Atom;

import magpiebridge.core.AnalysisConsumer;

public abstract class AbstractPythonWalaTaintAnalysis extends WalaTaintAnalysis {
	protected AstSSAPropagationCallGraphBuilder builder;

	@Override
	public String source() {
		return "WALA Python taint";
	}

	@Override
	protected ModRef<InstanceKey> modRef() {
		return new PythonModRef();
	}

	@Override
	protected AstSSAPropagationCallGraphBuilder makeBuilder(Collection<? extends Module> files,
															AnalysisConsumer server) throws WalaException {
		PythonAnalysisEngine<?> E = new PythonAnalysisEngine<Void>() {
			@Override
			public Void performAnalysis(PropagationCallGraphBuilder builder) throws CancelException {
				assert false;
				return null;
			}
		};

		E.setModuleFiles(files);

		try {
			return builder = (AstSSAPropagationCallGraphBuilder) E.defaultCallGraphBuilder();
		} catch (IllegalArgumentException | IOException e) {
			throw new WalaException("WALA error", e);
		}
	}
}
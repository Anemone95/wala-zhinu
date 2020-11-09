package com.ibm.wala.examples.SOAP2020.taint;

import com.ibm.wala.cast.python.client.PythonAnalysisEngine;
import com.ibm.wala.cast.python.loader.PythonLoaderFactory;
import com.ibm.wala.cast.python.util.PythonInterpreter;
import com.ibm.wala.cast.util.SourceBuffer;
import com.ibm.wala.classLoader.Module;
import com.ibm.wala.classLoader.SourceFileModule;
import com.ibm.wala.classLoader.SourceURLModule;
import magpiebridge.core.AnalysisConsumer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;

import static org.junit.Assert.*;

public class PythonWalaTaintAnalysisTest {

    @Before
    public void before() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        Class<?> j3 = Class.forName("com.ibm.wala.cast.python.loader.Python3LoaderFactory");
        PythonAnalysisEngine.setLoaderFactory((Class<? extends PythonLoaderFactory>) j3);
        Class<?> i3 = Class.forName("com.ibm.wala.cast.python.util.Python3Interpreter");
        PythonInterpreter.setInterpreter((PythonInterpreter)i3.newInstance());
    }

    @Test
    public void taintAnalysis(){
        String filename="demo.py";
        Collection<Module> src = Collections.singleton(new SourceURLModule(
                PythonWalaTaintAnalysisTest.class.getClassLoader().getResource(filename)));
        AnalysisConsumer ac = (rs, s) -> {
            System.out.println("results for " + s);
            rs.forEach(r -> {
                try {
                    System.out.println(new SourceBuffer(r.position()));
                } catch (IOException ignored) {

                }
                System.out.println(r.toString(false) + ": " + r.position());
            });
        };
        new PythonWalaTaintAnalysis().analyze(src, ac, false);
    }
}

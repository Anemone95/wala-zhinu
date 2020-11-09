package com.ibm.wala.examples.SOAP2020.taint;

@FunctionalInterface
interface EndpointFinder<T> {
	
	boolean endpoint(T s);
	
}
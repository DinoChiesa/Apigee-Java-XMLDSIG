package com.google.apigee.util;

@FunctionalInterface
public interface ThrowingSideEffect<E extends Exception> {
    public void invoke() throws E;
}

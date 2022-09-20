package com.google.apigee.util;

@FunctionalInterface
public interface ThrowingSupplier<T,E extends Exception> {
    public T get() throws E;
}

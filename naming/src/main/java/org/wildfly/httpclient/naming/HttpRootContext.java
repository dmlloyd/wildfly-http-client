/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.httpclient.naming;

import static java.security.AccessController.doPrivileged;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadLocalRandom;

import javax.naming.Binding;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NameClassPair;
import javax.naming.NamingException;
import javax.net.ssl.SSLContext;

import org.jboss.marshalling.InputStreamByteInput;
import org.jboss.marshalling.Marshaller;
import org.jboss.marshalling.Marshalling;
import org.jboss.marshalling.MarshallingConfiguration;
import org.jboss.marshalling.Unmarshaller;
import org.wildfly.httpclient.common.ContentType;
import org.wildfly.httpclient.common.HttpTargetContext;
import org.wildfly.httpclient.common.WildflyHttpContext;
import org.wildfly.naming.client.AbstractContext;
import org.wildfly.naming.client.CloseableNamingEnumeration;
import org.wildfly.naming.client.ProviderEnvironment;
import org.wildfly.naming.client.util.FastHashtable;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.xnio.IoUtils;
import io.undertow.client.ClientRequest;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.Methods;
import io.undertow.util.StatusCodes;

/**
 * @author Stuart Douglas
 */
public class HttpRootContext extends AbstractContext {

    private static final AuthenticationContextConfigurationClient CLIENT = doPrivileged(AuthenticationContextConfigurationClient.ACTION);
    private final String ACCEPT_VALUE = "application/x-wf-jndi-jbmar-value;version=1,application/x-wf-jbmar-exception;version=1";
    private final ContentType VALUE_TYPE = new ContentType("application/x-wf-jndi-jbmar-value", 1);

    private final HttpNamingProvider httpNamingProvider;
    private final String scheme;

    protected HttpRootContext(FastHashtable<String, Object> environment, HttpNamingProvider httpNamingProvider, String scheme) {
        super(environment);
        this.httpNamingProvider = httpNamingProvider;
        this.scheme = scheme;
    }

    @Override
    public void bind(String name, Object obj) throws NamingException {
        super.bind(name, obj);
    }

    @Override
    protected Object lookupNative(Name name) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/lookup/");
        return processInvocation(name, Methods.POST, providerUri, sb);
    }

    @Override
    protected Object lookupLinkNative(Name name) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/lookuplink/");
        return processInvocation(name, Methods.POST, providerUri, sb);
    }

    @Override
    protected CloseableNamingEnumeration<NameClassPair> listNative(Name name) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/list/");
        Collection<NameClassPair> result = (Collection<NameClassPair>) processInvocation(name, Methods.GET, providerUri, sb);
        return CloseableNamingEnumeration.fromIterable(result);
    }

    @Override
    protected CloseableNamingEnumeration<Binding> listBindingsNative(Name name) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/list-bindings/");
        Collection<Binding> result = (Collection<Binding>) processInvocation(name, Methods.GET, providerUri, sb);
        return CloseableNamingEnumeration.fromIterable(result);
    }

    @Override
    protected void bindNative(Name name, Object obj) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/bind/");
        processInvocation(name, Methods.PUT, providerUri, obj, sb);
    }

    @Override
    protected void rebindNative(Name name, Object obj) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/rebind/");
        processInvocation(name, Methods.PATCH, providerUri, obj, sb);
    }

    @Override
    protected void unbindNative(Name name) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/unbind/");
        processInvocation(name, Methods.PUT, providerUri, sb);
    }

    @Override
    protected void renameNative(Name oldName, Name newName) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/rename/");
        processInvocation(oldName, Methods.PATCH, providerUri, sb, newName);
    }

    @Override
    protected void destroySubcontextNative(Name name) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/rename/");
        processInvocation(name, Methods.PUT, providerUri, sb);
    }

    @Override
    protected Context createSubcontextNative(Name name) throws NamingException {
        URI providerUri = getProviderUri();
        StringBuilder sb = new StringBuilder(providerUri.getPath());
        sb.append("/naming/v1/create-subcontext/");
        processInvocation(name, Methods.PUT, providerUri, null, sb);
        return new HttpRemoteContext(this, name.toString());
    }

    private URI getProviderUri() {
        final List<URI> providerUris = httpNamingProvider.getProviderEnvironment().getProviderUris();
        if (providerUris.size() == 1) {
            return providerUris.get(0);
        } else {
            return providerUris.get(ThreadLocalRandom.current().nextInt(providerUris.size()));
        }
    }

    private MarshallingConfiguration createMarshallingConfig() {
        final MarshallingConfiguration marshallingConfiguration = new MarshallingConfiguration();
        marshallingConfiguration.setVersion(2);
        return marshallingConfiguration;
    }

    private Object processInvocation(Name name, HttpString method, URI providerUri, StringBuilder sb) throws NamingException {
        return processInvocation(name, method, providerUri, sb, (Name) null);
    }

    private Object processInvocation(Name name, HttpString method, URI providerUri, StringBuilder sb, Name newName) throws NamingException {
        try {
            sb.append(URLEncoder.encode(name.toString(), StandardCharsets.UTF_8.name()));
            if (newName != null) {
                sb.append("?new=");
                sb.append(URLEncoder.encode(newName.toString(), StandardCharsets.UTF_8.name()));
            }
        } catch (UnsupportedEncodingException e) {
            NamingException namingException = new NamingException(e.getMessage());
            namingException.initCause(e);
            throw namingException;
        }
        String path = sb.toString();
        final ClientRequest clientRequest = new ClientRequest()
                .setPath(path)
                .setMethod(method);
        clientRequest.getRequestHeaders().put(Headers.ACCEPT, ACCEPT_VALUE);

        final CompletableFuture<Object> result = new CompletableFuture<>();

        final HttpTargetContext targetContext = WildflyHttpContext.getCurrent().getTargetContext(providerUri);
        final ProviderEnvironment providerEnvironment = httpNamingProvider.getProviderEnvironment();
        final AuthenticationContext context = providerEnvironment.getAuthenticationContextSupplier().get();
        AuthenticationContextConfigurationClient client = CLIENT;
        final int defaultPort = providerUri.getScheme().equals("https") ? 443 : 80;
        final AuthenticationConfiguration authenticationConfiguration = client.getAuthenticationConfiguration(providerUri, context, defaultPort, "jndi", "jboss");
        final SSLContext sslContext;
        try {
            sslContext = client.getSSLContext(providerUri, context, "jndi", "jboss");
        } catch (GeneralSecurityException e) {
            final CommunicationException e2 = new CommunicationException(e.toString());
            e2.initCause(e);
            throw e2;
        }
        targetContext.sendRequest(clientRequest, sslContext, authenticationConfiguration, null, (input, response) -> {
            if (response.getResponseCode() == StatusCodes.NO_CONTENT) {
                result.complete(new HttpRemoteContext(HttpRootContext.this, name.toString()));
                IoUtils.safeClose(input);
                return;
            }

            Exception exception = null;
            Object returned = null;
            try {

                final MarshallingConfiguration marshallingConfiguration = createMarshallingConfig();
                final Unmarshaller unmarshaller = targetContext.createUnmarshaller(marshallingConfiguration);
                unmarshaller.start(new InputStreamByteInput(input));
                returned = unmarshaller.readObject();
                // finish unmarshalling
                if (unmarshaller.read() != -1) {
                    exception = HttpNamingClientMessages.MESSAGES.unexpectedDataInResponse();
                }
                unmarshaller.finish();

                if (response.getResponseCode() >= 400) {
                    exception = (Exception) returned;
                }
            } catch (Exception e) {
                exception = e;
            }
            if (exception != null) {
                result.completeExceptionally(exception);
            } else {
                result.complete(returned);
            }
        }, result::completeExceptionally, VALUE_TYPE, null, true);

        try {
            return result.get();
        } catch (InterruptedException e) {
            NamingException namingException = new NamingException(e.getMessage());
            namingException.initCause(e);
            throw namingException;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof NamingException) {
                throw (NamingException) cause;
            } else {
                NamingException namingException = new NamingException();
                namingException.initCause(cause);
                throw namingException;
            }
        }
    }


    private void processInvocation(Name name, HttpString method, URI providerUri, Object object, StringBuilder sb) throws NamingException {
        try {
            sb.append(URLEncoder.encode(name.toString(), StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            NamingException namingException = new NamingException(e.getMessage());
            namingException.initCause(e);
            throw namingException;
        }
        String path = sb.toString();
        final ClientRequest clientRequest = new ClientRequest()
                .setPath(path)
                .setMethod(method);
        clientRequest.getRequestHeaders().put(Headers.ACCEPT, ACCEPT_VALUE);
        if (object != null) {
            clientRequest.getRequestHeaders().put(Headers.CONTENT_TYPE, VALUE_TYPE.toString());
        }
        final CompletableFuture<Object> result = new CompletableFuture<>();

        final HttpTargetContext targetContext = WildflyHttpContext.getCurrent().getTargetContext(providerUri);
        final ProviderEnvironment providerEnvironment = httpNamingProvider.getProviderEnvironment();
        final AuthenticationContext context = providerEnvironment.getAuthenticationContextSupplier().get();
        AuthenticationContextConfigurationClient client = CLIENT;
        final int defaultPort = providerUri.getScheme().equals("https") ? 443 : 80;
        final AuthenticationConfiguration authenticationConfiguration = client.getAuthenticationConfiguration(providerUri, context, defaultPort, "jndi", "jboss");
        final SSLContext sslContext;
        try {
            sslContext = client.getSSLContext(providerUri, context, "jndi", "jboss");
        } catch (GeneralSecurityException e) {
            final CommunicationException e2 = new CommunicationException(e.toString());
            e2.initCause(e);
            throw e2;
        }
        targetContext.sendRequest(clientRequest, sslContext, authenticationConfiguration, output -> {
            if (object != null) {
                Marshaller marshaller = targetContext.createMarshaller(createMarshallingConfig());
                marshaller.start(Marshalling.createByteOutput(output));
                marshaller.writeObject(object);
                marshaller.finish();
            }
            output.close();
        }, (input, response) -> {
            result.complete(null);
        }, result::completeExceptionally, null, null);

        try {
            result.get();
        } catch (InterruptedException e) {
            NamingException namingException = new NamingException(e.getMessage());
            namingException.initCause(e);
            throw namingException;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof NamingException) {
                throw (NamingException) cause;
            } else {
                NamingException namingException = new NamingException();
                namingException.initCause(cause);
                throw namingException;
            }
        }
    }

    @Override
    public void close() throws NamingException {

    }

    @Override
    public String getNameInNamespace() throws NamingException {
        final String scheme = this.scheme;
        return scheme == null || scheme.isEmpty() ? "" : scheme + ":";
    }
}

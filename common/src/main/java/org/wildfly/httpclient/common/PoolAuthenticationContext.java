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

package org.wildfly.httpclient.common;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Locale;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import io.undertow.client.ClientRequest;
import io.undertow.client.ClientResponse;
import io.undertow.security.impl.DigestWWWAuthenticateToken;
import io.undertow.server.session.SecureRandomSessionIdGenerator;
import io.undertow.util.FlexBase64;
import io.undertow.util.HeaderValues;
import io.undertow.util.Headers;
import io.undertow.util.HexConverter;
import io.undertow.util.StatusCodes;
import org.wildfly.security.auth.principal.NamePrincipal;

/**
 * Class that holds authentication information for a connection
 *
 * @author Stuart Douglas
 */
class PoolAuthenticationContext {

    private static final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT;

    static {
        AUTH_CONTEXT_CLIENT = AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
    }

    private volatile Type current;
    private String realm;
    private String domain;
    private String nonce;
    private String opaque;
    private String algorithm;
    private String qop;
    private int nccount = 1;
    private static final SecureRandomSessionIdGenerator cnonceGenerator = new SecureRandomSessionIdGenerator();

    boolean handleResponse(ClientResponse response) {
        if (response.getResponseCode() != StatusCodes.UNAUTHORIZED) {
            return false;
        }
        String authenticate = response.getResponseHeaders().getFirst(Headers.WWW_AUTHENTICATE);
        if (authenticate == null) {
            return false;
        }
        String auth = authenticate.toLowerCase(Locale.ENGLISH);
        if (auth.startsWith("basic ")) {
            current = Type.BASIC;
            return true;
        }
        if (auth.startsWith("digest ")) {
            current = Type.DIGEST;

            Map<DigestWWWAuthenticateToken, String> result = DigestWWWAuthenticateToken.parseHeader(authenticate.substring(7));

            synchronized (this) {
                domain = result.get(DigestWWWAuthenticateToken.DOMAIN);
                nonce = result.get(DigestWWWAuthenticateToken.NONCE);
                opaque = result.get(DigestWWWAuthenticateToken.OPAQUE);
                algorithm = result.get(DigestWWWAuthenticateToken.ALGORITHM);
                String s = result.get(DigestWWWAuthenticateToken.MESSAGE_QOP);
                qop = null;
                if(s != null) {
                    for(String p : s.split(",")) {
                        if(p.equals("auth")) {
                            qop = p;
                        }
                    }
                    if(qop == null) {
                        throw HttpClientMessages.MESSAGES.unsupportedQopInDigest();
                    }
                }
                realm = result.get(DigestWWWAuthenticateToken.REALM);
                nccount = 1;
                if(algorithm.startsWith("\"")) {
                    algorithm = algorithm.substring(1, algorithm.length() - 1);
                }
            }
            return true;

        }
        return false;
    }

    boolean prepareRequest(URI uri, ClientRequest request, AuthenticationConfiguration authenticationConfiguration) {
        if (current == Type.NONE) {
            return false;
        }
        AuthenticationConfiguration config = authenticationConfiguration;
        if (config == null) {
            config = AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, AuthenticationContext.captureCurrent());
        }

        final CallbackHandler callbackHandler = AUTH_CONTEXT_CLIENT.getCallbackHandler(config);

        // TODO: also try credential callback, passing in DIGEST parameters (if any) when DIGEST is in use
        NameCallback nameCallback = new NameCallback("user name");
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        try {
            callbackHandler.handle(new Callback[] { nameCallback, passwordCallback });
        } catch (IOException | UnsupportedCallbackException e) {
            return false;
        }
        final String name = nameCallback.getName();
        if (name == null) {
            return false;
        }
        char[] password = passwordCallback.getPassword();
        if (password == null) {
            return false;
        }
        Principal principal = new NamePrincipal(name);
        if (current == Type.BASIC) {
            String challenge = principal.getName() + ":" + new String(password);
            request.getRequestHeaders().put(Headers.AUTHORIZATION, "Basic " + FlexBase64.encodeString(challenge.getBytes(StandardCharsets.UTF_8), false));
            return true;
        } else if (current == Type.DIGEST) {
            String cnonce = cnonceGenerator.createSessionId();
            String digestUri = null;
            try {
                String path;
                String query;
                int pos = request.getPath().indexOf("?");
                if (pos > 0) {
                    path = request.getPath().substring(0, pos);
                    query = request.getPath().substring(pos + 1);
                } else {
                    path = request.getPath();
                    query = null;
                }
                digestUri = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), path, query, null).toString();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
            synchronized (this) {
                StringBuilder sb = new StringBuilder("Digest username=\"");
                sb.append(principal.getName());
                sb.append("\", uri=\"");
                sb.append(digestUri);
                sb.append("\", realm=\"");
                sb.append(realm);
                sb.append("\"");
                StringBuilder ncBuilder = new StringBuilder();
                if(qop != null) {
                    sb.append(", nc=");
                    String nonceCountString = Integer.toHexString(nccount++);
                    for (int i = nonceCountString.length(); i < 8; ++i) {
                        ncBuilder.append("0"); //must be 8 digits long
                    }
                    ncBuilder.append(nonceCountString);
                    sb.append(ncBuilder.toString());

                    sb.append(", cnonce=\"");
                    sb.append(cnonce);
                    sb.append("\"");
                }
                sb.append(", algorithm=");
                sb.append(algorithm);
                sb.append(", nonce=\"");
                sb.append(nonce);
                sb.append("\", opaque=\"");
                sb.append(opaque);
                sb.append("\", qop=auth"); //TODO: fix this? What do we want to do about auth-int

                //calculate the response
                String a1 = principal.getName() + ":" + realm + ":" + new String(password);
                String a2 = request.getMethod().toString() + ":" + digestUri;

                try {
                    MessageDigest digest = MessageDigest.getInstance(algorithm);
                    digest.update(a1.getBytes(StandardCharsets.UTF_8));
                    byte[] hashedA1 = HexConverter.convertToHexBytes(digest.digest());
                    digest.reset();
                    digest.update(a2.getBytes(StandardCharsets.UTF_8));
                    String hashedA2 = HexConverter.convertToHexString(digest.digest());
                    digest.reset();
                    digest.update(hashedA1);
                    digest.update((byte) ':');
                    digest.update(nonce.getBytes(StandardCharsets.UTF_8));
                    digest.update((byte) ':');
                    if(qop != null) {
                        digest.update(ncBuilder.toString().getBytes(StandardCharsets.UTF_8));
                        digest.update((byte) ':');
                        digest.update(cnonce.getBytes(StandardCharsets.UTF_8));
                        digest.update((byte) ':');
                        digest.update("auth".getBytes(StandardCharsets.UTF_8));
                        digest.update((byte) ':');
                    }
                    digest.update(hashedA2.getBytes(StandardCharsets.UTF_8));
                    sb.append(", response=\"");
                    sb.append(HexConverter.convertToHexString(digest.digest()));
                    sb.append("\"");
                    request.getRequestHeaders().put(Headers.AUTHORIZATION, sb.toString());
                    return true;
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return false;
    }

    boolean isStale(ClientResponse response) {
        if (current != Type.DIGEST) {
            return false;
        }
        if (response.getResponseCode() != StatusCodes.UNAUTHORIZED) {
            return false;
        }
        HeaderValues headers = response.getResponseHeaders().get(Headers.WWW_AUTHENTICATE);
        if(headers == null) {
            return false;
        }
        for(String authenticate : headers) {
            String auth = authenticate.toLowerCase(Locale.ENGLISH);
            if (!auth.startsWith("digest ")) {
                continue;
            }
            Map<DigestWWWAuthenticateToken, String> result = DigestWWWAuthenticateToken.parseHeader(authenticate.substring(7));
            if(result.containsKey(DigestWWWAuthenticateToken.STALE)) {
                return true;
            }
        }
        return false;
    }

    enum Type {
        NONE,
        BASIC,
        DIGEST
    }

}

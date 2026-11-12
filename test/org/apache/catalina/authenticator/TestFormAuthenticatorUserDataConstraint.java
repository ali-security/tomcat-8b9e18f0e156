/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.catalina.authenticator;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.core.StandardContext;
import org.apache.catalina.startup.SimpleHttpClient;
import org.apache.catalina.startup.TesterMapRealm;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.catalina.valves.RemoteIpValve;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.apache.tomcat.util.http.Method;

/*
 * FORM authentication restores the request that triggered the login once the user has authenticated. The request that
 * triggers the restore (usually a GET following the redirect issued after a successful login) may use a different HTTP
 * method than the restored request. The user data constraint (transport guarantee) that applies to the method of the
 * restored request must be enforced even when the method of the request that triggers the restore is not subject to it.
 */
public class TestFormAuthenticatorUserDataConstraint extends TomcatBaseTest {

    private static final String CRLF = SimpleHttpClient.CRLF;

    private static final String USER = "userA";
    private static final String ROLE = "standard";
    private static final String BODY = "action=transfer";


    @Test
    public void testRestoredRequestOverConfidentialTransport() throws Exception {
        SimpleHttpClient client = setupTest();

        // POST /secure over (proxied) https - request is saved and the login form is returned
        requestSecure(client, Method.POST, true);
        Assert.assertEquals(200, client.getStatusCode());
        Assert.assertTrue(client.getResponseBody(), client.getResponseBody().contains("j_security_check"));
        client.resetResponse();

        // Submit login form - receive redirect
        submitFormAuth(client);

        // Follow-up GET over (proxied) https restores the saved POST which meets the transport guarantee
        requestSecure(client, Method.GET, true);
        String body = client.getResponseBody();
        Assert.assertEquals(body, 200, client.getStatusCode());
        Assert.assertEquals(Method.POST + System.lineSeparator() + USER + System.lineSeparator() + "transfer" +
                System.lineSeparator() + "true" + System.lineSeparator(), body);
        client.resetResponse();
    }


    @Test
    public void testRestoredRequestOverNonConfidentialTransport() throws Exception {
        SimpleHttpClient client = setupTest();

        // POST /secure over (proxied) https - request is saved and the login form is returned
        requestSecure(client, Method.POST, true);
        Assert.assertEquals(200, client.getStatusCode());
        Assert.assertTrue(client.getResponseBody(), client.getResponseBody().contains("j_security_check"));
        client.resetResponse();

        // Submit login form - receive redirect
        submitFormAuth(client);

        /*
         * Follow-up GET over plain http. GET /secure is not subject to any constraint but the restored POST /secure
         * requires a confidential transport. The restored POST must not be processed over plain http.
         */
        requestSecure(client, Method.GET, false);
        String body = client.getResponseBody();
        Assert.assertEquals(body, 302, client.getStatusCode());
        Assert.assertNotNull(client.getRedirectUri());
        Assert.assertTrue(client.getRedirectUri(), client.getRedirectUri().startsWith("https://"));
        Assert.assertFalse(body, body.contains("transfer"));
        client.resetResponse();
    }


    private SimpleHttpClient setupTest() throws Exception {
        Tomcat tomcat = getTomcatInstance();

        // Use X-Forwarded-Proto from a (local) reverse proxy to control whether a request is secure
        tomcat.getHost().getPipeline().addValve(new RemoteIpValve());

        // No file system docBase required
        StandardContext ctx = (StandardContext) getProgrammaticRootContext();

        // Add Servlets
        Tomcat.addServlet(ctx, "login", new LoginServlet());
        Tomcat.addServlet(ctx, "error", new ErrorServlet());
        Tomcat.addServlet(ctx, "target", new TargetServlet());
        ctx.addServletMappingDecoded("/login", "login");
        ctx.addServletMappingDecoded("/error", "error");
        ctx.addServletMappingDecoded("/secure", "target");

        // Configure the Realm
        TesterMapRealm realm = new TesterMapRealm();
        realm.addUser(USER, USER);
        realm.addUserRole(USER, ROLE);
        ctx.setRealm(realm);

        // /secure requires authentication and a confidential transport, but only for POST
        SecurityConstraint constraint = new SecurityConstraint();
        SecurityCollection collection = new SecurityCollection();
        collection.addMethod(Method.POST);
        collection.setName("Protect secure");
        collection.addPattern("/secure");
        constraint.addCollection(collection);
        constraint.addAuthRole(ROLE);
        constraint.setUserConstraint("CONFIDENTIAL");
        ctx.addConstraint(constraint);

        // Configure authentication
        LoginConfig lc = new LoginConfig();
        lc.setAuthMethod("FORM");
        lc.setLoginPage("/login");
        lc.setErrorPage("/error");
        ctx.setLoginConfig(lc);
        ctx.getPipeline().addValve(new FormAuthenticator());

        tomcat.start();

        TestHttpClient client = new TestHttpClient();
        client.setPort(getPort());
        client.setUseContentLength(true);
        client.setUseCookies(true);
        client.setRequestPause(0);
        client.connect();

        return client;
    }


    private void submitFormAuth(SimpleHttpClient client) throws Exception {
        client.setRequest(new String[] {
                "POST /j_security_check HTTP/1.1" + CRLF,
                "Host: localhost:" + getPort() + CRLF,
                "X-Forwarded-Proto: https" + CRLF,
                "Cookie: JSESSIONID=" + client.getSessionId() + CRLF,
                "Content-Type: application/x-www-form-urlencoded" + CRLF,
                "Content-Length: " + (23 + USER.length() * 2) + CRLF,
                CRLF,
                "j_username=" + USER + "&j_password=" + USER });
        client.processRequest();
        Assert.assertEquals(303, client.getStatusCode());
        client.resetResponse();
    }


    private void requestSecure(SimpleHttpClient client, String method, boolean confidential) throws Exception {
        String sessionID = client.getSessionId();
        boolean withBody = Method.POST.equals(method);

        client.setRequest(new String[] {
                method + " /secure HTTP/1.1" + CRLF,
                "Host: localhost:" + getPort() + CRLF,
                (confidential ? "X-Forwarded-Proto: https" + CRLF : null),
                "Cookie: " + (sessionID == null ? "a=b" : "JSESSIONID=" + sessionID) + CRLF,
                (withBody ? "Content-Type: application/x-www-form-urlencoded" + CRLF : null),
                (withBody ? "Content-Length: " + BODY.length() + CRLF : null),
                CRLF,
                (withBody ? BODY : null) });
        client.processRequest();
    }


    private static class TestHttpClient extends SimpleHttpClient {

        @Override
        public boolean isResponseBodyOK() {
            return true;
        }
    }


    private static class LoginServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/html");
            resp.setCharacterEncoding(StandardCharsets.UTF_8);
            PrintWriter pw = resp.getWriter();
            pw.println("<html>");
            pw.println("<body>");
            pw.println("<form method=\"post\" action=\"j_security_check\">");
            pw.println("<input name=\"j_username\">");
            pw.println("<input name=\"j_password\" type=\"password\">");
            pw.println("<button type=\"submit\">Login</button>");
            pw.println("</form>");
            pw.println("</body>");
            pw.println("</html>");
        }
    }


    private static class ErrorServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.UTF_8);
            PrintWriter pw = resp.getWriter();
            pw.println("Login failed");
        }
    }


    private static class TargetServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            resp.setContentType("text/plain");
            resp.setCharacterEncoding(StandardCharsets.UTF_8);
            PrintWriter pw = resp.getWriter();
            pw.println(req.getMethod());
            pw.println(req.getRemoteUser());
            pw.println(req.getParameter("action"));
            pw.println(req.isSecure());
        }

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            doGet(req, resp);
        }
    }
}

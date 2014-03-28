package net.tirasa.hippocmssso;

import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.jcr.Credentials;
import javax.jcr.RepositoryException;
import javax.jcr.SimpleCredentials;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.jackrabbit.core.security.AnonymousPrincipal;
import org.apache.jackrabbit.core.security.SystemPrincipal;
import org.apache.jackrabbit.core.security.UserPrincipal;
import org.apache.jackrabbit.core.security.authentication.CredentialsCallback;
import org.apache.jackrabbit.core.security.authentication.RepositoryCallback;
import org.apache.jackrabbit.core.security.authentication.ImpersonationCallback;

import org.hippoecm.repository.jackrabbit.RepositoryImpl;
import org.hippoecm.repository.security.SecurityManager;

public class JAASLoginModule implements LoginModule {

    @SuppressWarnings("unused")
    private static final String SVN_ID = "$Id: $";

    protected Subject subject;

    protected CallbackHandler callbackHandler;

    protected Set<Principal> principals;

    protected boolean validLogin;

    protected boolean allowPreAuthorized = false;

    protected Map<String, ?> sharedState;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        principals = new HashSet<Principal>();
        validLogin = false;
        this.sharedState = sharedState;
        allowPreAuthorized = options.containsKey("preAuthorized");
    }

    @Override
    public boolean login() throws LoginException {
        if (callbackHandler == null) {
            throw new LoginException("No CallbackHandler set");
        }
        List<Callback> callbacks = new LinkedList<Callback>();
        ImpersonationCallback impersonationCallback = new ImpersonationCallback();
        String username = null;
        char[] password = null;
        boolean validCredentials = false;

        callbacks.clear();
        callbacks.add(impersonationCallback);
        try {
            callbackHandler.handle(callbacks.toArray(new Callback[callbacks.size()]));
            Subject impersonator = impersonationCallback.getImpersonator();
            if (impersonator != null) {
                if (!impersonator.getPrincipals(AnonymousPrincipal.class).isEmpty()) {
                    throw new LoginException("Anonymous user is not allowed to impersonate");
                }
                if (impersonator != null && !impersonator.getPrincipals(SystemPrincipal.class).isEmpty()) {
                    principals.add(new SystemPrincipal());
                    return (validLogin = true);
                } else {
                    if (impersonator.getPrincipals(UserPrincipal.class).isEmpty()) {
                        throw new LoginException("Valid user principals required for impersonation");
                    }
                    Principal iup = impersonator.getPrincipals(UserPrincipal.class).iterator().next();
                    String impersonarorId = iup.getName();
                    // TODO: check somehow if the user is allowed to impersonate
                }
                validLogin = true;
            }
        } catch (UnsupportedCallbackException ex) {
        } catch (IOException ex) {
        }

        if (!validCredentials) {
            callbacks.clear();
            CredentialsCallback credentialsCallback = new CredentialsCallback();
            callbacks.add(credentialsCallback);
            try {

                callbackHandler.handle(callbacks.toArray(new Callback[callbacks.size()]));
                Credentials credentials = credentialsCallback.getCredentials();
                if (credentials instanceof SimpleCredentials) {
                    username = ((SimpleCredentials) credentials).getUserID();
                    password = ((SimpleCredentials) credentials).getPassword();
                    validCredentials = true;
                } else {
                    if (allowPreAuthorized) {
                        Object authorizedName = sharedState.get("javax.security.auth.login.name");
                        if (authorizedName instanceof String) {
                            validCredentials = true;
                            validLogin = true;
                            username = (String) authorizedName;
                        } else if (authorizedName instanceof Subject) {
                            validCredentials = true;
                            validLogin = true;
                            // FIXME: get username from subject
                        } else {
                            validLogin = false;
                        }
                    }
                }
            } catch (UnsupportedCallbackException ex) {
            } catch (IOException ex) {
            }
        }

        if (!validCredentials) {
            callbacks.clear();
            NameCallback nameCallback = new NameCallback("username");
            PasswordCallback passwordCallback = new PasswordCallback("password", false);
            callbacks.add(nameCallback);
            callbacks.add(passwordCallback);
            try {
                callbackHandler.handle(callbacks.toArray(new Callback[callbacks.size()]));
                username = nameCallback.getName();
                password = passwordCallback.getPassword();
                if (username != null) {
                    validCredentials = true;
                }
            } catch (UnsupportedCallbackException ex) {
            } catch (IOException ex) {
            }
        }

        callbacks.clear();
        RepositoryCallback repositoryCallback = new RepositoryCallback();
        callbacks.add(repositoryCallback);
        try {
            callbackHandler.handle(callbacks.toArray(new Callback[callbacks.size()]));
            SecurityManager securityManager = null;
            try {
                if (repositoryCallback.getSession() != null) {
                    securityManager = ((SecurityManager) ((RepositoryImpl) repositoryCallback.getSession().
                            getRepository()).getSecurityManager());
                }
            } catch (RepositoryException ex) {
            }
            if (!validLogin) {
                if (username != null) {
                    if (securityManager != null) {
                        if (!securityManager.authenticate(new SimpleCredentials(username, (password == null
                                ? new char[0] : password)))) {
                            throw new LoginException("invalid login");
                        }
                    } else {
                        throw new LoginException("unable to authenticate");
                    }
                }
                validLogin = !principals.isEmpty();
            }
            if (securityManager != null) {
                securityManager.assignPrincipals(principals, username);
                if (username == null) {
                    principals.add(new AnonymousPrincipal());
                } else {
                    principals.add(new UserPrincipal(username));
                }
            }
        } catch (UnsupportedCallbackException ex) {
        } catch (IOException ex) {
        }
        return validLogin;
    }

    public boolean commit() throws LoginException {
        subject.getPrincipals().addAll(principals);
        return validLogin;
    }

    public boolean abort() throws LoginException {
        subject.getPrincipals().removeAll(principals);
        principals.clear();
        return validLogin;
    }

    public boolean logout() throws LoginException {
        subject.getPrincipals().removeAll(principals);
        principals.clear();
        return validLogin;
    }
}

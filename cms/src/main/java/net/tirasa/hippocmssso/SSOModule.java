package net.tirasa.hippocmssso;

import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.hippoecm.frontend.util.WebApplicationHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSOModule implements LoginModule {

    private static final Logger log = LoggerFactory.getLogger(SSOModule.class);

    private final boolean validLogin = true;

    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler,
            final Map<String, ?> sharedState, final Map<String, ?> options) {

        log.debug("Query string {}", WebApplicationHelper.retrieveWebRequest().getQueryString());

        final String sessoinUser = (String) WebApplicationHelper.retrieveWebRequest()
                .getHttpServletRequest().getSession().getAttribute("edu.yale.its.tp.cas.client.filter.receipt");
        
//        final String idFromQuery = WebApplicationHelper.retrieveWebRequest().getQueryString().split("=")[1];
        ((Map<String, String>) sharedState).put("javax.security.auth.login.name",
                sessoinUser.isEmpty() ? "anonymous" : sessoinUser);

        log.debug("Set username with {}", sessoinUser.isEmpty() ? "anonymous" : sessoinUser);
    }

    @Override
    public boolean login() throws LoginException {
        log.debug("LOGIN");
        return validLogin;
    }

    protected String validate(final String key) {
        log.debug("VALIDATE");
        return key;
    }

    @Override
    public boolean commit() throws LoginException {
        log.debug("COMMIT");
        return validLogin;
    }

    @Override
    public boolean abort() throws LoginException {
        log.debug("ABORT");
        return validLogin;
    }

    @Override
    public boolean logout() throws LoginException {
        log.debug("LOGOUT");
        return validLogin;
    }
}

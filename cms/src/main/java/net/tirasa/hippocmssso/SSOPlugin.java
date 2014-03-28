package net.tirasa.hippocmssso;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import javax.jcr.Credentials;
import javax.servlet.http.Cookie;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.wicket.RequestCycle;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.ajax.form.AjaxFormComponentUpdatingBehavior;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.form.DropDownChoice;
import org.apache.wicket.markup.html.panel.FeedbackPanel;
import org.apache.wicket.model.PropertyModel;
import org.apache.wicket.protocol.http.WebRequest;
import org.apache.wicket.protocol.http.WebResponse;

import org.apache.wicket.PageParameters;
import org.hippoecm.frontend.PluginPage;
import org.hippoecm.frontend.model.UserCredentials;
import org.hippoecm.frontend.plugin.IPluginContext;
import org.hippoecm.frontend.plugin.config.IPluginConfig;
import org.hippoecm.frontend.plugins.login.LoginPlugin;
import org.hippoecm.frontend.service.render.RenderPlugin;
import org.hippoecm.frontend.session.LoginException;
import org.hippoecm.frontend.session.PluginUserSession;

public class SSOPlugin extends RenderPlugin implements Credentials {

    private static final long serialVersionUID = 6971843172794119352L;

    private static final Logger log = LoggerFactory.getLogger(SSOPlugin.class);

    @SuppressWarnings("unused")
    private final static String SVN_ID = "$Id$";

    private static final String LOCALE_COOKIE = "loc";

    private DropDownChoice locale;

    public String selectedLocale;

    public SSOPlugin(final IPluginContext context, final IPluginConfig config) throws LoginException {

        super(context, config);
        fromOfficialDocs();

        login();
    }

    private void login() throws LoginException {
        final PluginUserSession userSession = (PluginUserSession) getSession();
        userSession.login(new UserCredentials(this));

        userSession.setLocale(new Locale(selectedLocale));
        userSession.getJcrSession();

        setResponsePage(PluginPage.class, new PageParameters(RequestCycle.get().getRequest().getParameterMap()));
    }

    private void fromOfficialDocs() {
        String[] localeArray = getPluginConfig().getStringArray("locales");
        if (localeArray == null) {
            localeArray = LoginPlugin.LOCALES;
        }
        final List<String> locales = Arrays.asList(localeArray);

        // by default, use the user's browser settings for the locale
        selectedLocale = "en";
        if (locales.contains(getSession().getLocale().getLanguage())) {
            selectedLocale = getSession().getLocale().getLanguage();
        }

        // check if user has previously selected a locale
        Cookie[] cookies = ((WebRequest) RequestCycle.get().getRequest()).getHttpServletRequest().getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (LOCALE_COOKIE.equals(cookie.getName())) {
                    if (locales.contains(cookie.getValue())) {
                        selectedLocale = cookie.getValue();
                        getSession().setLocale(new Locale(selectedLocale));
                    }
                }
            }
        }

        add(locale = new DropDownChoice("locale", new PropertyModel(this, "selectedLocale"), locales));

        locale.add(new AjaxFormComponentUpdatingBehavior("onchange") {

            private static final long serialVersionUID = 1L;

            @Override
            protected void onUpdate(AjaxRequestTarget target) {
                //immediately set the locale when the user changes it
                Cookie localeCookie = new Cookie(LOCALE_COOKIE, selectedLocale);
                localeCookie.setMaxAge(365 * 24 * 3600); // expire one year from now
                ((WebResponse) RequestCycle.get().getResponse()).addCookie(localeCookie);
                getSession().setLocale(new Locale(selectedLocale));
                setResponsePage(this.getFormComponent().getPage());
            }
        });

        add(new FeedbackPanel("feedback").setEscapeModelStrings(false));
        add(new Label("pinger"));
    }
}

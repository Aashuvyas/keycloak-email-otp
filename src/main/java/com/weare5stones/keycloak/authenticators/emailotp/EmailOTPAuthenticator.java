package com.weare5stones.keycloak.authenticators.emailotp;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

public class EmailOTPAuthenticator implements Authenticator {

  private static final Logger logger = Logger.getLogger(EmailOTPAuthenticator.class);

  private static final String TOTP_FORM = "totp-form.ftl";
  private static final String USERNAME_FORM = "login-username.ftl";
  private static final String TOTP_EMAIL = "totp-email.ftl";
  private static final String AUTH_NOTE_CODE = "code";
  private static final String AUTH_NOTE_TTL = "ttl";
  private static final String AUTH_NOTE_REMAINING_RETRIES = "remainingRetries";

  private static final String ALPHA_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz";
  private static final String NUM = "0123456789";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    KeycloakSession session = context.getSession();
    AuthenticationSessionModel authSession = context.getAuthenticationSession();

    // If user is not yet set, prompt for username
    if (context.getUser() == null) {
      context.challenge(context.form().createForm(USERNAME_FORM));
      return;
    }

    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    UserModel user = context.getUser();

    boolean requireVerifiedEmail = Boolean.parseBoolean(config.getConfig()
        .getOrDefault(EmailOTPAuthenticatorFactory.CONFIG_PROP_REQUIRE_VERIFIED_EMAIL, "false"));

    if (requireVerifiedEmail && !user.isEmailVerified()) {
      context.failureChallenge(
          AuthenticationFlowError.INVALID_USER,
          context.form().setError("emailNotVerified").createErrorPage(Response.Status.FORBIDDEN)
      );
      return;
    }

    int ttl = Integer.parseInt(config.getConfig().get(EmailOTPAuthenticatorFactory.CONFIG_PROP_TTL));
    String emailSubject = config.getConfig().get(EmailOTPAuthenticatorFactory.CONFIG_PROP_EMAIL_SUBJECT);
    boolean isSimulation = Boolean.parseBoolean(config.getConfig()
        .getOrDefault(EmailOTPAuthenticatorFactory.CONFIG_PROP_SIMULATION, "false"));

    String code = getCode(config);
    int maxRetries = getMaxRetries(config);

    authSession.setAuthNote(AUTH_NOTE_CODE, code);
    authSession.setAuthNote(AUTH_NOTE_TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
    authSession.setAuthNote(AUTH_NOTE_REMAINING_RETRIES, Integer.toString(maxRetries));

    try {
      RealmModel realm = context.getRealm();

      if (isSimulation) {
        logger.warnf("***** SIMULATION MODE ***** Would send a TOTP email to %s with code: %s", user.getEmail(), code);
      } else {
        String realmName = Strings.isNullOrEmpty(realm.getDisplayName()) ? realm.getName() : realm.getDisplayName();
        List<Object> subjAttr = ImmutableList.of(realmName);
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("code", code);
        attributes.put("ttl", Math.floorDiv(ttl, 60));
        session.getProvider(EmailTemplateProvider.class)
            .setAuthenticationSession(authSession)
            .setRealm(realm)
            .setUser(user)
            .setAttribute("realmName", realmName)
            .send(emailSubject, subjAttr, TOTP_EMAIL, attributes);
      }

      context.challenge(context.form().setAttribute("realm", realm).createForm(TOTP_FORM));
    } catch (Exception e) {
      logger.error("An error occurred when attempting to email a TOTP code:", e);
      context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
          context.form().setError("emailTOTPEmailNotSent", e.getMessage())
              .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();

    // Handle username form submission if user isn't set
    if (context.getUser() == null && formParams.containsKey("username")) {
      String username = formParams.getFirst("username");
      UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

      if (user == null || user.getEmail() == null) {
        context.failureChallenge(AuthenticationFlowError.UNKNOWN_USER,
            context.form().setError("emailOTPUnknownUser").createErrorPage(Response.Status.BAD_REQUEST));
        return;
      }

      context.setUser(user);
      authenticate(context); // Re-run authenticate phase now that user is set
      return;
    }

    String enteredCode = formParams.getFirst("code");
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String code = authSession.getAuthNote(AUTH_NOTE_CODE);
    String ttl = authSession.getAuthNote(AUTH_NOTE_TTL);
    String remainingAttemptsStr = authSession.getAuthNote(AUTH_NOTE_REMAINING_RETRIES);
    int remainingAttempts = remainingAttemptsStr == null ? 0 : Integer.parseInt(remainingAttemptsStr);

    if (code == null || ttl == null) {
      context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
          context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
      return;
    }

    if (enteredCode.equals(code)) {
      if (Long.parseLong(ttl) < System.currentTimeMillis()) {
        context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
            context.form().setError("emailTOTPCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
      } else {
        if (!context.getUser().isEmailVerified()) {
          context.getUser().setEmailVerified(true);
        }
        context.success();
      }
    } else {
      if (remainingAttempts > 0) {
        authSession.setAuthNote(AUTH_NOTE_REMAINING_RETRIES, Integer.toString(remainingAttempts - 1));
        context.failureChallenge(
            AuthenticationFlowError.INVALID_CREDENTIALS,
            context.form()
                .setAttribute("realm", context.getRealm())
                .setError("emailTOTPCodeInvalid", Integer.toString(remainingAttempts))
                .createForm(TOTP_FORM));
      } else {
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
      }
    }
  }

  @Override
  public boolean requiresUser() {
    return false; // because we can prompt for username
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return user.getEmail() != null;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}

  private int getMaxRetries(AuthenticatorConfigModel config) {
    return Integer.parseInt(
        config.getConfig().getOrDefault(EmailOTPAuthenticatorFactory.CONFIG_PROP_MAX_RETRIES, "3"));
  }

  private String getCode(AuthenticatorConfigModel config) {
    int length = Integer.parseInt(config.getConfig().get(EmailOTPAuthenticatorFactory.CONFIG_PROP_LENGTH));
    boolean allowUppercase = Boolean.parseBoolean(
        config.getConfig().getOrDefault(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_UPPERCASE, "true"));
    boolean allowLowercase = Boolean.parseBoolean(
        config.getConfig().getOrDefault(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_LOWERCASE, "true"));
    boolean allowNumbers = Boolean.parseBoolean(
        config.getConfig().getOrDefault(EmailOTPAuthenticatorFactory.CONFIG_PROP_ALLOW_NUMBERS, "true"));

    StringBuilder sb = new StringBuilder();
    if (allowUppercase) sb.append(ALPHA_UPPER);
    if (allowLowercase) sb.append(ALPHA_LOWER);
    if (allowNumbers) sb.append(NUM);

    if (sb.length() == 0) {
      sb.append(ALPHA_UPPER).append(ALPHA_LOWER).append(NUM);
    }

    char[] symbols = sb.toString().toCharArray();
    return SecretGenerator.getInstance().randomString(length, symbols);
  }
}

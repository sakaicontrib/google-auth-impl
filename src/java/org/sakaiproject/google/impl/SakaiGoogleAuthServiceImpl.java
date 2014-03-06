package org.sakaiproject.google.impl;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;


public class SakaiGoogleAuthServiceImpl {
	
	/** Our logger. */
	private static final Log M_log = LogFactory.getLog(SakaiGoogleAuthServiceImpl.class);

	/** Global instance of the HTTP transport. */
	private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();

	/** Global instance of the JSON factory. */
	private static final JsonFactory JSON_FACTORY = new JacksonFactory();
	
	/** Authorizes the service account to access user's protected data. */
	public static GoogleCredential authorize(String userid, String serviceAccountEmail, String privateKey, String scope) {
		return authorize(userid, serviceAccountEmail, privateKey, new String[] {scope});
	}

	/**
	 * Authorizes service account to access user's data for 1 or multiple scopes
	 */
	public static GoogleCredential authorize(String userid, String serviceAccountEmail, String privateKey, String[] scopes) {
		try {
			GoogleCredential credential;
			
			// API 1.5 + requires a collection for scopes
			List<String> scopesCollection = Arrays.asList(scopes);
			if (userid != null && !userid.isEmpty()) {
				// service account credential
				credential = new GoogleCredential.Builder()
						.setTransport(HTTP_TRANSPORT)
						.setJsonFactory(JSON_FACTORY)
						.setServiceAccountId(serviceAccountEmail)
						.setServiceAccountScopes(scopesCollection) // now a collection of strings
						.setServiceAccountPrivateKeyFromP12File(new File(privateKey))
						.setServiceAccountUser(userid).build();

				return credential;
			}

		} catch (IOException e) {
			M_log.error("authorize: " + e.getMessage());
			return null;
		} catch (Exception e) {
			M_log.error("authorize: " + e.getMessage());
			return null;
		}

		return null;
	}
	
}
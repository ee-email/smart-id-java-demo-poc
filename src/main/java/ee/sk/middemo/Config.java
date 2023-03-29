package ee.sk.middemo;

/*-
 * #%L
 * Smart-ID sample Java client
 * %%
 * Copyright (C) 2018 - 2019 SK ID Solutions AS
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * #L%
 */

import ee.sk.middemo.model.UserSidSession;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.SmartIdClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.web.context.WebApplicationContext;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

@Configuration
public class Config {

    @Value("${mid.client.relyingPartyUuid}")
    private String midRelyingPartyUuid;

    @Value("${mid.client.relyingPartyName}")
    private String midRelyingPartyName;

    @Value("${mid.client.applicationProviderHost}")
    private String midApplicationProviderHost;

    @Value("${mid.truststore.trusted-server-ssl-certs.filename}")
    private String midTrustedServerSslCertsFilename;

    @Value("${mid.truststore.trusted-server-ssl-certs.password}")
    private String midTrustedServerSslCertsPassword;

    @Value("${mid.truststore.trusted-root-certs.filename}")
    private String midTrustedRootCertsFilename;

    @Value("${mid.truststore.trusted-root-certs.password}")
    private String midTrustedRootCertsPassword;

    @Bean
    public SmartIdClient mobileIdClient() throws Exception {

        InputStream is = Config.class.getResourceAsStream(midTrustedServerSslCertsFilename);
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(is, midTrustedServerSslCertsPassword.toCharArray());


        // Client setup. Note that these values are demo environment specific.
        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(midRelyingPartyUuid);
        client.setRelyingPartyName(midRelyingPartyName);
        client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v2/");
        client.setTrustStore(trustStore);

        return client;
    }

    @Bean
    @Scope(value = WebApplicationContext.SCOPE_SESSION,
            proxyMode = ScopedProxyMode.TARGET_CLASS)
    public UserSidSession userSessionSigning() {
        return new UserSidSession();
    }

    @Bean
    public AuthenticationResponseValidator midResponseValidator() throws Exception {

        List<X509Certificate> certificates = new ArrayList<>();

        InputStream is = Config.class.getResourceAsStream(midTrustedRootCertsFilename);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, midTrustedRootCertsPassword.toCharArray());
        Enumeration<String> aliases = keystore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
            certificates.add(certificate);
        }

        return new AuthenticationResponseValidator(certificates.toArray(new X509Certificate[0]));
    }

}

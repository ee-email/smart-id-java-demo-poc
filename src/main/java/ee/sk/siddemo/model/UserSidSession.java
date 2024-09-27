package ee.sk.siddemo.model;

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

public class UserSidSession {
    private SigningSessionInfo signingSessionInfo;
    private AuthenticationSessionInfo authenticationSessionInfo;

    public SigningSessionInfo getSigningSessionInfo() {
        return signingSessionInfo;
    }

    public void setSigningSessionInfo(SigningSessionInfo signingSessionInfo) {
        this.signingSessionInfo = signingSessionInfo;
    }

    public AuthenticationSessionInfo getAuthenticationSessionInfo() {
        return authenticationSessionInfo;
    }

    public void setAuthenticationSessionInfo(AuthenticationSessionInfo authenticationSessionInfo) {
        this.authenticationSessionInfo = authenticationSessionInfo;
    }

    public void clearSigningSession() {
        this.signingSessionInfo = null;
    }

    public void clearAuthenticationSessionInfo() {
        this.authenticationSessionInfo = null;
    }

}

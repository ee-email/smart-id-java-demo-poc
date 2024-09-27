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

import java.util.Date;

public class SigningResult {

    private final String result;
    private final Boolean valid;
    private final Date timestamp;
    private final String containerFilePath;

    private SigningResult(Builder builder) {
        this.result = builder.result;
        this.valid = builder.valid;
        this.timestamp = builder.timestamp;
        this.containerFilePath = builder.containerFilePath;
    }

    public String getResult() {
        return result;
    }

    public Boolean getValid() {
        return valid;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public String getContainerFilePath() {
        return containerFilePath;
    }

    public static Builder newBuilder() {
        return new Builder();
    }


    public static class Builder {
        private String result;
        private Boolean valid;
        private Date timestamp;
        private String containerFilePath;

        public Builder withResult(String result) {
            this.result = result;
            return this;
        }

        public Builder withValid(Boolean valid) {
            this.valid = valid;
            return this;
        }

        public Builder withTimestamp(Date timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder withContainerFilePath(String containerFilePath) {
            this.containerFilePath = containerFilePath;
            return this;
        }

        public SigningResult build() {
            return new SigningResult(this);
        }
    }

}

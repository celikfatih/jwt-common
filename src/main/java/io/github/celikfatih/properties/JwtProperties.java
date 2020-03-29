package io.github.celikfatih.properties;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;

/**
 * author @ fati
 * created @ 29.03.2020
 */

@Data
public class JwtProperties {

    @Value("${jwt-common.authentication.url:/login}")
    private String url;

    @Value("${jwt-common.authentication.header:Authorization}")
    private String header;

    @Value("${jwt-common.authentication.token-prefix:Bearer}")
    private String tokenPrefix;

    @Value("${jwt-common.authentication.expiration-time:#{12*60*60}}")
    private String expirationTime;

    @Value("${jwt-common.authentication.secret-key:jwt-common-secret-key}")
    private String secretKey;
}

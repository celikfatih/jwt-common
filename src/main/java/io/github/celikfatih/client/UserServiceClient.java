package io.github.celikfatih.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import static io.github.celikfatih.constants.Constants.GET_USER_URL;

/**
 * author @ fati
 * created @ 29.03.2020
 */

@FeignClient(name = "userServiceClient", url = "${jwt-common.domain.user-service}")
public interface UserServiceClient {

    @GetMapping(value = GET_USER_URL + "/{username}")
    UserDetails getUser(@PathVariable("username") String username);
}

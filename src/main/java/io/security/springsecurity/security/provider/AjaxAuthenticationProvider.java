package io.security.springsecurity.security.provider;

import io.security.springsecurity.security.common.FormWebAuthenticationDetails;
import io.security.springsecurity.security.service.AccountContetxt;
import io.security.springsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

public class AjaxAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        AccountContetxt accountContetxt = (AccountContetxt)userDetailsService.loadUserByUsername(username);

        if(!passwordEncoder.matches(password, accountContetxt.getAccount().getPassword())){
            throw new BadCredentialsException("BadCredentialsException");
        }

        AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(accountContetxt.getAccount(), null, accountContetxt.getAuthorities());

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}

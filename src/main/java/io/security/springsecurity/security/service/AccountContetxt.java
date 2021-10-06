package io.security.springsecurity.security.service;

import io.security.springsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class AccountContetxt extends User {

    private final Account account;

    public AccountContetxt(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }

    public Account getAccount(){
        return account;
    }
}

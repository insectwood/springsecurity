package io.security.springsecurity.repository;

import io.security.springsecurity.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepositoryImpl extends JpaRepository<Account, Long> {
}

package com.LearnJWTSecurity.LearnJWTSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.LearnJWTSecurity.LearnJWTSecurity.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByEmail(username)
        .orElseThrow(() -> new UsernameNotFoundException("User Not Found"));

/*
UserDetailsService adalah interface dari Spring Security untuk mengambil user dari database.
Kode ini mencari user berdasarkan email (sebagai username).
Jika tidak ditemukan, akan melempar
 */

    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
/*
DaoAuthenticationProvider digunakan untuk mengambil user dari database.
setUserDetailsService(userDetailsService()) → Menggunakan UserDetailsService yang sudah dibuat sebelumnya.
setPasswordEncoder(passwordEncoder()) → Menggunakan BCrypt untuk mencocokkan password yang dikirim dengan yang ada di database.
🔹 Tujuan utama: Spring Security akan menggunakan userDetailsService() untuk mencari user dan passwordEncoder() untuk memverifikasi password
 */

    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();

/*
AuthenticationManager bertanggung jawab untuk mengelola autentikasi.
Ini mengambil konfigurasi dari AuthenticationConfiguration yang sudah dikonfigurasi oleh Spring Security
 */

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();

/*
Menggunakan BCryptPasswordEncoder untuk hashing password.
Ketika user login, Spring Security akan:
Mengambil password yang dikirim user.
Membandingkannya dengan password yang sudah di-hash di database menggunakan BCrypt.
✅ Kenapa BCrypt?

Lebih aman dibanding hashing biasa (misal: MD5 atau SHA-256).
Menggunakan salt (random value) untuk mencegah serangan rainbow table.
 */

    }

}

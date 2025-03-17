package com.LearnJWTSecurity.LearnJWTSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf
                        .disable())
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/api/v1/auth/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .sessionManagement(management -> management
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(
                        jwtAuthFilter,
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

/** 
 * 
 * 
 * Kapan SecurityFilterChain Dijalan?
SecurityFilterChain dijalankan sebelum setiap request HTTP diproses oleh aplikasi Spring Boot. Ini terjadi saat permintaan masuk ke server dan sebelum mencapai controller atau endpoint lainnya.
Spring Security bekerja dengan cara memasang filter pada servlet container, sehingga setiap request yang masuk akan melewati filter chain terlebih dahulu sebelum diproses lebih lanjut.

=======================
Bagaimana Proses Eksekusi SecurityFilterChain?
Saat aplikasi Spring Boot dijalankan, konfigurasi keamanan Spring Security diinisialisasi.
Spring Security akan mendaftarkan filter chain berdasarkan SecurityFilterChain yang telah dikonfigurasi.
Ketika ada request masuk ke aplikasi, filter chain akan berjalan secara berurutan untuk menentukan apakah request:
Diizinkan tanpa autentikasi (misalnya permitAll() untuk /api/v1/auth/**).
Harus diautentikasi (misalnya semua request lain authenticated()).
Divalidasi menggunakan JWT melalui JwtAuthenticationFilter.
Jika request membutuhkan autentikasi, maka filter akan mengecek validitas JWT yang dikirim oleh client.
Jika autentikasi berhasil, request akan diteruskan ke controller.
Jika autentikasi gagal, request akan ditolak.

=======================================
Kapan SecurityFilterChain Berjalan dalam Kode Ini?
Di kode SecurityConfiguration kamu, SecurityFilterChain akan berjalan dalam skenario berikut:
Saat ada request ke endpoint /api/v1/auth/**, request akan diizinkan tanpa autentikasi (permitAll()).
Saat ada request ke endpoint lain, request harus melewati autentikasi (authenticated()).
Saat JWT authentication digunakan, JwtAuthenticationFilter akan dijalankan sebelum UsernamePasswordAuthenticationFilter, memastikan bahwa token JWT diverifikasi sebelum request diteruskan.
Spring Security tidak menggunakan sesi (SessionCreationPolicy.STATELESS), sehingga setiap request akan melewati autentikasi ulang tanpa menyimpan status di session.

==================================
Urutan Eksekusi dalam SecurityFilterChain
Request Masuk
→ Diteruskan ke Spring Security Filter Chain.
Pemeriksaan CSRF (http.csrf().disable()) → (diabaikan karena dinonaktifkan).
Pengecekan URL
Jika URL termasuk /api/v1/auth/**, request diizinkan tanpa autentikasi.
Jika URL bukan /api/v1/auth/**, request harus diautentikasi.
Filter JWT dijalankan (JwtAuthenticationFilter)
Jika request memiliki JWT yang valid, request akan diteruskan ke aplikasi.
Jika tidak, request akan ditolak.
Filter Spring Security lainnya (misalnya UsernamePasswordAuthenticationFilter).
Jika lolos semua filter, request diteruskan ke controller.

===================================
Kesimpulan
SecurityFilterChain akan dijalankan sebelum setiap request HTTP diproses oleh aplikasi.
Filter JWT akan berjalan lebih awal untuk menangani autentikasi berbasis token.
Request hanya diteruskan ke controller jika lolos semua filter keamanan.
Setiap request diverifikasi ulang karena session state dinonaktifkan (STATELESS).
 * 
 */

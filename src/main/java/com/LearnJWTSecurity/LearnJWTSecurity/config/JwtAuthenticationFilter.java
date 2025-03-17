package com.LearnJWTSecurity.LearnJWTSecurity.config;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /*
OncePerRequestFilter adalah kelas abstrak dalam Spring Security yang memastikan bahwa sebuah filter hanya dijalankan sekali per request HTTP.

Kesimpulan
OncePerRequestFilter memastikan bahwa filter hanya dijalankan sekali per request, meskipun ada forward atau include.
JwtAuthenticationFilter menggunakannya untuk memproses JWT hanya sekali per request.
Ini membantu mengoptimalkan performa dan menghindari pemrosesan berulang yang tidak perlu. 🚀
     */

    private final JwtService jwtservice;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(

        /*
         Kesimpulan
✅ doFilterInternal() tidak dipanggil langsung dalam SecurityFilterChain, tetapi dipanggil otomatis oleh Spring Security setiap kali ada request yang masuk.
✅ JwtAuthenticationFilter dimasukkan ke dalam filter chain menggunakan addFilterBefore(), sehingga dieksekusi sebelum filter autentikasi username & password.
✅ Spring Security memanggil doFilter() dari OncePerRequestFilter, yang pada akhirnya menjalankan doFilterInternal().
✅ Ini memastikan bahwa setiap request diperiksa untuk JWT sebelum request diteruskan ke filter atau endpoint lain. 🚀
         */

        @NonNull HttpServletRequest request, 
        @NonNull HttpServletResponse response, 
        @NonNull FilterChain filterChain)

        /*
         * Di sini, request, response, dan filterChain berasal dari Spring Security.
doFilterInternal() kemudian dipanggil dengan parameter ini.
         */

        throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

            // Header HTTP yang berisi token JWT biasanya memiliki format seperti ini: 
            // Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNjk5NDA0MDAwLCJleHAiOjE2OTk0MDc2MDB9.XhTskcCvz5HRl5JFGYrP7vR-c6ViT6Jk5R4X0j8w7B8


        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); 
            // filterChain.doFilter(request, response); digunakan untuk 
            // meneruskan request ke filter berikutnya dalam SecurityFilterChain.
            return;
        }
        jwt = authHeader.substring(7); // mengambil jwt setelah tulisan "Bearer "
        userEmail = jwtservice.extractUsername(jwt);

        if (
            userEmail != null 
            && 
            SecurityContextHolder.getContext()
            .getAuthentication() == null) {

/*
* 
========. Periksa Apakah Pengguna Sudah Autentikasi
Cek apakah username dari token ada (userEmail != null).
Cek apakah pengguna sudah login (getAuthentication() == null).
Jika null, berarti belum ada user yang autentikasi.


*/

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

/*
=====================Ambil UserDetails dari Database
 UserDetailsService akan mencari user berdasarkan userEmail.
Jika ditemukan, kita dapat informasi user dari database, seperti:
Username (email)
Password (hashed)
Role (Authority)
 */

            if (jwtservice.isTokenValid(jwt, userDetails)) {
/*
 Memanggil jwtservice.isTokenValid(jwt, userDetails) untuk:
Memeriksa apakah username dalam token sama dengan yang ada di database.
Memeriksa apakah token belum kedaluwarsa.
Jika token valid, maka lanjut ke proses autentikasi.
 */


                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails, 
                    null, 
                    userDetails.getAuthorities()

                    /*
UsernamePasswordAuthenticationToken adalah objek autentikasi Spring Security.
userDetails berisi informasi pengguna dari database.
null berarti tidak ada password yang dikirim (karena sudah dicek di JWT).
userDetails.getAuthorities() memberikan role pengguna.
                     */
            );

            authToken.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)

/*
WebAuthenticationDetailsSource().buildDetails(request) digunakan untuk menyimpan detail tambahan dari request, seperti:
Alamat IP pengguna
Browser atau perangkat yang digunakan
 */

            );

            SecurityContextHolder.getContext().setAuthentication(authToken);

/*
SecurityContextHolder menyimpan informasi autentikasi pengguna.
Setelah diset, Spring Security tahu bahwa pengguna sudah terautentikasi.
 */

            }

        }

        filterChain.doFilter(request, response);
    }

}

/*
 * Hubungan JwtAuthenticationFilter dan SecurityFilterChain
Di Spring Security, SecurityFilterChain adalah konfigurasi utama yang mengatur bagaimana request diproses dan difilter, sementara JwtAuthenticationFilter adalah salah satu filter dalam chain tersebut yang digunakan untuk memvalidasi JWT.

Secara lebih spesifik, JwtAuthenticationFilter dimasukkan ke dalam SecurityFilterChain melalui kode berikut di SecurityConfiguration:

.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

Kode ini memastikan bahwa JwtAuthenticationFilter dijalankan sebelum UsernamePasswordAuthenticationFilter, yang merupakan filter bawaan Spring Security untuk autentikasi berbasis username dan password.

====================================================================================================
Bagaimana JwtAuthenticationFilter Bekerja dalam SecurityFilterChain?
1. SecurityFilterChain Menjalankan Filter
Ketika request masuk ke aplikasi, Spring Security akan memprosesnya melalui filter chain.
SecurityFilterChain memuat berbagai filter, termasuk:
JwtAuthenticationFilter (custom filter untuk JWT)
UsernamePasswordAuthenticationFilter (filter autentikasi username/password default Spring Security)
Filter lainnya (misalnya Exception Handling, CORS, dll.)

2. JwtAuthenticationFilter Mengecek JWT
Ketika SecurityFilterChain memproses request, JwtAuthenticationFilter akan berjalan lebih awal dan melakukan tugas-tugas berikut:
Mengecek apakah request memiliki header Authorization dengan format Bearer Token.
Jika tidak ada token, request langsung diteruskan ke filter selanjutnya.
Jika ada token, JWT diekstrak dan dicek validitasnya menggunakan JwtService.
Jika token valid, JwtAuthenticationFilter akan:
Mengambil informasi pengguna berdasarkan token.
Membuat UsernamePasswordAuthenticationToken untuk autentikasi.
Memasukkan informasi autentikasi ke dalam SecurityContextHolder.

3. SecurityContextHolder Menyimpan Autentikasi
Setelah JwtAuthenticationFilter berhasil mengautentikasi user, informasi user disimpan di SecurityContextHolder.
Filter berikutnya dalam chain bisa mengakses informasi user ini, sehingga tidak perlu login ulang dalam satu request.

4. Filter Lain dalam SecurityFilterChain Berjalan
Setelah JwtAuthenticationFilter selesai, request diteruskan ke filter berikutnya dalam filterChain.doFilter(request, response);, termasuk:
Filter otorisasi → mengecek apakah user memiliki akses ke endpoint yang diminta.
Filter lainnya dalam SecurityFilterChain.

=================================================================
Diagram Alur Eksekusi
1️⃣ Request Masuk
2️⃣ SecurityFilterChain mulai bekerja
3️⃣ JwtAuthenticationFilter dijalankan lebih awal

Mengecek dan memvalidasi JWT
Jika valid, memasukkan autentikasi ke SecurityContextHolder
4️⃣ Filter lainnya dalam SecurityFilterChain berjalan
5️⃣ Request diteruskan ke Controller jika lolos semua filter
6️⃣ Controller mengembalikan response

======================================================================
Kesimpulan
JwtAuthenticationFilter adalah bagian dari SecurityFilterChain yang berfungsi untuk memeriksa dan memvalidasi JWT.
JwtAuthenticationFilter dijalankan sebelum UsernamePasswordAuthenticationFilter, sehingga autentikasi JWT dilakukan lebih awal.
Jika token valid, informasi user dimasukkan ke SecurityContextHolder, sehingga filter lain dalam chain bisa mengenali user tanpa perlu autentikasi ulang.
SecurityFilterChain bertanggung jawab untuk menjalankan semua filter, termasuk JwtAuthenticationFilter.
 */

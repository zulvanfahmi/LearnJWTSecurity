package com.LearnJWTSecurity.LearnJWTSecurity.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/*
 * JwtService yang berfungsi untuk menangani pembuatan, 
 * ekstraksi, dan validasi token JWT di dalam aplikasi 
 * Spring Boot.
 */

@Service
public class JwtService {

    @Value("${secret_key}")
    private String secret_key;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /*
     * Fungsi ini mengambil username (email) dari token JWT.
🔹 Claims::getSubject akan mengambil nilai dari "subject" di dalam payload JWT.
🔹 Menggunakan method extractClaim() untuk mendapatkan klaim tertentu dari token.
     */

    public <T> T extractClaim(
        String token, 
        Function<Claims, T> claimsResolver
        ) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /*
     * Fungsi ini digunakan untuk mengambil klaim tertentu dari token JWT.
🔹 extractAllClaims(token) digunakan untuk mendapatkan seluruh klaim dari token.
🔹 claimsResolver.apply(claims) mengambil klaim tertentu sesuai permintaan.

======================================
Klaim Standar (Default JWT Claims) JWT memiliki beberapa klaim standar yang sering digunakan:

sub (Subject)	claims.getSubject()	Biasanya digunakan sebagai username/email pemilik token.

iss (Issuer)	claims.getIssuer()	Siapa yang menerbitkan token.

aud (Audience)	claims.getAudience()	Untuk siapa token ini dibuat.

iat (Issued At)	claims.getIssuedAt()	Waktu kapan token dibuat.

exp (Expiration)	claims.getExpiration()	Waktu kedaluwarsa token.

nbf (Not Before)	claims.getNotBefore()	Token tidak bisa digunakan sebelum waktu ini.

jti (JWT ID)	claims.getId()	ID unik untuk setiap token.

=============================================================
Klaim Custom (Tambahan) Anda juga bisa menambahkan klaim tambahan saat membuat token, misalnya:

Map<String, Object> extraClaims = new HashMap<>();
extraClaims.put("role", "ADMIN");
extraClaims.put("permissions", List.of("READ", "WRITE"));
     */

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /*
Membuat token JWT tanpa klaim tambahan (hanya username/email).
🔹 Memanggil generateToken(Map<String, Object> extraClaims, UserDetails userDetails).
🔹 Token akan memiliki informasi user tetapi tidak ada tambahan data lain.
     */

    public String generateToken(
        Map<String, Object> extraClaims,
        UserDetails userDetails
    ) {
        return Jwts
        .builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
    }

    /*
Fungsi ini membuat JWT dengan klaim tambahan jika diperlukan.
🔹 Data dalam token:
extraClaims → Data tambahan (jika ada).
subject → User yang memiliki token (biasanya username/email).
issuedAt → Waktu pembuatan token.
expiration → Token valid selama 24 jam.
signWith(getSignInKey(), SignatureAlgorithm.HS256) → Menandatangani token dengan kunci rahasia.
     */

    public boolean isTokenValid(
        String token, 
        UserDetails userDetails) {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);

            /*
Memeriksa apakah token masih valid dengan dua kondisi:
username.equals(userDetails.getUsername()) → Token harus sesuai dengan username.
!isTokenExpired(token) → Token belum kadaluarsa.
             */
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());

/*
 * Memeriksa apakah token sudah kadaluarsa.
🔹 extractExpiration(token) mengambil tanggal kadaluarsa dari token.
🔹 Jika tanggal kadaluarsa lebih kecil dari waktu sekarang → Token sudah expired.
 */
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);

/*
 *  Mengambil tanggal kadaluarsa dari token JWT.
🔹 Menggunakan extractClaim() dengan Claims::getExpiration.
 */
    }

    private Claims extractAllClaims(String token) {
        return Jwts
        .parserBuilder()
        .setSigningKey(getSignInKey())
        .build()
        .parseClaimsJws(token)
        .getBody();

/*
🔹 Menguraikan JWT dan mengambil semua klaim dalam bentuk objek Claims.
🔹 Menggunakan Jwts.parserBuilder() dengan kunci rahasia (getSignInKey())
 */
    }
        
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret_key);
        return Keys.hmacShaKeyFor(keyBytes);

/*
🔹 Mengubah secret_key menjadi Key untuk menandatangani dan memverifikasi JWT.
🔹 Decoders.BASE64.decode(secret_key) → Mengubah string kunci menjadi byte array.
🔹 Keys.hmacShaKeyFor(keyBytes) → Membuat objek Key untuk digunakan dalam signing JWT.
 */
    }

}

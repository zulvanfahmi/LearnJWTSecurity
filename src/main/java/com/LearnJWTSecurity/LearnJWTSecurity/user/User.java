package com.LearnJWTSecurity.LearnJWTSecurity.user;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data 
// @Data syntax package lombok yg digunakan untuk membuat getter setter toString hashCode
@Builder
// @Builder -> Mengaktifkan Builder Pattern, yang memungkinkan pembuatan objek menggunakan metode yang lebih fleksibel dibanding constructor.
@NoArgsConstructor
// noargsconstructor -> Membuat constructor tanpa parameter (default constructor).
@AllArgsConstructor
// allargsconstructor -> Membuat constructor dengan semua parameter sesuai dengan field di dalam class.
@Entity
// entity -> Menandakan bahwa class ini adalah Entity JPA yang akan dipetakan ke tabel dalam database.
@Table(name = "_user")
// table -> Menentukan nama tabel di database.

public class User implements UserDetails {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


}

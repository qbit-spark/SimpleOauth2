package com.kibuti.simplifiedoauth2server.GlobeAuthentication.Entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;


@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter

@Entity
@Table(name = "password_reset_otp_table")
public class PasswordResetOTPEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(name = "otp_code")
    private String otpCode;

    @Column(name = "sent_time")
    private LocalDateTime sentTime;


    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", unique = true)
        private GlobeUserEntity user;

}

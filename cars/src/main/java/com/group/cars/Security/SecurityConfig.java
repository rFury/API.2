package com.group.cars.Security;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;



@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	
	@Autowired
	KeycloakRoleConverter keycloakRoleConverter;
	
	@Bean
	public SecurityFilterChain filterChain (HttpSecurity http) throws Exception
	{
		http.sessionManagement( session -> 
		session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
		.csrf( csrf -> csrf.disable()) 
		
		.cors(cors -> cors.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration cors = new CorsConfiguration();
                cors.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                cors.setAllowedMethods(Collections.singletonList("*"));
                cors.setAllowedHeaders(Collections.singletonList("*"));
                cors.setExposedHeaders(Collections.singletonList("Authorization"));
                
                return cors;
            }
        }))
				
		.authorizeHttpRequests(requests -> requests
		.requestMatchers("/api/All/**").hasAnyAuthority("ADMIN", "USER")
		.requestMatchers(HttpMethod.GET, "/api/getbyid/{id}").hasAnyAuthority("ADMIN", "USER")
		.requestMatchers(HttpMethod.POST, "/api/addCar").hasAuthority("ADMIN")
		.requestMatchers(HttpMethod.PUT, "/api/updateCar").hasAuthority("ADMIN")
		.requestMatchers(HttpMethod.DELETE, "/api/delCar/{id}").hasAuthority("ADMIN")
		.anyRequest().authenticated()
	)	
					 //  .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));
						  .oauth2ResourceServer(rs->rs.jwt(jwt->
									  jwt.jwtAuthenticationConverter(keycloakRoleConverter)));
	   
		
	
	   
   return http.build();
   }
	}

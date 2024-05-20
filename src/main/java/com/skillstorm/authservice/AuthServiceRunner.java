package com.skillstorm.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@EnableDiscoveryClient
@SpringBootApplication
public class AuthServiceRunner {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceRunner.class, args);
	}

}

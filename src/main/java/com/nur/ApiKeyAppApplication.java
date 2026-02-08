package com.nur;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@ConfigurationPropertiesScan
@SpringBootApplication
public class ApiKeyAppApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiKeyAppApplication.class, args);
	}

}

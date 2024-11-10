package com.group.cars;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;

import com.group.cars.Crtlers.CarRestController;
import com.group.cars.Entities.Car;
import com.group.cars.Repositories.CarRepository;
import com.group.cars.Repositories.FGRepository;

@SpringBootApplication
public class CarsApplication implements CommandLineRunner{
	@Autowired
	CarRepository carRepository;
	@Autowired
	FGRepository FGRepository;

	@Autowired
	RepositoryRestConfiguration RespositoryRestConfiguration ;

	public static void main(String[] args) {
		SpringApplication.run(CarsApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		this.RespositoryRestConfiguration.exposeIdsFor(Car.class);
	}

}

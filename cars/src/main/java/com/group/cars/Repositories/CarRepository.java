package com.group.cars.Repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import com.group.cars.Entities.Car;
import com.group.cars.Entities.Family_Group;

@RepositoryRestResource(path = "Rest")
public interface CarRepository extends JpaRepository<Car, Long> {

    List<Car> findByCarModel(String carModel);

    List<Car> findByCarModelContains(String carModel);

    @Query("select c from Car c where c.carModel like %:carModel and c.price > :price")
    List<Car> findByCarModelPrice(@Param("carModel") String carModel, @Param("price") Double price);

    @Query("select c from Car c where c.familyGroup = :familyGroup")
    List<Car> findByFamilyGroup(Family_Group familyGroup);

    List<Car> findByFamilyGroupId(Long id);

    List<Car> findByOrderByCarModelAsc();

    @Query("select c from Car c order by c.carModel ASC, c.price DESC")
    List<Car> sortCarsByModelPrice();

}

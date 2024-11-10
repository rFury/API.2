package com.group.cars.Services;

import java.util.List;

import org.springframework.data.domain.Page;

import com.group.cars.Entities.Car;
import com.group.cars.Entities.Family_Group;

public interface carServices {
    Car saveCar(Car p);
    Car updateCar(Car p);
    void deleteCar(Car p);
    void deleteCarById(Long id);
    Car getCar(Long id);
    List<Car> getAllCars();
    Page<Car> getAllCarPP(int page, int size);
    List<Car> findByCarModel(String carModel);
    List<Car> findByCarModelContains(String carModel);
    List<Car> findByCarModelPrice(String carModel, Double price);
    List<Car> findByFamilyGroup(Family_Group FG);
    List<Car> findByFamilyGroupId(Long id);
    List<Car> findByOrderByCarModelAsc();
    List<Car> sortCarsByModelPrice();
    public List<Family_Group> getAllFG();
    public Family_Group saveFG(Family_Group FG);

}

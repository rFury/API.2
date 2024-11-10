package com.group.cars.Services;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.group.cars.Entities.Car;
import com.group.cars.Entities.Family_Group;
import com.group.cars.Repositories.CarRepository;
import com.group.cars.Repositories.FGRepository;

@Service
public class carServicesImpl implements carServices {
    @Autowired
    CarRepository carRepository ;

    @Autowired
    FGRepository fgRepository;

    @Override
    public Car saveCar(Car c) {
        return carRepository.save(c);
    }

    @Override
    public Car updateCar(Car c) {
        return carRepository.save(c);
    }

    @Override
    public void deleteCar(Car c) {
        carRepository.delete(c);
    }

    @Override
    public void deleteCarById(Long id) {
        carRepository.deleteById(id);;
    }

    @Override
    public Car getCar(Long id) {
        return carRepository.findById(id).get();
    }

    @Override
    public List<Car> getAllCars() {
        return carRepository.findAll();
    }

    @Override
    public Page<Car> getAllCarPP(int page, int size) {
        return carRepository.findAll(PageRequest.of(page, size));
    }

    @Override
    public List<Car> findByCarModel(String carModel) {
        return carRepository.findByCarModel(carModel);
    }

    @Override
    public List<Car> findByCarModelContains(String carModel) {
        return carRepository.findByCarModelContains(carModel);
    }

    @Override
    public List<Car> findByCarModelPrice(String carModel, Double price) {
        return carRepository.findByCarModelPrice(carModel, price);
    }

    @Override
    public List<Car> findByFamilyGroup(Family_Group familyGroup) {
        return carRepository.findByFamilyGroup(familyGroup);
    }

    @Override
    public List<Car> findByFamilyGroupId(Long id) {
        return carRepository.findByFamilyGroupId(id);
    }

    @Override
    public List<Car> findByOrderByCarModelAsc() {
        return carRepository.findByOrderByCarModelAsc();
    }

    @Override
    public List<Car> sortCarsByModelPrice() {
        return carRepository.sortCarsByModelPrice();
    }

    @Override
    public List<Family_Group> getAllFG(){
        return fgRepository.findAll();
    }
    
    @Override
    public Family_Group saveFG(Family_Group FG) {
        return fgRepository.save(FG);
    }
}

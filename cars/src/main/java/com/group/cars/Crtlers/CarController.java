package com.group.cars.Crtlers;

import java.text.ParseException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.group.cars.Entities.Car;
import com.group.cars.Services.carServices;

@Controller
public class CarController {

    @Autowired
    carServices carServices;

    @RequestMapping("/All")
    public String listeCars(ModelMap modelMap,
    @RequestParam(name="page", defaultValue = "0") int page,
    @RequestParam(name="size", defaultValue = "5") int size){
        Page<Car> Cars = carServices.getAllCarPP(page, size);
        modelMap.addAttribute("Cars", Cars.getContent());
        modelMap.addAttribute("pages", new int[Cars.getTotalPages()]);
        modelMap.addAttribute("currentPage", page);
    
        return "Car/Cars";
    }
    

    @RequestMapping("/showCreate")
    public String showCreate() {
        return "createCar";
    }

    @RequestMapping("/saveCar")
    public String saveCar(@ModelAttribute("Car") Car Car,ModelMap modelMap) throws ParseException {

        Car saveCar = carServices.saveCar(Car);
        String msg = "Car enregistré avec Id " + saveCar.getCarID();
        modelMap.addAttribute("msg", msg);
        return "createCar";
    }

    @RequestMapping("/supprimerCar")
    public String supprimerCar(@RequestParam("id") Long id,
            ModelMap modelMap,    
            @RequestParam (name="page",defaultValue = "0") int page,
            @RequestParam (name="size", defaultValue = "5") int size) {
        carServices.deleteCarById(id);
        Page<Car> Cars = carServices.getAllCarPP(size,page);
        modelMap.addAttribute("Cars", Cars);
        modelMap.addAttribute("pages", Cars.getTotalPages());
        modelMap.addAttribute("currentPage", page);
        return "Car/Cars";
    }

    @RequestMapping("/modifierCar")
    public String editerCar(@RequestParam("id") Long id,
            ModelMap modelMap) {
        Car p = carServices.getCar(id);
        modelMap.addAttribute("Car", p);
        return "editerCar";
    }

    @RequestMapping("/updateCar")
    public String updateCar(@ModelAttribute("Car") Car Car,
            ModelMap modelMap) throws ParseException {

        carServices.updateCar(Car);
        List<Car> Cars = carServices.getAllCars();
        modelMap.addAttribute("Cars", Cars);
        return "Car/Cars";
    }

}

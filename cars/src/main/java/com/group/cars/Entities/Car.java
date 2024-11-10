package com.group.cars.Entities;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Data
@Entity
@Table(name = "cars")
public class Car{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name= "Car_Id")
    private Long carID;
    
    @Column(name = "car_Model")
    private String carModel;
    
    @Column(name = "car_Brand")
    private String carBrand;
    
    private double price;
    
    @ManyToOne
    @JoinColumn(name = "family_group_group_id")
    private Family_Group familyGroup;

    public Car() {
    }

    public Car(Long carID,String carModel, String carBrand, double price,Family_Group fg) {
        this.carModel = carModel;
        this.carBrand = carBrand;
        this.price = price;
        this.setFamilyGroup(fg);
    }
    public Car(String carModel, String carBrand, double price,Family_Group fg) {
        this.carModel = carModel;
        this.carBrand = carBrand;
        this.price = price;
        this.setFamilyGroup(fg);
    }
    public Car(String carModel, String carBrand, double price) {
        this.carModel = carModel;
        this.carBrand = carBrand;
        this.price = price;
    }
}

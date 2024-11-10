package com.group.cars.Repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.group.cars.Entities.Family_Group;

public interface FGRepository extends JpaRepository<Family_Group,Long>{
    
}

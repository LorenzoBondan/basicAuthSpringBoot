package com.metaway.basicauth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/employees")
public class Controller {

    @GetMapping
    public ResponseEntity<List<Employee>> employeeDetails(){
        List<Employee> employeeList = new ArrayList<>();
        employeeList.add(new Employee("suraj",30));
        employeeList.add(new Employee("onkar",25));
        return ResponseEntity.ok(employeeList);
    }
}

package com.xpresspayments.GTCollection.gt_collections.api;



import com.xpresspayments.GTCollection.gt_collections.model.Validation;
import com.xpresspayments.GTCollection.gt_collections.services.ValidationServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


import java.util.List;
import java.util.Map;

@RestController
public class ValidationController {



@Autowired
ValidationServices validationServices;


    @GetMapping("/payment")
    public List<Validation> index(){
        return validationServices.findAll();
    }



    //@PostMapping("/paymentValidation")

   @RequestMapping(value = "/paymentValidation", method = RequestMethod.POST)

    public List<Validation> search(@RequestBody Map<String, String> body){
        String searchTerm = body.get("text");
        return validationServices.findBytitle(searchTerm);
    }
}

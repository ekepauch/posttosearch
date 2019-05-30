package com.xpresspayments.GTCollection.gt_collections.services;

import com.xpresspayments.GTCollection.gt_collections.model.Validation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


import java.util.List;

@Repository
public interface ValidationServices extends JpaRepository<Validation,Long> {

    List<Validation> findBytitle(String text);

}

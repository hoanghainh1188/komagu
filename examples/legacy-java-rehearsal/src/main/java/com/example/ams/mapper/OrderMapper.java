package com.example.ams.mapper;

import com.example.ams.model.Order;
import java.util.List;
import org.apache.ibatis.annotations.Param;

public interface OrderMapper {
    List<Order> listMine(@Param("ownerId") long ownerId, @Param("sort") String sort);
}

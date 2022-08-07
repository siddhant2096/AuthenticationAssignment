package com.bootcamp.bookshop.book;

import com.bootcamp.bookshop.money.Money;
import lombok.*;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class BookResponse {
    private Long id;
    private String name;
    private String authorName;
    private Money price;
}

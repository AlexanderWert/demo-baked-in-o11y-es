package co.elastic.demo.bakedInO11y;

import lombok.*;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class Doc {
    private String message;
    private Date date;
    private String user;
}

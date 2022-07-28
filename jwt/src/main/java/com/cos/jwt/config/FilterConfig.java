package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> myFilter1(){
        FilterRegistrationBean<MyFilter1> myFilterbean = new FilterRegistrationBean<>(new MyFilter1());
        myFilterbean.addUrlPatterns("/*");
        //낮은 번호가 필터 중에서 가장 먼저 실행된다.
        myFilterbean.setOrder(0);
        return myFilterbean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> myFilter2(){
        FilterRegistrationBean<MyFilter2> myFilterbean2 = new FilterRegistrationBean<>(new MyFilter2());
        myFilterbean2.addUrlPatterns("/*");
        //낮은 번호가 필터 중에서 가장 먼저 실행된다.
        myFilterbean2.setOrder(1);
        return myFilterbean2;
    }
}

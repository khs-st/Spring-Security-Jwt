package com.cos.jwt.filter;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        //토큰 : cors
        //아이디, 패스워드 정상적으로 입력 후 로그인 완료
        //로그인 완료 후 토큰 만들어주고 응답 처리
        //요청할 때마다 header에 Authorization에 value 값으로 토큰 가져온다.
        //그 때 토큰 값이 넘어오면 내가 만든 토큰이 맞는지 검증 가능(RSA, HS256)
        if(req.getMethod().equals("POST")){
            log.info("POST 요청됨");
            String headerAuth=req.getHeader("Authorization");
            log.info(headerAuth);

            if(headerAuth.equals("cors")){
                filterChain.doFilter(req,res);
            }else{
                log.info("인증되지않음");
            }
        }
    }
}

package com.cos.jwt.config.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//login 요청하여 userName, password 전송(post) 시
// UsernamePasswordAuthenticationFilter 필터 동작
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    
    //login 요청 시 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("authenticationManager 로그인 시도 중");

        //1. username, password 받아서

        //2. 정상인지 로그인 시도 -> authenticationManager로 로그인 시도
        //3. 시도 하면 PrincipalDetailsService가 호출 -> loadUserByUsername()이 실행
    
        //4. PrincipalDetails를 세션이 담는다. (세션에 담는 이유: 권한 관리를 위해서)
        //5. JWT 토큰을 만들어 응답하면 된다.
        return super.attemptAuthentication(request, response);
    }
}

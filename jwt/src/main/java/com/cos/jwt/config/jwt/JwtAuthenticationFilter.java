package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

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
        log.info("JwtAuthenticationFilter 로그인 시도 중");
        try {
//            BufferdReader로 확인
//            BufferedReader br = request.getReader();
//            String input=null;
//
//            while ((input=br.readLine())!=null){
//                log.info(input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            log.info("ObjectMapper로 만든 user: " + user);

            //토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            log.info("authenticationToken: " + authenticationToken);

            //2. 정상인지 로그인 시도 -> authenticationManager로 로그인 시도
            //PrincipalDetailsService의 loadUserByUsername() 함수가 실행된다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            log.info("authentication의 user: " + authentication);

            //3. 시도 하면 PrincipalDetailsService가 호출 -> loadUserByUsername()이 실행
            //4. PrincipalDetails를 세션이 담는다. (세션에 담는 이유: 권한 관리를 위해서)
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            log.info("principalDetails의 userName: " + principalDetails.getUsername());

            //5. JWT 토큰을 만들어 응답하면 된다.
            //authentication 객체가 session 영역에 저장된다. => 로그인 되었다는 의미다.
            //return 하는 이유 => 권한 관리를 security가 대신 해주기 때문에 편리성으로 한다.
            //Jwt 토큰 사용하며 세션 만들 이유가 없다. => 사용이유는 권한처리 때문에 session에 넣어준다.
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    //attemptAuthentication 인증이 정상적으로 완료되었다면 successfulAuthentication 실행
    //Jwt 토큰을 만들어서 request한 사용자에게 Jwt 토큰을 response해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("인증완료 !!!! successfulAuthentication 실행됨");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();


        //유저네임, 패스워드 로그인 정상
        //서버쪽 세션ID 생성
        //클라이언트 쿠키 세션ID를 응답
        //요청할 때마다 쿠키값과 세션ID를 항상 들고 서버에 요청하기 때문에
        //서버는 세션ID가 유효한지 판단해서 유효하다면 인증이 필요한 페이지로 접근하게 한다.

        //위 방식이 아닌 JWT 토큰을 생성하여 클라이언트 쪽으로 JWT 토큰을 응답
        //요청할 때마다 JWT 토큰을 가지고 요청
        //서버는 JWT 토큰이 유효한지를 판단(필터 생성 필요)

        //RSA 방식이 아니라 Hash 암호 방식
        String jwtToken = JWT.create()
                .withSubject("cors토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING,JwtProperties.TOKEN_PREFIX + jwtToken);
    }


}

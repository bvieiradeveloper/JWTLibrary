package br.com.bvieira.core.dto;

public record AnyResponse(String status, Integer code, AuthUserResponse authUser){
}

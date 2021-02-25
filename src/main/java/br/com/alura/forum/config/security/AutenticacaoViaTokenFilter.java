package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;

public class AutenticacaoViaTokenFilter extends OncePerRequestFilter{
	
	
	private TokenService tokenSerive;
	
	private UsuarioRepository repository;
	
	public AutenticacaoViaTokenFilter(TokenService tokenSerive, UsuarioRepository repository) {
		this.tokenSerive = tokenSerive;
		this.repository = repository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String token = recuperarToken(request);
		boolean valido = tokenSerive.isTokenValido(token);
		
		if(valido) {
			autenticaCliente(token);
		}
		
		filterChain.doFilter(request, response);
		
	}

	private void autenticaCliente(String token) {
		Long idUsuario = tokenSerive.getIdUsuario(token);
		Usuario usuario = repository.findById(idUsuario).get();
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
	}

	private String recuperarToken(HttpServletRequest request) {
		String token = request.getHeader("Authorization");
		if(token == null || token.isEmpty() || !token.startsWith("Bearer ")) {
			return null;
		}
		
		return token.substring(7, token.length());
	}

}

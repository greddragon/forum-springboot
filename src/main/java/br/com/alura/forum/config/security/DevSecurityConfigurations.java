package br.com.alura.forum.config.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
@Configuration
@Profile(value = "dev")
public class DevSecurityConfigurations extends WebSecurityConfigurerAdapter{
	
	
	//configuracoes de autorizacao
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/**").permitAll()
			.and().csrf().disable();
	}
	//configuracoes de recursos estaticos
		@Override
		public void configure(WebSecurity web) throws Exception {
			 web.ignoring()
		        .antMatchers("/**.html", "/v2/api-docs", "/webjars/**", "/configuration/**", "/swagger-resources/**");
		}
	
	
	

}

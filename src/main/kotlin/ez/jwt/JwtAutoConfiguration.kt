package ez.jwt

import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@ConfigurationProperties("ez.jwt")
@Configuration
class JwtAutoConfiguration {
  /**
   * jwt secretKey.
   * **NOTICE**: algorithm may require specific key format. eg: key for [SignatureAlgorithm.HS256] should have at least 256 bits(32 chars)
   */
  var secretKey = Math.random().toString()

  /**
   * jwt token ttl
   */
  var tokenExpireSeconds = 86400L

  /**
   * algorithm to encrypt jwt secretKey
   */
  var algorithm = SignatureAlgorithm.HS256

  /**
   * claims field name of user
   */
  var userField = "user"

  /**
   * role name of administrator(superuser)
   */
  var adminRole = "admin"

  /**
   * schema for using jwt in http Authorization header. header value should be like "&lt;Schema&gt; &lt;Token&gt;"
   */
  var authorizationSchema = "Bearer"

  @ConditionalOnMissingBean(JwtUtil::class)
  @Bean
  fun jwtUtil() = JwtUtil(this)
}

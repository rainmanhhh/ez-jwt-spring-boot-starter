package ez.jwt

import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.DefaultClaims
import org.slf4j.LoggerFactory
import java.util.*
import javax.crypto.spec.SecretKeySpec

class JwtUtil(val config: JwtAutoConfiguration) {
  /**
   * schema prefix
   */
  private val prefix = config.authorizationSchema + " "

  /**
   * final secretKey used by
   */
  private val secretKey = SecretKeySpec(config.secretKey.toByteArray(), config.algorithm.jcaName)

  /**
   * @param ttl unit: seconds; less than 0 means token never expire
   */
  fun createToken(user: JwtUser, ttl: Long = config.tokenExpireSeconds): String {
    val builder = Jwts.builder()
    val id = UUID.randomUUID().toString()
    val claims = DefaultClaims().also {
      val nowMillis = System.currentTimeMillis() //生成JWT的时间
      it.id = id
      it.issuedAt = Date(nowMillis)
      it[config.userField] = user
      if (ttl >= 0) {
        val expMillis = nowMillis + ttl * 1000
        val exp = Date(expMillis)
        it.expiration = exp //设置过期时间
      }
    }
    val token = builder
      .setClaims(claims)
      .signWith(secretKey) //设置签名使用的签名算法和签名使用的秘钥
      .compact()
    if (logger.isDebugEnabled) {
      logger.debug("new jwt for user: {}, id: {}, content: {}", user.id, id, token)
    } else {
      logger.info("new jwt for user: {}, id: {}", user.id, id)
    }
    return token
  }

  /**
   * prefix is "&lt;Schema&gt; "
   * @param ttl unit: seconds; less than 0 means token never expire
   * @see [JwtAutoConfiguration.authorizationSchema]
   */
  fun createTokenWithPrefix(user: JwtUser, ttl: Long = config.tokenExpireSeconds): String {
    val token = createToken(user, ttl)
    return prefix + token
  }

  private fun parseToken(token: String): Claims {
    logger.debug("parse jwt: {}", token)
    return Jwts.parserBuilder()
      .setSigningKey(secretKey)
      .build()
      .parseClaimsJws(token)
      .body
  }

  private fun verifyToken(claims: Claims): JwtUser {
    return claims[config.userField] as? JwtUser ?: throw JwtException("claims.user invalid")
  }

  /**
   * @param token jwt token without schema prefix
   */
  fun verifyToken(token: String) = verifyToken(parseToken(token))

  /**
   * @param tokenWithPrefix jwt token with schema prefix
   */
  fun verifyTokenWithPrefix(tokenWithPrefix: String): JwtUser {
    if (verifySchema(tokenWithPrefix)) return verifyToken(tokenWithPrefix.substring(prefix.length))
    else throw JwtException("token not start with schema prefix: `$prefix`")
  }

  /**
   * check whether the token start with correct schema prefix
   */
  fun verifySchema(tokenWithPrefix: String) = tokenWithPrefix.startsWith(prefix)

  /**
   * verify http Authorization header value
   */
  fun verifyAuthHeader(authHeaderValue: Iterable<String>?): JwtUser {
    return authHeaderValue?.firstOrNull {
      verifySchema(it)
    }?.let {
      verifyTokenWithPrefix(it)
    } ?: Anon
  }

  companion object {
    private val logger = LoggerFactory.getLogger(JwtUtil::class.java)!!
  }
}

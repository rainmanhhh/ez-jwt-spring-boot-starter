package ez.jwt

data class JwtUser(
  var id: String = "",
  var roles: Set<String> = emptySet(),
  var perms: Set<String> = emptySet()
)

/**
 * anonymous user
 */
val Anon = JwtUser()

/**
 * check whether the user is anonymous
 * @return true - user id is ""
 */
val JwtUser.isAnon get() = id == ""

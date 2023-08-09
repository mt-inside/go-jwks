/*
* You can go
* * From PEM -> JWK[S]
* * From Key[s] -> JWK[S]
* * From JWK[S] -> Key[s]
* * From JWK[S] -> PEM
* Anywhere you can parse or render JSON, you can also get an [Un]Marshaler type for embedding in larger structs
* TODO:
* - examples
* - tick off all those combos - API needs squaring
* - rename module to go-jwks
*
* The user should be able to do everything using the types provided.
* Everything non-method func is a convenience, and they either:
* - deal with going straight to/from PEM, ie all the en/decoding
* - bypass our wrapper types and thus lose KeyID info
* Eg Keys2JWKS & Key2JWK take stdlib Key types, which don't allow for KeyIDs
* - We could take an optional Key in JWK, but a map in JWKS wouldn't work because what would you use for keys if you don't have KeyIDs?
* Eg JWKS2Keys & JWK2Key return stdlib Key types, thus losing any KeyID that was present.
* - JWKS gives a map that does have key IDs (or auto-generated short ints), as this is such a common use case
 */
package jwks

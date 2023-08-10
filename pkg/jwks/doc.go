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

/* Go's Serialization APIs:
* Anything that implementes MarshalJSON fullfils json.Marshaler
* Ditto UnmashalJSON with json.Unmarshaler
* Note that pkg encoding/json just provides the [Un]MarshalJSON ifaces; types (that can represent themselves as JSON) have to implement it.
* json.Marshal() then walks objects and calls the members' MarshalJSON(), or errors if they don't have that iface
* root encoding/ pkg encoding also has ifaces [Un]Marshall[Binary,Text] for things that can represent themselves that way
* [Un]Marshal deal with strings/[]byte
* [En,De]coder deal with streams (io.[Reader,Writer])
* - There aren't Decode/Encode ifaces
* These two often share code.
 */

/* On type wrangling in Go:
* Go doesn't allow "extension methods", ie we can't add methods to other package's types, so we can't add MarshalJSON to rsa.PublicKey
* Hence, we alias those types and impl the marshal funcs on our aliases
* Often you'll hold a variable typed as the crypto.[Public,Private]Key interface, and want to marshal that.
* That iface doesn't include MarshalJSON, so again we wanna add it.
* However we can't even alias the interface and do it that way, because you can't have iface receivers.
* Hence, functions like these at the top that go from the stdlib iface to one of our concrete impls.
 */
/* TODO
* - X test with istio demo master (move to containerimage)
* - rearrange to lib at top
* - X to melange & apko; test
* - X test all Just targets
* - X tests stable
* - fix up test_keys dir (inc the pkcs8 - leave a cmd that gens taht)
* - doc.go (explain the ortho of the funcs, eg to/from json vs to/from an [un]marshaler
* - README.md
* - check gh action & its outputs
* - tag 0.2 (1.0?)
* - examples
*   - http get google jwks, parse, pick key by key id and verify JWT
*   - get marshaller and put it in larger object which is then serialised
*   - ditto unmarshaller - unmarhsal some JSON object that has a jwk embedded in it
 */
package jwks

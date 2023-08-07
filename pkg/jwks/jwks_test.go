package jwks

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
)

// TODO
// * Test decoder with https://www.googleapis.com/oauth2/v3/certs
// * test jwks parse & verify a jwt sig by lookup kid in map (code from httplog, but don't do the network fetches)

var publics = []struct {
	pem  []byte
	jwks string
}{
	// RSA Public 2048
	{
		pem: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8iGXpjwlnRJCVSaROlgQ
pPYGpCK4aMztJOPISheg/DiL1hZ0c0oqXSjeByHop0eCwJI64SIu8l+Q5bp+3ZYH
E53JlaVdU6rMZUDKv1zZpKpVcPec8X6RilTz8EuSMOSsOVn5O6vi8FqXAjRvlJW0
onOOLPhYDDfzQmz8TX65vAcoRKQ4HsSidL+lw56HRxBFeGWjqmJdxgtBqVWJWvoQ
+6UUrdUqm6GLkiRjAEQHjLS7xduWbJH33tQXCBu7ScvPVEFZhqpV8OcP/xEgs1hY
iYz/foMc8QveOhEo4k1nSX2mjW6CBViDY8HXy1fPlamGExmYpkTmxb09uJLdnUxj
uQIDAQAB
-----END PUBLIC KEY-----
`),
		jwks: `{"keys":[{"kty":"RSA","alg":"RS256","n":"8iGXpjwlnRJCVSaROlgQpPYGpCK4aMztJOPISheg_DiL1hZ0c0oqXSjeByHop0eCwJI64SIu8l-Q5bp-3ZYHE53JlaVdU6rMZUDKv1zZpKpVcPec8X6RilTz8EuSMOSsOVn5O6vi8FqXAjRvlJW0onOOLPhYDDfzQmz8TX65vAcoRKQ4HsSidL-lw56HRxBFeGWjqmJdxgtBqVWJWvoQ-6UUrdUqm6GLkiRjAEQHjLS7xduWbJH33tQXCBu7ScvPVEFZhqpV8OcP_xEgs1hYiYz_foMc8QveOhEo4k1nSX2mjW6CBViDY8HXy1fPlamGExmYpkTmxb09uJLdnUxjuQ","e":"AQAB"}]}`,
	},

	// RSA Public 8192
	{
		pem: []byte(`-----BEGIN PUBLIC KEY-----
MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAwewyATYbIBH44YpX9mTB
K5wn7t+Si9EDy2HBmXeY0QDMOcUoxTwfqjuUOd+tzuOq9wRBKzou/LN7Ow055ZMP
blc5Cjaaus+IkI/Ft9tHRHI6k89M3hLKoLT4j4yJlgFb+K2+pAhPE1JV4iE8w0Ek
jdHSMZEDPojlMqnfu0q+AJBBW8Qzku2T3OQbZIyHfnFnuJKODF/ezw/m3pdCkrCk
rvDyro2H5XVUGiFAUB61aTCBPnuF920MI1ZwCyrC8Le4t5vRndghrB68ZiE7bnqF
vXV3pKVeW/+RF+GzI0TooIF9tjlHqiXUN74GhRSjkoGyX9NTVJHkaB8UX40wQD9D
+GbaI0PWhgZCQCHxoi+et+v+ovxeJ3gAbCMvslcMjGO87RbsWxchx/6DuiyWcnBi
JNjW+/u0ILp/g9kNp58ivFy37hx0r0xtOreD9RN3YFpqkCf+RijQcnmSu/xOYboc
We9iyglXE4Kl4MPfTSpTG/RDKR4hduraTZ3iOh3FK+7kQfAzV0VWUdHkhEsjMHPY
b18w4SI//x48Rq+pyO2zKMCgr1DdFpSpOM+9UPnfDzDrVw2zCiSfuKNcVWdq2A8e
OWo+vMNiRtQnF+//iRtjr4M8g+dP4buNs9p30Yo0wa5Omndtxo39OJvIA5oaQfHO
HL2fJGS12N4S5U8RzpoiOmGxGX1tmqfihan8MRmWeGgMwURFBDbiYkIykAuytt3G
vw/0Y3F2DnjnLJBai5ceZBYErNtgs30p0QoNIyvQZ1Qli+97f9bJT2BkuuHS/bfd
SZUc0V8vpvzfIkERAD4CuTm+FwIpQZ4pLjK9u7zsDWIQMyW3JYe5ATODgC68ij4F
lehyaOIs4FZrkOJ6mTlbNg7DwKkRdtlzCzCzxQ1Jz3mh0NcQKTu2a80x4G5C2/sK
uetY078dm5pEhuIi89OcKATKUAe5Ld3kUfFW1FCTtVwSpBxkSzqDE8fyTmnnJicd
fBmGgpZ3/HgoxMtMZ+a8SdTLbBe8xD9Zl72bLVaDaZoNGA7Ki8P9XeYFypARrjjf
/YtbeXXsmw8HiLnyz/AvNLDFkc9o3gZSJaGLBzp0mrdMPfbE/qTn03t/TOt7AUi+
HC4L/X20qkzrsD+amCE0X6Jt2ImEpCr6EExMmaWuYSvhLXK0r0Fy5TIHrZoauRFu
VTJF6CqTltX9dOtFRVFTb46WvK+dWcVDyhjP1FPI1FEO0kDKR6nVfz+GqCAtK/GN
YfeDABmeY5hl4Ejsr8W+kYg9xGP/W5MOksoGwkldzp2OH0L+IitN94raks52iaZ6
qsu7s5yKxDsZpgVKCTDkN7l29ij5GdCBofp4WCoYs8lN98rDhUcpxdDs/k3OF56N
YwIDAQAB
-----END PUBLIC KEY-----
`),
		jwks: `{"keys":[{"kty":"RSA","alg":"RS1024","n":"wewyATYbIBH44YpX9mTBK5wn7t-Si9EDy2HBmXeY0QDMOcUoxTwfqjuUOd-tzuOq9wRBKzou_LN7Ow055ZMPblc5Cjaaus-IkI_Ft9tHRHI6k89M3hLKoLT4j4yJlgFb-K2-pAhPE1JV4iE8w0EkjdHSMZEDPojlMqnfu0q-AJBBW8Qzku2T3OQbZIyHfnFnuJKODF_ezw_m3pdCkrCkrvDyro2H5XVUGiFAUB61aTCBPnuF920MI1ZwCyrC8Le4t5vRndghrB68ZiE7bnqFvXV3pKVeW_-RF-GzI0TooIF9tjlHqiXUN74GhRSjkoGyX9NTVJHkaB8UX40wQD9D-GbaI0PWhgZCQCHxoi-et-v-ovxeJ3gAbCMvslcMjGO87RbsWxchx_6DuiyWcnBiJNjW-_u0ILp_g9kNp58ivFy37hx0r0xtOreD9RN3YFpqkCf-RijQcnmSu_xOYbocWe9iyglXE4Kl4MPfTSpTG_RDKR4hduraTZ3iOh3FK-7kQfAzV0VWUdHkhEsjMHPYb18w4SI__x48Rq-pyO2zKMCgr1DdFpSpOM-9UPnfDzDrVw2zCiSfuKNcVWdq2A8eOWo-vMNiRtQnF-__iRtjr4M8g-dP4buNs9p30Yo0wa5Omndtxo39OJvIA5oaQfHOHL2fJGS12N4S5U8RzpoiOmGxGX1tmqfihan8MRmWeGgMwURFBDbiYkIykAuytt3Gvw_0Y3F2DnjnLJBai5ceZBYErNtgs30p0QoNIyvQZ1Qli-97f9bJT2BkuuHS_bfdSZUc0V8vpvzfIkERAD4CuTm-FwIpQZ4pLjK9u7zsDWIQMyW3JYe5ATODgC68ij4FlehyaOIs4FZrkOJ6mTlbNg7DwKkRdtlzCzCzxQ1Jz3mh0NcQKTu2a80x4G5C2_sKuetY078dm5pEhuIi89OcKATKUAe5Ld3kUfFW1FCTtVwSpBxkSzqDE8fyTmnnJicdfBmGgpZ3_HgoxMtMZ-a8SdTLbBe8xD9Zl72bLVaDaZoNGA7Ki8P9XeYFypARrjjf_YtbeXXsmw8HiLnyz_AvNLDFkc9o3gZSJaGLBzp0mrdMPfbE_qTn03t_TOt7AUi-HC4L_X20qkzrsD-amCE0X6Jt2ImEpCr6EExMmaWuYSvhLXK0r0Fy5TIHrZoauRFuVTJF6CqTltX9dOtFRVFTb46WvK-dWcVDyhjP1FPI1FEO0kDKR6nVfz-GqCAtK_GNYfeDABmeY5hl4Ejsr8W-kYg9xGP_W5MOksoGwkldzp2OH0L-IitN94raks52iaZ6qsu7s5yKxDsZpgVKCTDkN7l29ij5GdCBofp4WCoYs8lN98rDhUcpxdDs_k3OF56NYw","e":"AQAB"}]}`,
	},

	// ECDSA Public P-256
	{
		pem: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsQQ9AIYMbDafWOjCZnQghRQ/ZoY7
g5T5JELrQ3C92FsGL91Y58QXxAyfFytAJTjW0pT10rxFtq1LA1MZ+UKlDg==
-----END PUBLIC KEY-----
`),
		jwks: `{"keys":[{"kty":"EC","crv":"P-256","x":"sQQ9AIYMbDafWOjCZnQghRQ_ZoY7g5T5JELrQ3C92Fs","y":"Bi_dWOfEF8QMnxcrQCU41tKU9dK8RbatSwNTGflCpQ4"}]}`,
	},

	// Multiple
	{
		pem: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8iGXpjwlnRJCVSaROlgQ
pPYGpCK4aMztJOPISheg/DiL1hZ0c0oqXSjeByHop0eCwJI64SIu8l+Q5bp+3ZYH
E53JlaVdU6rMZUDKv1zZpKpVcPec8X6RilTz8EuSMOSsOVn5O6vi8FqXAjRvlJW0
onOOLPhYDDfzQmz8TX65vAcoRKQ4HsSidL+lw56HRxBFeGWjqmJdxgtBqVWJWvoQ
+6UUrdUqm6GLkiRjAEQHjLS7xduWbJH33tQXCBu7ScvPVEFZhqpV8OcP/xEgs1hY
iYz/foMc8QveOhEo4k1nSX2mjW6CBViDY8HXy1fPlamGExmYpkTmxb09uJLdnUxj
uQIDAQAB
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsQQ9AIYMbDafWOjCZnQghRQ/ZoY7
g5T5JELrQ3C92FsGL91Y58QXxAyfFytAJTjW0pT10rxFtq1LA1MZ+UKlDg==
-----END PUBLIC KEY-----
`),
		jwks: `{"keys":[{"kty":"RSA","alg":"RS256","n":"8iGXpjwlnRJCVSaROlgQpPYGpCK4aMztJOPISheg_DiL1hZ0c0oqXSjeByHop0eCwJI64SIu8l-Q5bp-3ZYHE53JlaVdU6rMZUDKv1zZpKpVcPec8X6RilTz8EuSMOSsOVn5O6vi8FqXAjRvlJW0onOOLPhYDDfzQmz8TX65vAcoRKQ4HsSidL-lw56HRxBFeGWjqmJdxgtBqVWJWvoQ-6UUrdUqm6GLkiRjAEQHjLS7xduWbJH33tQXCBu7ScvPVEFZhqpV8OcP_xEgs1hYiYz_foMc8QveOhEo4k1nSX2mjW6CBViDY8HXy1fPlamGExmYpkTmxb09uJLdnUxjuQ","e":"AQAB"},{"kty":"EC","crv":"P-256","x":"sQQ9AIYMbDafWOjCZnQghRQ_ZoY7g5T5JELrQ3C92Fs","y":"Bi_dWOfEF8QMnxcrQCU41tKU9dK8RbatSwNTGflCpQ4"}]}`,
	},
}

var mixeds = []struct {
	pem  []byte
	jwks string
}{
	// RSA Public 2048
	{
		pem: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8iGXpjwlnRJCVSaROlgQ
pPYGpCK4aMztJOPISheg/DiL1hZ0c0oqXSjeByHop0eCwJI64SIu8l+Q5bp+3ZYH
E53JlaVdU6rMZUDKv1zZpKpVcPec8X6RilTz8EuSMOSsOVn5O6vi8FqXAjRvlJW0
onOOLPhYDDfzQmz8TX65vAcoRKQ4HsSidL+lw56HRxBFeGWjqmJdxgtBqVWJWvoQ
+6UUrdUqm6GLkiRjAEQHjLS7xduWbJH33tQXCBu7ScvPVEFZhqpV8OcP/xEgs1hY
iYz/foMc8QveOhEo4k1nSX2mjW6CBViDY8HXy1fPlamGExmYpkTmxb09uJLdnUxj
uQIDAQAB
-----END PUBLIC KEY-----
`),
		jwks: `{"keys":[{"kty":"RSA","alg":"RS256","n":"8iGXpjwlnRJCVSaROlgQpPYGpCK4aMztJOPISheg_DiL1hZ0c0oqXSjeByHop0eCwJI64SIu8l-Q5bp-3ZYHE53JlaVdU6rMZUDKv1zZpKpVcPec8X6RilTz8EuSMOSsOVn5O6vi8FqXAjRvlJW0onOOLPhYDDfzQmz8TX65vAcoRKQ4HsSidL-lw56HRxBFeGWjqmJdxgtBqVWJWvoQ-6UUrdUqm6GLkiRjAEQHjLS7xduWbJH33tQXCBu7ScvPVEFZhqpV8OcP_xEgs1hYiYz_foMc8QveOhEo4k1nSX2mjW6CBViDY8HXy1fPlamGExmYpkTmxb09uJLdnUxjuQ","e":"AQAB"}]}`,
	},

	// RSA Public 8192
	{
		pem: []byte(`-----BEGIN PUBLIC KEY-----
MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAwewyATYbIBH44YpX9mTB
K5wn7t+Si9EDy2HBmXeY0QDMOcUoxTwfqjuUOd+tzuOq9wRBKzou/LN7Ow055ZMP
blc5Cjaaus+IkI/Ft9tHRHI6k89M3hLKoLT4j4yJlgFb+K2+pAhPE1JV4iE8w0Ek
jdHSMZEDPojlMqnfu0q+AJBBW8Qzku2T3OQbZIyHfnFnuJKODF/ezw/m3pdCkrCk
rvDyro2H5XVUGiFAUB61aTCBPnuF920MI1ZwCyrC8Le4t5vRndghrB68ZiE7bnqF
vXV3pKVeW/+RF+GzI0TooIF9tjlHqiXUN74GhRSjkoGyX9NTVJHkaB8UX40wQD9D
+GbaI0PWhgZCQCHxoi+et+v+ovxeJ3gAbCMvslcMjGO87RbsWxchx/6DuiyWcnBi
JNjW+/u0ILp/g9kNp58ivFy37hx0r0xtOreD9RN3YFpqkCf+RijQcnmSu/xOYboc
We9iyglXE4Kl4MPfTSpTG/RDKR4hduraTZ3iOh3FK+7kQfAzV0VWUdHkhEsjMHPY
b18w4SI//x48Rq+pyO2zKMCgr1DdFpSpOM+9UPnfDzDrVw2zCiSfuKNcVWdq2A8e
OWo+vMNiRtQnF+//iRtjr4M8g+dP4buNs9p30Yo0wa5Omndtxo39OJvIA5oaQfHO
HL2fJGS12N4S5U8RzpoiOmGxGX1tmqfihan8MRmWeGgMwURFBDbiYkIykAuytt3G
vw/0Y3F2DnjnLJBai5ceZBYErNtgs30p0QoNIyvQZ1Qli+97f9bJT2BkuuHS/bfd
SZUc0V8vpvzfIkERAD4CuTm+FwIpQZ4pLjK9u7zsDWIQMyW3JYe5ATODgC68ij4F
lehyaOIs4FZrkOJ6mTlbNg7DwKkRdtlzCzCzxQ1Jz3mh0NcQKTu2a80x4G5C2/sK
uetY078dm5pEhuIi89OcKATKUAe5Ld3kUfFW1FCTtVwSpBxkSzqDE8fyTmnnJicd
fBmGgpZ3/HgoxMtMZ+a8SdTLbBe8xD9Zl72bLVaDaZoNGA7Ki8P9XeYFypARrjjf
/YtbeXXsmw8HiLnyz/AvNLDFkc9o3gZSJaGLBzp0mrdMPfbE/qTn03t/TOt7AUi+
HC4L/X20qkzrsD+amCE0X6Jt2ImEpCr6EExMmaWuYSvhLXK0r0Fy5TIHrZoauRFu
VTJF6CqTltX9dOtFRVFTb46WvK+dWcVDyhjP1FPI1FEO0kDKR6nVfz+GqCAtK/GN
YfeDABmeY5hl4Ejsr8W+kYg9xGP/W5MOksoGwkldzp2OH0L+IitN94raks52iaZ6
qsu7s5yKxDsZpgVKCTDkN7l29ij5GdCBofp4WCoYs8lN98rDhUcpxdDs/k3OF56N
YwIDAQAB
-----END PUBLIC KEY-----
`),
		jwks: `{"keys":[{"kty":"RSA","alg":"RS1024","n":"wewyATYbIBH44YpX9mTBK5wn7t-Si9EDy2HBmXeY0QDMOcUoxTwfqjuUOd-tzuOq9wRBKzou_LN7Ow055ZMPblc5Cjaaus-IkI_Ft9tHRHI6k89M3hLKoLT4j4yJlgFb-K2-pAhPE1JV4iE8w0EkjdHSMZEDPojlMqnfu0q-AJBBW8Qzku2T3OQbZIyHfnFnuJKODF_ezw_m3pdCkrCkrvDyro2H5XVUGiFAUB61aTCBPnuF920MI1ZwCyrC8Le4t5vRndghrB68ZiE7bnqFvXV3pKVeW_-RF-GzI0TooIF9tjlHqiXUN74GhRSjkoGyX9NTVJHkaB8UX40wQD9D-GbaI0PWhgZCQCHxoi-et-v-ovxeJ3gAbCMvslcMjGO87RbsWxchx_6DuiyWcnBiJNjW-_u0ILp_g9kNp58ivFy37hx0r0xtOreD9RN3YFpqkCf-RijQcnmSu_xOYbocWe9iyglXE4Kl4MPfTSpTG_RDKR4hduraTZ3iOh3FK-7kQfAzV0VWUdHkhEsjMHPYb18w4SI__x48Rq-pyO2zKMCgr1DdFpSpOM-9UPnfDzDrVw2zCiSfuKNcVWdq2A8eOWo-vMNiRtQnF-__iRtjr4M8g-dP4buNs9p30Yo0wa5Omndtxo39OJvIA5oaQfHOHL2fJGS12N4S5U8RzpoiOmGxGX1tmqfihan8MRmWeGgMwURFBDbiYkIykAuytt3Gvw_0Y3F2DnjnLJBai5ceZBYErNtgs30p0QoNIyvQZ1Qli-97f9bJT2BkuuHS_bfdSZUc0V8vpvzfIkERAD4CuTm-FwIpQZ4pLjK9u7zsDWIQMyW3JYe5ATODgC68ij4FlehyaOIs4FZrkOJ6mTlbNg7DwKkRdtlzCzCzxQ1Jz3mh0NcQKTu2a80x4G5C2_sKuetY078dm5pEhuIi89OcKATKUAe5Ld3kUfFW1FCTtVwSpBxkSzqDE8fyTmnnJicdfBmGgpZ3_HgoxMtMZ-a8SdTLbBe8xD9Zl72bLVaDaZoNGA7Ki8P9XeYFypARrjjf_YtbeXXsmw8HiLnyz_AvNLDFkc9o3gZSJaGLBzp0mrdMPfbE_qTn03t_TOt7AUi-HC4L_X20qkzrsD-amCE0X6Jt2ImEpCr6EExMmaWuYSvhLXK0r0Fy5TIHrZoauRFuVTJF6CqTltX9dOtFRVFTb46WvK-dWcVDyhjP1FPI1FEO0kDKR6nVfz-GqCAtK_GNYfeDABmeY5hl4Ejsr8W-kYg9xGP_W5MOksoGwkldzp2OH0L-IitN94raks52iaZ6qsu7s5yKxDsZpgVKCTDkN7l29ij5GdCBofp4WCoYs8lN98rDhUcpxdDs_k3OF56NYw","e":"AQAB"}]}`,
	},

	// RSA Private 1024
	{
		pem: []byte(`-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAK9yHSgSapN62QkL
BwPUSuW/+aDSFCS259j0HxxiP9OysKuX5VgMWJT0gsfWU91bwGb+mu4QMjJOKTOA
kIHCmh0BTe1Bo5lF1841EkPSNxDsl8nbANpata1NKc3qxl3cLEpDA/2gLqmxFTn0
mmI6fEuFHt+1e5+TLFhtjvG5LOedAgMBAAECgYEAqBeHA8uRPLeolVdxYyPUlob1
3jUog3ySaXSLEiC30lYTmnOvkkpR3HTfkCMyupSbpJIvUgNGdJgaNXPp/8i46ZW4
W6Yax4mUbFEndzRJjaBstCzPU7a+PlvTcKMq9wOl/Mng3kq6UZycRd1hkI7k8Ko/
bEGYW1TUbkbbwNMhPakCQQDmmLd7wJ4K7f4qF7Tj8+ZuFoSdxdFJUAze94BKuVo5
5FCjzpeIaFDCpr/f6PQfkldsEm6VBxiPNkt4grZvCi7rAkEAwsYI39CtPgMXS7MB
CoWIeJNWcDROXJx1fYbzILeOzG0KyXcBqvaPw6vsutQPoyOv0XRltPCldVJA3pln
7ADxlwJAcDtZ6kBYa2dj8eax4tR9jY0mJIf4EZ+FdCuv5C6MTGrkGKXfOMPUsrhn
4LnHv2oBZJcf/SaD/IfneZLc6fRh2wJBAJQN5wcC3/2oadfgDOWLla5aCTWnfP2G
7QRrRXrULRcVuEJmVP05CRUrJfrqYayX3vjvarR8zLj+ulK697T9DqcCQQCqnvRc
G56ttnV6XhPgu91nxp/kD5ZpeVHjOOXcR1D6zoInp61pNnwwS0JnPTE2SZcN3Lvl
Vp6eelghdiQWYJaL
-----END PRIVATE KEY-----
`),
		jwks: `{"keys":[{"kty":"RSA","alg":"RS128","n":"r3IdKBJqk3rZCQsHA9RK5b_5oNIUJLbn2PQfHGI_07Kwq5flWAxYlPSCx9ZT3VvAZv6a7hAyMk4pM4CQgcKaHQFN7UGjmUXXzjUSQ9I3EOyXydsA2lq1rU0pzerGXdwsSkMD_aAuqbEVOfSaYjp8S4Ue37V7n5MsWG2O8bks550","e":"AQAB"}]}`,
	},

	// ECDSA Public P-256
	{
		pem: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsQQ9AIYMbDafWOjCZnQghRQ/ZoY7
g5T5JELrQ3C92FsGL91Y58QXxAyfFytAJTjW0pT10rxFtq1LA1MZ+UKlDg==
-----END PUBLIC KEY-----
`),
		jwks: `{"keys":[{"kty":"EC","crv":"P-256","x":"sQQ9AIYMbDafWOjCZnQghRQ_ZoY7g5T5JELrQ3C92Fs","y":"Bi_dWOfEF8QMnxcrQCU41tKU9dK8RbatSwNTGflCpQ4"}]}`,
	},

	// ECDSA Private P-256, in non-openssl-standard pkcs8 (so that it matches what we output)
	{
		pem: []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvw58OTuD3Y9sxa6B
s7zoo+14+J0IiA20ioMpG1YW8n6hRANCAASxBD0AhgxsNp9Y6MJmdCCFFD9mhjuD
lPkkQutDcL3YWwYv3VjnxBfEDJ8XK0AlONbSlPXSvEW2rUsDUxn5QqUO
-----END PRIVATE KEY-----
`),
		jwks: `{"keys":[{"kty":"EC","crv":"P-256","x":"sQQ9AIYMbDafWOjCZnQghRQ_ZoY7g5T5JELrQ3C92Fs","y":"Bi_dWOfEF8QMnxcrQCU41tKU9dK8RbatSwNTGflCpQ4"}]}`,
	},

	// Multiple
	{
		pem: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8iGXpjwlnRJCVSaROlgQ
pPYGpCK4aMztJOPISheg/DiL1hZ0c0oqXSjeByHop0eCwJI64SIu8l+Q5bp+3ZYH
E53JlaVdU6rMZUDKv1zZpKpVcPec8X6RilTz8EuSMOSsOVn5O6vi8FqXAjRvlJW0
onOOLPhYDDfzQmz8TX65vAcoRKQ4HsSidL+lw56HRxBFeGWjqmJdxgtBqVWJWvoQ
+6UUrdUqm6GLkiRjAEQHjLS7xduWbJH33tQXCBu7ScvPVEFZhqpV8OcP/xEgs1hY
iYz/foMc8QveOhEo4k1nSX2mjW6CBViDY8HXy1fPlamGExmYpkTmxb09uJLdnUxj
uQIDAQAB
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsQQ9AIYMbDafWOjCZnQghRQ/ZoY7
g5T5JELrQ3C92FsGL91Y58QXxAyfFytAJTjW0pT10rxFtq1LA1MZ+UKlDg==
-----END PUBLIC KEY-----
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvw58OTuD3Y9sxa6B
s7zoo+14+J0IiA20ioMpG1YW8n6hRANCAASxBD0AhgxsNp9Y6MJmdCCFFD9mhjuD
lPkkQutDcL3YWwYv3VjnxBfEDJ8XK0AlONbSlPXSvEW2rUsDUxn5QqUO
-----END PRIVATE KEY-----
`),
		jwks: `{"keys":[{"kty":"RSA","alg":"RS256","n":"8iGXpjwlnRJCVSaROlgQpPYGpCK4aMztJOPISheg_DiL1hZ0c0oqXSjeByHop0eCwJI64SIu8l-Q5bp-3ZYHE53JlaVdU6rMZUDKv1zZpKpVcPec8X6RilTz8EuSMOSsOVn5O6vi8FqXAjRvlJW0onOOLPhYDDfzQmz8TX65vAcoRKQ4HsSidL-lw56HRxBFeGWjqmJdxgtBqVWJWvoQ-6UUrdUqm6GLkiRjAEQHjLS7xduWbJH33tQXCBu7ScvPVEFZhqpV8OcP_xEgs1hYiYz_foMc8QveOhEo4k1nSX2mjW6CBViDY8HXy1fPlamGExmYpkTmxb09uJLdnUxjuQ","e":"AQAB"},{"kty":"EC","crv":"P-256","x":"sQQ9AIYMbDafWOjCZnQghRQ_ZoY7g5T5JELrQ3C92Fs","y":"Bi_dWOfEF8QMnxcrQCU41tKU9dK8RbatSwNTGflCpQ4"},{"kty":"EC","crv":"P-256","x":"sQQ9AIYMbDafWOjCZnQghRQ_ZoY7g5T5JELrQ3C92Fs","y":"Bi_dWOfEF8QMnxcrQCU41tKU9dK8RbatSwNTGflCpQ4"}]}`,
	},
}

var privates = []struct {
	pem  []byte
	jwks string
}{
	// RSA Private 1024
	{
		pem: []byte(`-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAK9yHSgSapN62QkL
BwPUSuW/+aDSFCS259j0HxxiP9OysKuX5VgMWJT0gsfWU91bwGb+mu4QMjJOKTOA
kIHCmh0BTe1Bo5lF1841EkPSNxDsl8nbANpata1NKc3qxl3cLEpDA/2gLqmxFTn0
mmI6fEuFHt+1e5+TLFhtjvG5LOedAgMBAAECgYEAqBeHA8uRPLeolVdxYyPUlob1
3jUog3ySaXSLEiC30lYTmnOvkkpR3HTfkCMyupSbpJIvUgNGdJgaNXPp/8i46ZW4
W6Yax4mUbFEndzRJjaBstCzPU7a+PlvTcKMq9wOl/Mng3kq6UZycRd1hkI7k8Ko/
bEGYW1TUbkbbwNMhPakCQQDmmLd7wJ4K7f4qF7Tj8+ZuFoSdxdFJUAze94BKuVo5
5FCjzpeIaFDCpr/f6PQfkldsEm6VBxiPNkt4grZvCi7rAkEAwsYI39CtPgMXS7MB
CoWIeJNWcDROXJx1fYbzILeOzG0KyXcBqvaPw6vsutQPoyOv0XRltPCldVJA3pln
7ADxlwJAcDtZ6kBYa2dj8eax4tR9jY0mJIf4EZ+FdCuv5C6MTGrkGKXfOMPUsrhn
4LnHv2oBZJcf/SaD/IfneZLc6fRh2wJBAJQN5wcC3/2oadfgDOWLla5aCTWnfP2G
7QRrRXrULRcVuEJmVP05CRUrJfrqYayX3vjvarR8zLj+ulK697T9DqcCQQCqnvRc
G56ttnV6XhPgu91nxp/kD5ZpeVHjOOXcR1D6zoInp61pNnwwS0JnPTE2SZcN3Lvl
Vp6eelghdiQWYJaL
-----END PRIVATE KEY-----
`),
		jwks: `{"keys":[{"kty":"RSA","alg":"RS128","n":"r3IdKBJqk3rZCQsHA9RK5b_5oNIUJLbn2PQfHGI_07Kwq5flWAxYlPSCx9ZT3VvAZv6a7hAyMk4pM4CQgcKaHQFN7UGjmUXXzjUSQ9I3EOyXydsA2lq1rU0pzerGXdwsSkMD_aAuqbEVOfSaYjp8S4Ue37V7n5MsWG2O8bks550","e":"AQAB","d":"qBeHA8uRPLeolVdxYyPUlob13jUog3ySaXSLEiC30lYTmnOvkkpR3HTfkCMyupSbpJIvUgNGdJgaNXPp_8i46ZW4W6Yax4mUbFEndzRJjaBstCzPU7a-PlvTcKMq9wOl_Mng3kq6UZycRd1hkI7k8Ko_bEGYW1TUbkbbwNMhPak","p":"5pi3e8CeCu3-Khe04_PmbhaEncXRSVAM3veASrlaOeRQo86XiGhQwqa_3-j0H5JXbBJulQcYjzZLeIK2bwou6w","q":"wsYI39CtPgMXS7MBCoWIeJNWcDROXJx1fYbzILeOzG0KyXcBqvaPw6vsutQPoyOv0XRltPCldVJA3pln7ADxlw","dp":"cDtZ6kBYa2dj8eax4tR9jY0mJIf4EZ-FdCuv5C6MTGrkGKXfOMPUsrhn4LnHv2oBZJcf_SaD_IfneZLc6fRh2w","dq":"lA3nBwLf_ahp1-AM5YuVrloJNad8_YbtBGtFetQtFxW4QmZU_TkJFSsl-uphrJfe-O9qtHzMuP66Urr3tP0Opw","qi":"qp70XBuerbZ1el4T4LvdZ8af5A-WaXlR4zjl3EdQ-s6CJ6etaTZ8MEtCZz0xNkmXDdy75VaennpYIXYkFmCWiw"}]}`,
	},

	// ECDSA Private P-256, in pkcs8
	{
		pem: []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvw58OTuD3Y9sxa6B
s7zoo+14+J0IiA20ioMpG1YW8n6hRANCAASxBD0AhgxsNp9Y6MJmdCCFFD9mhjuD
lPkkQutDcL3YWwYv3VjnxBfEDJ8XK0AlONbSlPXSvEW2rUsDUxn5QqUO
-----END PRIVATE KEY-----
`),
		jwks: `{"keys":[{"kty":"EC","crv":"P-256","x":"sQQ9AIYMbDafWOjCZnQghRQ_ZoY7g5T5JELrQ3C92Fs","y":"Bi_dWOfEF8QMnxcrQCU41tKU9dK8RbatSwNTGflCpQ4","d":"vw58OTuD3Y9sxa6Bs7zoo-14-J0IiA20ioMpG1YW8n4"}]}`,
	},

	// Multiple
	{
		pem: []byte(`-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAK9yHSgSapN62QkL
BwPUSuW/+aDSFCS259j0HxxiP9OysKuX5VgMWJT0gsfWU91bwGb+mu4QMjJOKTOA
kIHCmh0BTe1Bo5lF1841EkPSNxDsl8nbANpata1NKc3qxl3cLEpDA/2gLqmxFTn0
mmI6fEuFHt+1e5+TLFhtjvG5LOedAgMBAAECgYEAqBeHA8uRPLeolVdxYyPUlob1
3jUog3ySaXSLEiC30lYTmnOvkkpR3HTfkCMyupSbpJIvUgNGdJgaNXPp/8i46ZW4
W6Yax4mUbFEndzRJjaBstCzPU7a+PlvTcKMq9wOl/Mng3kq6UZycRd1hkI7k8Ko/
bEGYW1TUbkbbwNMhPakCQQDmmLd7wJ4K7f4qF7Tj8+ZuFoSdxdFJUAze94BKuVo5
5FCjzpeIaFDCpr/f6PQfkldsEm6VBxiPNkt4grZvCi7rAkEAwsYI39CtPgMXS7MB
CoWIeJNWcDROXJx1fYbzILeOzG0KyXcBqvaPw6vsutQPoyOv0XRltPCldVJA3pln
7ADxlwJAcDtZ6kBYa2dj8eax4tR9jY0mJIf4EZ+FdCuv5C6MTGrkGKXfOMPUsrhn
4LnHv2oBZJcf/SaD/IfneZLc6fRh2wJBAJQN5wcC3/2oadfgDOWLla5aCTWnfP2G
7QRrRXrULRcVuEJmVP05CRUrJfrqYayX3vjvarR8zLj+ulK697T9DqcCQQCqnvRc
G56ttnV6XhPgu91nxp/kD5ZpeVHjOOXcR1D6zoInp61pNnwwS0JnPTE2SZcN3Lvl
Vp6eelghdiQWYJaL
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvw58OTuD3Y9sxa6B
s7zoo+14+J0IiA20ioMpG1YW8n6hRANCAASxBD0AhgxsNp9Y6MJmdCCFFD9mhjuD
lPkkQutDcL3YWwYv3VjnxBfEDJ8XK0AlONbSlPXSvEW2rUsDUxn5QqUO
-----END PRIVATE KEY-----
`),
		jwks: `{"keys":[{"kty":"RSA","alg":"RS128","n":"r3IdKBJqk3rZCQsHA9RK5b_5oNIUJLbn2PQfHGI_07Kwq5flWAxYlPSCx9ZT3VvAZv6a7hAyMk4pM4CQgcKaHQFN7UGjmUXXzjUSQ9I3EOyXydsA2lq1rU0pzerGXdwsSkMD_aAuqbEVOfSaYjp8S4Ue37V7n5MsWG2O8bks550","e":"AQAB","d":"qBeHA8uRPLeolVdxYyPUlob13jUog3ySaXSLEiC30lYTmnOvkkpR3HTfkCMyupSbpJIvUgNGdJgaNXPp_8i46ZW4W6Yax4mUbFEndzRJjaBstCzPU7a-PlvTcKMq9wOl_Mng3kq6UZycRd1hkI7k8Ko_bEGYW1TUbkbbwNMhPak","p":"5pi3e8CeCu3-Khe04_PmbhaEncXRSVAM3veASrlaOeRQo86XiGhQwqa_3-j0H5JXbBJulQcYjzZLeIK2bwou6w","q":"wsYI39CtPgMXS7MBCoWIeJNWcDROXJx1fYbzILeOzG0KyXcBqvaPw6vsutQPoyOv0XRltPCldVJA3pln7ADxlw","dp":"cDtZ6kBYa2dj8eax4tR9jY0mJIf4EZ-FdCuv5C6MTGrkGKXfOMPUsrhn4LnHv2oBZJcf_SaD_IfneZLc6fRh2w","dq":"lA3nBwLf_ahp1-AM5YuVrloJNad8_YbtBGtFetQtFxW4QmZU_TkJFSsl-uphrJfe-O9qtHzMuP66Urr3tP0Opw","qi":"qp70XBuerbZ1el4T4LvdZ8af5A-WaXlR4zjl3EdQ-s6CJ6etaTZ8MEtCZz0xNkmXDdy75VaennpYIXYkFmCWiw"},{"kty":"EC","crv":"P-256","x":"sQQ9AIYMbDafWOjCZnQghRQ_ZoY7g5T5JELrQ3C92Fs","y":"Bi_dWOfEF8QMnxcrQCU41tKU9dK8RbatSwNTGflCpQ4","d":"vw58OTuD3Y9sxa6Bs7zoo-14-J0IiA20ioMpG1YW8n4"}]}`,
	},
}

func TestMixedPEMs(t *testing.T) {
	for _, cse := range mixeds {
		rendered, err := PEM2JWKSPublic(cse.pem)
		require.NoError(t, err)

		require.Equal(t, cse.jwks, rendered, "JWKS for crypto object doesn't match expected object")
	}
}
func TestPublicPEMsIdentity(t *testing.T) {
	for _, cse := range publics {
		rendered, err := PEM2JWKSPublic(cse.pem)
		require.NoError(t, err)

		require.Equal(t, cse.jwks, rendered, "JWKS for crypto object doesn't match expected object")

		back, err := JWKS2PEMPublic([]byte(rendered))
		require.NoError(t, err)

		require.Equal(t, cse.pem, back, "PEM->JWKS->PEM is not identity")
	}
}
func TestMixedKeys(t *testing.T) {
	for _, cse := range mixeds {
		ders, err := parsePEM(cse.pem)
		require.NoError(t, err)
		var keys []crypto.PublicKey
		for _, der := range ders {
			key, err := parsePublicKey(der)
			require.NoError(t, err)
			keys = append(keys, key)
		}

		rendered, err := Keys2JWKSPublic(keys)
		require.NoError(t, err)

		require.Equal(t, cse.jwks, rendered, "JWKS for crypto object doesn't match expected object")
	}
}

func TestPrivatePEMs(t *testing.T) {
	for _, cse := range privates {
		rendered, err := PEM2JWKSPrivate(cse.pem)
		require.NoError(t, err)

		require.Equal(t, cse.jwks, string(rendered), "JWKS for crypto object doesn't match expected object")
	}
}
func TestPrivatePEMsIdentity(t *testing.T) {
	for _, cse := range privates {
		rendered, err := PEM2JWKSPrivate(cse.pem)
		require.NoError(t, err)

		require.Equal(t, cse.jwks, rendered, "JWKS for crypto object doesn't match expected object")
		t.Log(rendered)

		back, err := JWKS2PEMPrivate([]byte(rendered))
		require.NoError(t, err)

		require.Equal(t, cse.pem, back, "PEM->JWKS->PEM is not identity")
	}
}
func TestPrivateKeys(t *testing.T) {
	for _, cse := range privates {
		ders, err := parsePEM(cse.pem)
		require.NoError(t, err)
		var keys []crypto.PrivateKey
		for _, der := range ders {
			key, err := parsePrivateKey(der)
			require.NoError(t, err)
			keys = append(keys, key)
		}

		rendered, err := Keys2JWKSPrivate(keys)
		require.NoError(t, err)

		require.Equal(t, cse.jwks, string(rendered), "JWKS for crypto object doesn't match expected object")
	}
}

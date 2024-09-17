package sw

import (
	"crypto/rand"
	"log"

	"github.com/m4ru1/fabric-gm-bdais/bccsp"
	"github.com/m4ru1/fabric-gm-bdais/pkg/ccs-gm/sm2"
	"github.com/m4ru1/fabric-gm-bdais/pkg/ccs-gm/utils"
)

type sm2Signer struct{}

func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signSm2(k.(*SM2PrivateKey).privKey, digest, opts)
}

type sm2PrivateKeyVerifier struct{}

func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySm2(&k.(*SM2PrivateKey).privKey.PublicKey, signature, digest, opts)
}

type sm2PublicKeyVerifier struct{}

func (v *sm2PublicKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySm2(k.(*SM2PublicKey).pubKey, signature, digest, opts)
}

// 签名方法，参考ccs-gm api
func signSm2(k *sm2.PrivateKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	pv, _ := utils.PrivateKeyToPEM(k, nil)

	log.Printf(
		`signing
key: %s,
P: %s,
N: %s,
B: %s,
Gx: %s,
BitSize: %d,
Name: %s,
X: %s,
Y: %s,
D: %s,
`, string(pv),
		k.Curve.Params().P.String(),
		k.Curve.Params().N.String(),
		k.Curve.Params().B.String(),
		k.Curve.Params().Gx.String(),
		k.Curve.Params().BitSize,
		k.Curve.Params().Name,
		k.PublicKey.X.String(),
		k.PublicKey.Y.String(),
		k.D.String(),
	)

	sig, err := k.Sign(rand.Reader, digest, opts)

	return sig, err
}

// 验签方法，参考ccs-gm api
func verifySm2(k *sm2.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return k.Verify(digest, signature), nil
}

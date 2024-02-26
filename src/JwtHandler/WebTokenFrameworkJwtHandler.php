<?php declare(strict_types=1);

namespace danielburger1337\OAuth2DPoP\JwtHandler;

use danielburger1337\OAuth2DPoP\Exception\MissingDPoPJwkException;
use danielburger1337\OAuth2DPoP\Model\WebTokenFrameworkJwk;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class WebTokenFrameworkJwtHandler implements JwtHandlerInterface
{
    private readonly JWKSet $jwkSet;
    private readonly JWSBuilder $jwsBuilder;
    private readonly JWSSerializerManager $serializer;

    public function __construct(
        JWKSet|JWK $jwkSet,
        private readonly AlgorithmManager $algorithmManager,
    ) {
        if ($jwkSet instanceof JWK) {
            $jwkSet = new JWKSet([$jwkSet]);
        }
        $this->jwkSet = $jwkSet;

        $this->jwsBuilder = new JWSBuilder($this->algorithmManager);
        $this->serializer = new JWSSerializerManager([new CompactSerializer()]);
    }

    public function selectJWK(?string $jkt, ?array $serverSupportedSignatureAlgorithms = null): JwkInterface
    {
        $serverSupportedSignatureAlgorithms ??= $this->algorithmManager->list();

        foreach ($serverSupportedSignatureAlgorithms as $algorithmName) {
            if (!$this->algorithmManager->has($algorithmName)) {
                continue;
            }

            $algorithm = $this->algorithmManager->get($algorithmName);

            if (null !== ($jwk = $this->jwkSet->selectKey('sig', $algorithm))) {
                if (null === $jkt || $jkt === $jwk->thumbprint('sha256')) {
                    return new WebTokenFrameworkJwk($jwk, $algorithm);
                }
            }
        }

        if (null !== $jkt) {
            throw new MissingDPoPJwkException(\sprintf(
                'Failed to find a JWK with the "%s" JKT.',
                $jkt
            ));
        }

        throw new MissingDPoPJwkException(\sprintf(
            'Failed to find a JWK for the supported DPoP algorithms "%s".',
            \implode(',', $serverSupportedSignatureAlgorithms)
        ));
    }

    public function createProof(JwkInterface $jwk, array $payload, array $protectedHeader): string
    {
        if (!$jwk instanceof WebTokenFrameworkJwk) {
            throw new \InvalidArgumentException(\sprintf('$jwk must be an instance of "%s", "%s" given.', WebTokenFrameworkJwk::class, \get_debug_type($jwk)));
        }

        $protectedHeader['alg'] = $jwk->algorithm->name();

        if ($jwk->jwk->has('kid')) {
            $protectedHeader['kid'] = $jwk->jwk->get('kid');
        }
        if ($jwk->jwk->has('crv')) {
            $protectedHeader['crv'] = $jwk->jwk->get('crv');
        }

        $builder = $this->jwsBuilder->create()
            ->withPayload(JsonConverter::encode($payload))
            ->addSignature($jwk->jwk, $protectedHeader)
        ;

        return $this->serializer->serialize(CompactSerializer::NAME, $builder->build());
    }
}

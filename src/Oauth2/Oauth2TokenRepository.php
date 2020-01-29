<?php

namespace Oauth2;


class Oauth2TokenRepository
{
    /**
     * @var
     */
    private $entityManager;

    public function __construct(array $connectionParams)
    {
        \Doctrine\DBAL\Types\Type::addType('uuid', 'Ramsey\Uuid\Doctrine\UuidType');

        // Setup Doctrine
        $configuration = \Doctrine\ORM\Tools\Setup::createAnnotationMetadataConfiguration(
            $paths = [__DIR__ . '/entities'],
            $isDevMode = true
        );

        // Get the entity manager
        $this->entityManager = \Doctrine\ORM\EntityManager::create($connectionParams, $configuration);

        $connection = $this->entityManager->getConnection();
        $connection->getDatabasePlatform()->registerDoctrineTypeMapping('enum', 'string');


    }



    public function getToken($provider = 'mautic')
    {
        return $this->entityManager->getRepository('Oauth2\\Oauth2Token')->findOneBy(
            ['provider' => $provider], ['accessTokenExpires' => 'DESC']
        );
    }

    public function saveToken(Oauth2Token $oauth2Token)
    {
        $this->entityManager->persist($oauth2Token);

        $this->entityManager->flush();

    }
}
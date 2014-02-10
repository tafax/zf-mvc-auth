<?php
/**
 * @license   http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 * @copyright Copyright (c) 2013 Zend Technologies USA Inc. (http://www.zend.com)
 */

namespace ZF\MvcAuth\Factory;

use Zend\Http\Request;
use Zend\ServiceManager\FactoryInterface;
use Zend\ServiceManager\ServiceLocatorInterface;
use Zend\Di\Exception\ClassNotFoundException;

/**
 * Factory for creating an AclAuthorization instance from configuration
 */
class AclAuthorizationFactory implements FactoryInterface
{
    /**
     * @var array
     */
    protected $httpMethods = array(
        Request::METHOD_DELETE => true,
        Request::METHOD_GET    => true,
        Request::METHOD_PATCH  => true,
        Request::METHOD_POST   => true,
        Request::METHOD_PUT    => true,
    );

    /**
     * Create the DefaultAuthorizationListener
     *
     * @param ServiceLocatorInterface $services
     * @return DefaultAuthorizationListener
     */
    public function createService(ServiceLocatorInterface $services)
    {
        $config = array();
        if ($services->has('config')) {
            $config = $services->get('config');
        }

        return $this->createAclFromConfig($config, $services);
    }

    /**
     * Generate the ACL instance based on the zf-mvc-auth "authorization" configuration
     *
     * Consumes the AclFactory in order to create the AclAuthorization instance.
     *
     * @param array                                        $config
     * @param \Zend\ServiceManager\ServiceLocatorInterface $services
     * @throws \Zend\Di\Exception\ClassNotFoundException
     * @return \ZF\MvcAuth\Authorization\AclAuthorization
     */
    protected function createAclFromConfig(array $config, ServiceLocatorInterface $services)
    {
        $aclConfig = array();

        $factory = '';

        if (isset($config['zf-mvc-auth'])
            && isset($config['zf-mvc-auth']['authorization'])
        ) {
            $config = $config['zf-mvc-auth']['authorization'];

            if (array_key_exists('deny_by_default', $config)) {
                $aclConfig['deny_by_default'] = (bool) $config['deny_by_default'];
                unset($config['deny_by_default']);
            }

            if(isset($config['acl_factory']))
            {
                $factory = $config['acl_factory'];
                unset($config['acl_factory']);
            }

            foreach ($config as $controllerService => $privileges) {
                $this->createAclConfigFromPrivileges($controllerService, $privileges, $aclConfig);
            }
        }

        if(!class_exists($factory))
            throw new ClassNotFoundException('Unable to find "' . $factory . '" used as the factory for authorization.');

        return $factory::factory($aclConfig, $services);
    }

    /**
     * Creates ACL configuration based on the privileges configured
     *
     * - Extracts a privilege per action
     * - Extracts privileges for each of "collection" and "resource" configured
     *
     * @param string $controllerService
     * @param array $privileges
     * @param array $aclConfig
     */
    protected function createAclConfigFromPrivileges($controllerService, array $privileges, &$aclConfig)
    {
        if (isset($privileges['actions'])) {
            foreach ($privileges['actions'] as $action => $methods) {
                $aclConfig[] = array(
                    'resource'   => sprintf('%s::%s', $controllerService, $action),
                    'privileges' => $this->createPrivilegesFromMethods($methods),
                );
            }
        }

        if (isset($privileges['collection'])) {
            $aclConfig[] = array(
                'resource'   => sprintf('%s::collection', $controllerService),
                'privileges' => $this->createPrivilegesFromMethods($privileges['collection']),
            );
        }

        if (isset($privileges['resource'])) {
            $aclConfig[] = array(
                'resource'   => sprintf('%s::resource', $controllerService),
                'privileges' => $this->createPrivilegesFromMethods($privileges['resource']),
            );
        }
    }

    /**
     * Create the list of HTTP methods defining privileges
     *
     * @param array $methods
     * @return array|null
     */
    protected function createPrivilegesFromMethods(array $methods)
    {
        $privileges = array();

        if (isset($methods['default']) && $methods['default']) {
            $privileges = $this->httpMethods;
            unset($methods['default']);
        }

        foreach ($methods as $method => $flag) {
            if (!$flag) {
                if (isset($privileges[$method])) {
                    unset($privileges[$method]);
                }
                continue;
            }
            $privileges[$method] = true;
        }

        if (empty($privileges)) {
            return null;
        }

        return array_keys($privileges);
    }
}

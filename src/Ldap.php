<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @author      Raffael Sahli <sahli@gyselroth.net>
 * @copyright   Copryright (c) 2015-2017 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth;

use Micro\Auth\Ldap\Exception;
use Psr\Log\LoggerInterface;

class Ldap
{
    /**
     * Connection resource.
     *
     * @var resource
     */
    protected $connection;

    /**
     * Logger.
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * URI.
     *
     * @var string
     */
    protected $uri = 'ldap://127.0.0.1:389';

    /**
     * Binddn.
     *
     * @var string
     */
    protected $binddn;

    /**
     * Bindpw.
     *
     * @var string
     */
    protected $bindpw;

    /**
     * Basedn.
     *
     * @var string
     */
    protected $basedn = '';

    /**
     * tls.
     *
     * @var bool
     */
    protected $tls = false;

    /**
     *  Options.
     *
     * @var array
     */
    protected $options = [];

    /**
     * construct.
     *
     * @param iterable $config
     * @param Logger   $logger
     *
     * @return resource
     */
    public function __construct(LoggerInterface $logger, ?Iterable $config = null)
    {
        $this->setOptions($config);
        $this->logger = $logger;
    }

    /**
     * Connect.
     *
     * @return Ldap
     */
    public function connect(): self
    {
        $this->logger->debug('connect to ldap server ['.$this->uri.']', [
            'category' => get_class($this),
        ]);

        if (null === $this->binddn) {
            $this->logger->warning('no binddn set for ldap connection, you should avoid anonymous bind', [
                'category' => get_class($this),
            ]);
        }

        if (false === $this->tls && 'ldaps' !== substr($this->uri, 0, 5)) {
            $this->logger->warning('neither tls nor ldaps enabled for ldap connection, it is strongly reccommended to encrypt ldap connections', [
                'category' => get_class($this),
            ]);
        }

        $this->connection = ldap_connect($this->uri);

        if (true === $this->tls) {
            ldap_start_tls($this->connection);
        }

        foreach ($this->options as $opt => $value) {
            ldap_set_option($this->connection, constant($value['attr']), $value['value']);
        }

        if ($this->connection) {
            if (null !== $this->binddn) {
                $bind = ldap_bind($this->connection, $this->binddn, $this->bindpw);

                if ($bind) {
                    $this->logger->info('bind to ldap server ['.$this->uri.'] with binddn ['.$this->binddn.'] was succesful', [
                        'category' => get_class($this),
                    ]);

                    return $this;
                }

                throw new Exception('failed bind to ldap server, error: '.ldap_error($this->connection));
            }
        } else {
            throw new Exception('failed connect to ldap server '.$this->uri);
        }

        return $this;
    }

    /**
     * Close socket.
     *
     * @return bool
     */
    public function close(): bool
    {
        if (is_resource($this->connection)) {
            return ldap_unbind($this->connection);
        }

        return true;
    }

    /**
     * Set options.
     *
     * @param iterable $config
     *
     * @return Ldap
     */
    public function setOptions(? Iterable $config = null): self
    {
        if (null === $config) {
            return $this;
        }

        foreach ($config as $option => $value) {
            switch ($option) {
                case 'uri':
                    $this->uri = (string) $value;

                    break;
                case 'options':
                    $this->options = $value;

                    break;
                case 'binddn':
                    $this->binddn = (string) $value;

                    break;
                case 'bindpw':
                    $this->bindpw = (string) $value;

                    break;
                case 'basedn':
                    $this->basedn = (string) $value;

                    break;
                case 'tls':
                    $this->tls = (bool) (int) $value;

                    break;
                default:
                    throw new Exception('unknown option '.$option.' given');
            }
        }

        return $this;
    }

    /**
     * Get base.
     *
     * @return string
     */
    public function getBase(): string
    {
        return $this->basedn;
    }

    /**
     * Get connection.
     *
     * @return resource
     */
    public function getResource()
    {
        if (!is_resource($this->connection)) {
            $this->connect();
        }

        return $this->connection;
    }
}

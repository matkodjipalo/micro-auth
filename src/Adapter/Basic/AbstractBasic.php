<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Adapter\Basic;

use Micro\Auth\Adapter\AbstractAdapter;
use Psr\Log\LoggerInterface;

abstract class AbstractBasic extends AbstractAdapter implements BasicInterface
{
    /**
     * Logger.
     *
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Attributes.
     *
     * @var array
     */
    protected $attributes = [];

    /**
     * Init.
     *
     * @param LoggerInterface $logger
     */
    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Authenticate.
     *
     * @return bool
     */
    public function authenticate(): bool
    {
        if (!isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $this->logger->debug('skip auth adapter ['.get_class($this).'], no http authorization header found', [
                'category' => get_class($this),
            ]);

            return false;
        }

        $header = $_SERVER['HTTP_AUTHORIZATION'];
        $parts = explode(' ', $header);

        if ('Basic' === $parts[0]) {
            $this->logger->debug('found http basic authorization header', [
                'category' => get_class($this),
            ]);

            $username = $_SERVER['PHP_AUTH_USER'];
            $password = $_SERVER['PHP_AUTH_PW'];

            return $this->plainAuth($username, $password);
        }
        $this->logger->warning('http authorization header contains no basic string or invalid authentication string', [
                'category' => get_class($this),
            ]);

        return false;
    }

    /**
     * Get attributes.
     *
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }
}

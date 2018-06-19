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
use Psr\Http\Message\ServerRequestInterface;
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
     * Init.
     */
    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Authenticate.
     */
    public function authenticate(ServerRequestInterface $request): ?array
    {
        $header = $request->getHeader('Authorization');

        if (0 === count($header)) {
            $this->logger->debug('skip auth adapter ['.get_class($this).'], no http authorization header found', [
                'category' => get_class($this),
            ]);

            return null;
        }

        $parts = explode(' ', $header[0]);

        if ('Basic' === $parts[0]) {
            $this->logger->debug('found http basic authorization header', [
                'category' => get_class($this),
            ]);

            list($username, $password) = explode(base64_decode($parts[1], true));

            return $this->plainAuth($username, $password);
        }

        $this->logger->warning('http authorization header contains no basic string or invalid authentication string', [
            'category' => get_class($this),
        ]);

        return null;
    }
}
